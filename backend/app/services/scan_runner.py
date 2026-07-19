"""
Scan runner: builds tool commands, executes as async subprocesses,
parses output line-by-line into ScanResult rows, enforces scope.
"""

import asyncio
import json
import logging
import shutil
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.engine import async_session
from app.db.models import Scan, ScanResult, ScanStatus, Target
from app.services.scope import ScopeEnforcer
from app.services.settings_service import get_setting

logger = logging.getLogger(__name__)

# Global registry of running scan processes
_running: dict[int, asyncio.subprocess.Process] = {}


def _find_tool(name: str, extra_paths: list[str] | None = None) -> str | None:
    path = shutil.which(name)
    if path:
        return path
    for ep in (extra_paths or []):
        candidate = Path(ep) / name
        if candidate.is_file():
            return str(candidate)
    return None


# ── Tool command builders ────────────────────────────────────────────

def _build_subfinder(targets: list[str], opts: dict) -> list[str]:
    cmd = ["subfinder", "-silent"]
    threads = opts.get("threads", 10)
    cmd += ["-t", str(threads)]
    for t in targets:
        domain = t.lstrip("*.")
        cmd += ["-d", domain]
    return cmd


def _build_dnsx(targets: list[str], opts: dict) -> list[str]:
    # dnsx reads from stdin, but we can pass -l with a file or pipe
    # For simplicity, use -d flag for domain list
    cmd = ["dnsx", "-silent", "-resp"]
    threads = opts.get("threads", 10)
    cmd += ["-t", str(threads)]
    for t in targets:
        cmd += ["-d", t.lstrip("*.")]
    return cmd


def _build_httpx(targets: list[str], opts: dict) -> list[str]:
    cmd = ["httpx", "-silent", "-status-code", "-title", "-tech-detect", "-json"]
    threads = opts.get("threads", 10)
    cmd += ["-t", str(threads)]
    # httpx reads from stdin, so we'll pipe targets
    return cmd


def _build_gau(targets: list[str], opts: dict) -> list[str]:
    cmd = ["gau", "--subs"]
    threads = opts.get("threads", 5)
    cmd += ["--threads", str(threads)]
    cmd += targets
    return cmd


def _build_katana(targets: list[str], opts: dict) -> list[str]:
    cmd = ["katana", "-silent", "-jc", "-kf", "all"]
    depth = opts.get("depth", 3)
    threads = opts.get("threads", 10)
    cmd += ["-d", str(depth), "-c", str(threads)]
    for t in targets:
        cmd += ["-u", t]
    return cmd


def _build_nmap(targets: list[str], opts: dict) -> list[str]:
    ports = opts.get("ports", "1-1000")
    cmd = ["nmap", "-sV", "--open", "-oG", "-"]
    # Support --top-ports style override
    if str(ports).startswith("--top-ports"):
        cmd += ports.split()
    else:
        cmd += ["-p", str(ports)]
    cmd += targets
    return cmd


def _build_ffuf(targets: list[str], opts: dict) -> list[str]:
    wordlist = opts.get("wordlist", "/usr/share/seclists/Discovery/Web-Content/common.txt")
    threads = opts.get("threads", 40)
    target = targets[0] if targets else ""
    if not target.startswith("http"):
        target = f"https://{target}"
    url = f"{target.rstrip('/')}/FUZZ"
    cmd = ["ffuf", "-u", url, "-w", wordlist, "-t", str(threads),
           "-mc", "200,201,301,302,403", "-o", "/dev/stdout", "-of", "json", "-s"]
    return cmd


def _build_nuclei(targets: list[str], opts: dict) -> list[str]:
    cmd = ["nuclei", "-silent", "-jsonl"]
    threads = opts.get("threads", 25)
    severity = opts.get("severity", "low,medium,high,critical")
    cmd += ["-c", str(threads), "-severity", severity]
    for t in targets:
        cmd += ["-u", t]
    return cmd


def _build_waybackurls(targets: list[str], _opts: dict) -> list[str]:
    return ["waybackurls"] + targets


def _build_assetfinder(targets: list[str], _opts: dict) -> list[str]:
    return ["assetfinder", "--subs-only"] + [t.lstrip("*.") for t in targets]


BUILDERS: dict[str, callable] = {
    "subfinder": _build_subfinder,
    "dnsx": _build_dnsx,
    "httpx": _build_httpx,
    "gau": _build_gau,
    "katana": _build_katana,
    "nmap": _build_nmap,
    "ffuf": _build_ffuf,
    "nuclei": _build_nuclei,
    "waybackurls": _build_waybackurls,
    "assetfinder": _build_assetfinder,
}

# Map tool → result_type
RESULT_TYPES: dict[str, str] = {
    "subfinder": "subdomain",
    "dnsx": "dns_record",
    "httpx": "live_host",
    "gau": "url",
    "katana": "url",
    "nmap": "port",
    "ffuf": "directory",
    "nuclei": "vulnerability",
    "waybackurls": "url",
    "assetfinder": "subdomain",
}


# ── Result parsers ───────────────────────────────────────────────────

def _parse_line(tool: str, line: str) -> tuple[str, str, str]:
    """Returns (result_type, value, metadata_json)."""
    line = line.strip()
    if not line:
        return ("", "", "{}")

    result_type = RESULT_TYPES.get(tool, "raw")

    if tool == "httpx":
        try:
            data = json.loads(line)
            return ("live_host", data.get("url", line), json.dumps({
                "status_code": data.get("status_code"),
                "title": data.get("title", ""),
                "tech": data.get("tech", []),
            }))
        except json.JSONDecodeError:
            return ("live_host", line, "{}")

    if tool == "nuclei":
        try:
            data = json.loads(line)
            return ("vulnerability", data.get("host", line), json.dumps({
                "template_id": data.get("template-id", ""),
                "name": data.get("info", {}).get("name", ""),
                "severity": data.get("info", {}).get("severity", ""),
                "matched_at": data.get("matched-at", ""),
            }))
        except json.JSONDecodeError:
            return ("vulnerability", line, "{}")

    if tool == "nmap":
        # Parse grepable output: Host: 1.2.3.4 ()   Ports: 80/open/tcp//http//
        if line.startswith("Host:") and "Ports:" in line:
            parts = line.split("Ports:")
            host = parts[0].split()[1] if len(parts[0].split()) > 1 else ""
            port_str = parts[1].strip() if len(parts) > 1 else ""
            return ("port", host, json.dumps({"ports": port_str}))
        return ("", "", "{}")

    if tool == "ffuf":
        try:
            data = json.loads(line)
            results = data.get("results", [])
            if results:
                r = results[0]
                return ("directory", r.get("url", line), json.dumps({
                    "status": r.get("status"),
                    "length": r.get("length"),
                }))
        except json.JSONDecodeError:
            pass
        return ("directory", line, "{}")

    if tool == "dnsx":
        # Format: domain [A] [1.2.3.4]
        return ("dns_record", line, "{}")

    return (result_type, line, "{}")


# ── Core scan execution ─────────────────────────────────────────────

async def start_scan(
    scan_id: int,
    project_id: int,
    tool_name: str,
    scan_type: str,
    target_override: str | None,
    options: dict,
) -> None:
    """Launch scan as background task."""
    asyncio.create_task(_run_scan(
        scan_id, project_id, tool_name, scan_type, target_override, options
    ))


async def _run_scan(
    scan_id: int,
    project_id: int,
    tool_name: str,
    scan_type: str,
    target_override: str | None,
    options: dict,
) -> None:
    async with async_session() as db:
        scan = await db.get(Scan, scan_id)
        if not scan:
            return

        try:
            # Get tool path
            go_path = await get_setting(db, "go_tools_path")
            extra = [go_path] if go_path else []
            tool_path = _find_tool(tool_name, extra)
            if not tool_path:
                scan.status = ScanStatus.failed
                scan.error_message = f"Tool '{tool_name}' not found"
                scan.completed_at = datetime.now(timezone.utc)
                await db.commit()
                return

            # Resolve targets
            if target_override:
                targets = [target_override]
            else:
                result = await db.execute(
                    select(Target).where(Target.project_id == project_id)
                )
                all_targets = result.scalars().all()
                targets = [
                    t.value for t in all_targets
                    if t.direction.value == "in_scope"
                ]

            if not targets:
                scan.status = ScanStatus.failed
                scan.error_message = "No in-scope targets"
                scan.completed_at = datetime.now(timezone.utc)
                await db.commit()
                return

            # Build scope enforcer for output filtering
            result = await db.execute(
                select(Target).where(Target.project_id == project_id)
            )
            scope_targets = result.scalars().all()
            enforcer = ScopeEnforcer(scope_targets)

            # Auto-inject wordlist setting for ffuf
            if tool_name == "ffuf" and "wordlist" not in options:
                wl = await get_setting(db, "wordlist_ffuf")
                if wl:
                    options["wordlist"] = wl
                else:
                    # Default to bundled small wordlist
                    bundled = Path(__file__).resolve().parents[2] / "wordlists" / "ffuf-wordlist-default-small.txt"
                    if bundled.is_file():
                        options["wordlist"] = str(bundled)

            # Build command
            builder = BUILDERS.get(tool_name)
            if not builder:
                scan.status = ScanStatus.failed
                scan.error_message = f"No builder for tool '{tool_name}'"
                scan.completed_at = datetime.now(timezone.utc)
                await db.commit()
                return

            cmd = builder(targets, options)
            # Replace tool name with full path
            cmd[0] = tool_path

            scan.command = " ".join(cmd)
            scan.status = ScanStatus.running
            scan.started_at = datetime.now(timezone.utc)
            await db.commit()

            # Determine if tool needs stdin (httpx)
            stdin_data = None
            if tool_name == "httpx":
                stdin_data = "\n".join(targets).encode()

            # Execute
            logger.info("Running scan %d: %s", scan_id, scan.command)
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE if stdin_data else None,
            )
            _running[scan_id] = proc

            if stdin_data:
                proc.stdin.write(stdin_data)
                proc.stdin.close()

            # Read output line by line
            result_count = 0
            seen = set()
            while True:
                line_bytes = await proc.stdout.readline()
                if not line_bytes:
                    break
                line = line_bytes.decode("utf-8", errors="replace").strip()
                if not line:
                    continue

                result_type, value, metadata = _parse_line(tool_name, line)
                if not value or not result_type:
                    continue

                # Dedup within scan
                if value in seen:
                    continue
                seen.add(value)

                # Scope filter for domain/URL-based outputs
                if result_type in ("subdomain", "url", "live_host", "directory"):
                    if not enforcer.is_in_scope(value):
                        continue

                db.add(ScanResult(
                    scan_id=scan_id,
                    result_type=result_type,
                    value=value,
                    metadata_json=metadata,
                ))
                result_count += 1

                # Batch commit every 50 results
                if result_count % 50 == 0:
                    await db.commit()

            await proc.wait()
            stderr = (await proc.stderr.read()).decode("utf-8", errors="replace")

            scan.status = ScanStatus.completed
            scan.completed_at = datetime.now(timezone.utc)
            if proc.returncode != 0 and stderr:
                scan.error_message = stderr[:2000]
            await db.commit()

            logger.info("Scan %d completed: %d results", scan_id, result_count)

        except asyncio.CancelledError:
            scan.status = ScanStatus.cancelled
            scan.completed_at = datetime.now(timezone.utc)
            await db.commit()
        except Exception as e:
            logger.exception("Scan %d failed", scan_id)
            scan.status = ScanStatus.failed
            scan.error_message = str(e)[:2000]
            scan.completed_at = datetime.now(timezone.utc)
            await db.commit()
        finally:
            _running.pop(scan_id, None)


async def cancel_scan(scan_id: int) -> bool:
    proc = _running.get(scan_id)
    if proc:
        proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), timeout=5)
        except asyncio.TimeoutError:
            proc.kill()
        _running.pop(scan_id, None)
        return True
    return False


def get_running_scan_ids() -> list[int]:
    return list(_running.keys())
