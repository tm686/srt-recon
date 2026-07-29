"""
Scan runner: builds tool commands, executes as async subprocesses,
parses output line-by-line into ScanResult rows, enforces scope.

Data flow (pipeline chaining):
  Phase 1 — subfinder/assetfinder/alterx → subdomains (from raw targets)
  Phase 2 — dnsx                         → DNS records (from subdomains)
  Phase 3 — nmap/rustscan                → open ports (from subdomains + DNS IPs)
  Phase 4 — httpx                        → live hosts (from subdomains + port URLs)
  Phase 5 — katana/gau/waybackurls       → URLs (from live hosts / subdomains)
  Phase 6 — ffuf                         → directories (from live hosts, each fuzzed)
  Phase 7 — nuclei/dalfox/subjack        → vulns (from live hosts + URLs + dirs)
  Phase 8 — gowitness                    → screenshots (from live hosts)
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
from app.db.models import Project, Scan, ScanResult, ScanStatus, Target
from app.services.scope import ScopeEnforcer
from app.services.settings_service import get_setting

logger = logging.getLogger(__name__)

# Global registry of running scan processes
_running: dict[int, asyncio.subprocess.Process] = {}


def _find_tool(name: str, extra_paths: list[str] | None = None) -> str | None:
    # Check extra_paths (go_tools_path) FIRST so Go binaries take
    # priority over system/venv binaries with the same name (e.g. httpx).
    for ep in (extra_paths or []):
        candidate = Path(ep) / name
        if candidate.is_file():
            return str(candidate)
    path = shutil.which(name)
    if path:
        return path
    return None


# ── Tool command builders ────────────────────────────────────────────

def _build_subfinder(targets: list[str], opts: dict) -> list[str]:
    cmd = ["subfinder", "-silent", "-all"]
    threads = opts.get("threads", 10)
    cmd += ["-t", str(threads)]
    for t in targets:
        cmd += ["-d", t.lstrip("*.")]
    return cmd


def _build_dnsx(targets: list[str], opts: dict) -> list[str]:
    # dnsx reads domains from stdin; we pipe targets via stdin_data
    cmd = ["dnsx", "-silent", "-j", "-retry", "3",
           "-a", "-aaaa", "-cname", "-mx", "-ns", "-txt"]
    threads = opts.get("threads", 10)
    cmd += ["-t", str(threads)]
    return cmd


def _build_httpx(targets: list[str], opts: dict) -> list[str]:
    # httpx reads from stdin; we pipe targets via stdin_data
    cmd = ["httpx", "-silent", "-json", "-fr",
           "-sc", "-title", "-td", "-server", "-ip",
           "-timeout", "10", "-retries", "2"]
    threads = opts.get("threads", 10)
    cmd += ["-t", str(threads)]
    return cmd


def _build_gau(targets: list[str], opts: dict) -> list[str]:
    cmd = ["gau", "--subs",
           "--providers", "wayback,commoncrawl,otx",
           "--timeout", "60", "--retries", "2"]
    threads = opts.get("threads", 5)
    cmd += ["--threads", str(threads)]
    cmd += [t.lstrip("*.") for t in targets]
    return cmd


def _build_katana(targets: list[str], opts: dict) -> list[str]:
    depth = opts.get("depth", 3)
    threads = opts.get("threads", 10)
    cmd = ["katana", "-silent", "-jc", "-kf", "all", "-j",
           "-timeout", "10", "-retry", "2",
           "-rl", "100",
           "-d", str(depth), "-c", str(threads)]
    for t in targets:
        cmd += ["-u", t]
    return cmd


def _build_nmap(targets: list[str], opts: dict) -> list[str]:
    ports = opts.get("ports", "1-1000")
    scan_speed = opts.get("scan_speed", "normal")  # stealth | normal | aggressive

    if scan_speed == "stealth":
        timing, max_rate, max_retries, host_timeout = "-T2", "100", "1", "900s"
    elif scan_speed == "aggressive":
        timing, max_rate, max_retries, host_timeout = "-T4", "5000", "2", "300s"
    else:  # normal
        timing, max_rate, max_retries, host_timeout = "-T3", "1000", "2", "600s"

    cmd = ["nmap", "-sC", "-sV", timing, "--open", "-oG", "-",
           "--max-rate", max_rate,
           "--max-retries", max_retries, "--host-timeout", host_timeout]
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
           "-mc", "200,201,301,302,403",
           "-ac",          # auto-calibrate filtering
           "-r",           # follow redirects
           "-timeout", "10",
           "-sa",          # stop on all errors
           "-o", "/dev/stdout", "-of", "json", "-s"]
    return cmd


def _build_nuclei(targets: list[str], opts: dict) -> list[str]:
    threads = opts.get("threads", 25)
    severity = opts.get("severity", "low,medium,high,critical")
    cmd = ["nuclei", "-silent", "-jsonl",
           "-c", str(threads),
           "-severity", severity,
           "-rl", "150",       # rate limit: 150 req/s
           "-timeout", "10",
           "-retries", "1",
           "-mhe", "30",       # skip host after 30 errors
           "-fr",              # follow redirects
           "-bs", "25"]        # bulk size
    # Use -l (list file) when there are many targets (chained results)
    target_file = opts.get("_target_file")
    if target_file:
        cmd += ["-l", target_file]
    else:
        for t in targets:
            cmd += ["-u", t]
    return cmd


def _build_waybackurls(targets: list[str], _opts: dict) -> list[str]:
    return ["waybackurls"] + [t.lstrip("*.") for t in targets]


def _build_assetfinder(targets: list[str], _opts: dict) -> list[str]:
    return ["assetfinder", "--subs-only"] + [t.lstrip("*.") for t in targets]


def _build_gowitness(targets: list[str], opts: dict) -> list[str]:
    # gowitness v3: `gowitness scan file -f <file> -s <dir> -t N`
    screenshot_dir = opts.get("screenshot_dir", "/tmp/gowitness")
    threads = opts.get("threads", 8)
    url_file = opts.get("url_file", "/tmp/gowitness_urls.txt")
    cmd = ["gowitness", "scan", "file",
           "-f", url_file,
           "-s", screenshot_dir,
           "-t", str(threads),
           "-T", "30",
           "--screenshot-format", "png",
           "--log-scan-errors",
           "--write-none"]
    return cmd


def _build_dalfox(targets: list[str], opts: dict) -> list[str]:
    # dalfox pipe mode: reads URLs from stdin, one per line
    threads = opts.get("threads", 10)
    cmd = ["dalfox", "pipe",
           "--silence",
           "--format", "json",
           "-w", str(threads),
           "--timeout", "10",
           "--delay", "100"]
    return cmd


def _build_subjack(targets: list[str], opts: dict) -> list[str]:
    # subjack reads from a file; we write targets to a temp file in _run_scan
    threads = opts.get("threads", 10)
    input_file = opts.get("input_file", "/tmp/subjack_targets.txt")
    cmd = ["subjack", "-w", input_file,
           "-t", str(threads),
           "-timeout", "30",
           "-ssl", "-a"]
    return cmd


def _build_rustscan(targets: list[str], opts: dict) -> list[str]:
    scan_speed = opts.get("scan_speed", "normal")

    if scan_speed == "stealth":
        batch_size = opts.get("batch_size", 500)
        timeout = opts.get("timeout", 3000)
    elif scan_speed == "aggressive":
        batch_size = opts.get("batch_size", 4500)
        timeout = opts.get("timeout", 2000)
    else:  # normal
        batch_size = opts.get("batch_size", 1500)
        timeout = opts.get("timeout", 2000)

    cmd = ["rustscan",
           "-a", ",".join(targets),
           "--ulimit", "5000",
           "-b", str(batch_size),
           "-t", str(timeout),
           "-g"]
    return cmd


def _build_alterx(targets: list[str], opts: dict) -> list[str]:
    # alterx reads subdomains from stdin
    cmd = ["alterx", "-silent", "-enrich"]
    limit = opts.get("limit", 10000)
    cmd += ["-limit", str(limit)]
    return cmd


def _build_searchsploit(targets: list[str], opts: dict) -> list[str]:
    return ["searchsploit", "--json", "--"]


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
    "gowitness": _build_gowitness,
    "dalfox": _build_dalfox,
    "subjack": _build_subjack,
    "rustscan": _build_rustscan,
    "alterx": _build_alterx,
    "searchsploit": _build_searchsploit,
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
    "dalfox": "vulnerability",
    "subjack": "vulnerability",
    "gowitness": "screenshot",
    "rustscan": "port",
    "alterx": "subdomain",
    "searchsploit": "exploit",
}


# ── Service priority classification ──────────────────────────────────

_CRITICAL_SERVICES = {"mysql", "postgresql", "postgres", "mssql", "ms-sql",
                      "mongodb", "redis", "memcached", "docker", "kubernetes",
                      "k8s", "elasticsearch", "cassandra", "couchdb"}
_HIGH_SERVICES = {"http", "https", "ssl/http", "ssl/https", "http-proxy",
                  "https-proxy", "ajp13", "ftp", "smtp", "rdp", "ms-wbt-server",
                  "vnc", "telnet", "jenkins", "tomcat", "webmin", "ldap"}


def _service_priority(service: str) -> str:
    svc = service.lower() if service else ""
    if any(s in svc for s in _CRITICAL_SERVICES):
        return "critical"
    if any(s in svc for s in _HIGH_SERVICES):
        return "high"
    return "medium"


# ── Result parsers ───────────────────────────────────────────────────

def _parse_line(tool: str, line: str) -> list[tuple[str, str, str]]:
    """Returns list of (result_type, value, metadata_json) tuples.
    Most tools return one result per line; nmap can return multiple (one per port).
    """
    line = line.strip()
    if not line:
        return []

    result_type = RESULT_TYPES.get(tool, "raw")

    if tool == "httpx":
        try:
            data = json.loads(line)
            return [("live_host", data.get("url", line), json.dumps({
                "status_code": data.get("status_code"),
                "title": data.get("title", ""),
                "tech": data.get("tech", []),
                "server": data.get("webserver", ""),
                "ip": data.get("host", ""),
                "content_length": data.get("content_length"),
            }))]
        except json.JSONDecodeError:
            return [("live_host", line, "{}")]

    if tool == "nuclei":
        try:
            data = json.loads(line)
            return [("vulnerability", data.get("host", line), json.dumps({
                "template_id": data.get("template-id", ""),
                "name": data.get("info", {}).get("name", ""),
                "severity": data.get("info", {}).get("severity", ""),
                "matched_at": data.get("matched-at", ""),
            }))]
        except json.JSONDecodeError:
            return [("vulnerability", line, "{}")]

    if tool == "nmap":
        # Parse grepable output: Host: 1.2.3.4 (hostname)   Ports: 22/open/tcp//ssh///version_info, 80/open/tcp//http//
        if line.startswith("Host:") and "Ports:" in line:
            parts = line.split("Ports:")
            host_parts = parts[0].split()
            host = host_parts[1] if len(host_parts) > 1 else ""
            # Hostname is in parens: Host: 10.1.1.5 (server.example.com)
            hostname = ""
            if len(host_parts) > 2:
                raw = host_parts[2].strip("()")
                if raw and raw != host:
                    hostname = raw
            port_str = parts[1].strip() if len(parts) > 1 else ""
            if not host or not port_str:
                return []
            results = []
            # Each port entry: 22/open/tcp//ssh//version_string/
            for port_entry in port_str.split(","):
                port_entry = port_entry.strip().rstrip("/")
                if not port_entry:
                    continue
                fields = port_entry.split("/")
                port_num = fields[0] if len(fields) > 0 else ""
                state = fields[1] if len(fields) > 1 else ""
                protocol = fields[2] if len(fields) > 2 else ""
                service = fields[4] if len(fields) > 4 else ""
                version = fields[6] if len(fields) > 6 else ""
                if state != "open":
                    continue
                value = f"{host}:{port_num}"
                web_services = {"http", "https", "ssl/http", "ssl/https", "http-proxy", "https-proxy"}
                svc_lower = service.lower() if service else ""
                hint = ("Web service - may need /etc/hosts entry for virtual hosting"
                        if any(ws in svc_lower for ws in web_services) else "")
                metadata = json.dumps({
                    "port": port_num,
                    "protocol": protocol,
                    "service": service,
                    "version": version,
                    "state": state,
                    "hostname": hostname,
                    "hint": hint,
                    "priority": _service_priority(service),
                })
                results.append(("port", value, metadata))
            return results
        return []

    if tool == "ffuf":
        # ffuf outputs a single JSON doc — handled by _parse_ffuf_json instead
        return [("directory", line, "{}")]

    if tool == "dnsx":
        try:
            data = json.loads(line)
            host = data.get("host", line)
            records = {}
            for rtype in ("a", "aaaa", "cname", "mx", "ns", "txt"):
                if data.get(rtype):
                    records[rtype] = data[rtype]
            return [("dns_record", host, json.dumps(records))]
        except json.JSONDecodeError:
            return [("dns_record", line, "{}")]

    if tool == "dalfox":
        try:
            data = json.loads(line)
            return [("vulnerability", data.get("data", line), json.dumps({
                "type": data.get("type", ""),
                "poc": data.get("poc", ""),
                "param": data.get("param", ""),
                "payload": data.get("payload", ""),
                "severity": "high",
            }))]
        except json.JSONDecodeError:
            return [("vulnerability", line, json.dumps({"severity": "high"}))]

    if tool == "subjack":
        # Format: [Vulnerable] domain.com - Service
        if line.startswith("[Vulnerable]"):
            parts = line.replace("[Vulnerable]", "").strip().split(" - ", 1)
            domain = parts[0].strip() if parts else line
            service = parts[1].strip() if len(parts) > 1 else ""
            return [("vulnerability", domain, json.dumps({
                "service": service,
                "vulnerable": True,
                "severity": "high",
            }))]
        return []

    if tool == "rustscan":
        # Greppable format: host -> [ports]
        if "->" in line:
            parts = line.split("->")
            host = parts[0].strip()
            port_str = parts[1].strip().strip("[]")
            results = []
            for port in port_str.split(","):
                port = port.strip()
                if port:
                    results.append(("port", f"{host}:{port}", json.dumps({
                        "port": port,
                        "protocol": "tcp",
                        "service": "",
                        "state": "open",
                    })))
            return results
        return []

    if tool == "katana":
        try:
            data = json.loads(line)
            endpoint = data.get("request", {}).get("endpoint", line)
            return [("url", endpoint, json.dumps({
                "method": data.get("request", {}).get("method", ""),
                "source": data.get("request", {}).get("source", ""),
                "tag": data.get("request", {}).get("tag", ""),
            }))]
        except json.JSONDecodeError:
            return [("url", line, "{}")]

    if tool == "alterx":
        return [("subdomain", line, "{}")]

    if tool == "gowitness":
        # Ignore stdout lines — real results come from post-processing (PNG dir scan)
        return []

    return [(result_type, line, "{}")]


def _parse_ffuf_json(text: str) -> list[tuple[str, str, str]]:
    """Parse ffuf's single JSON document output into individual results."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    results = []
    for r in data.get("results", []):
        url = r.get("url", "")
        if not url:
            continue
        metadata = json.dumps({
            "status": r.get("status"),
            "length": r.get("length"),
            "words": r.get("words"),
        })
        results.append(("directory", url, metadata))
    return results


# ── Pipeline data chaining ──────────────────────────────────────────
# Every tool that isn't a root-level scanner (subfinder/assetfinder)
# feeds from the results of upstream pipeline stages.  This is the
# single source of truth for what feeds into what.

async def _get_previous_results(
    db: AsyncSession,
    project_id: int,
    result_types: list[str],
) -> list[str]:
    """Fetch deduplicated result values of given types from all scans in this project."""
    stmt = (
        select(ScanResult.value)
        .join(Scan)
        .where(Scan.project_id == project_id)
        .where(ScanResult.result_type.in_(result_types))
        .distinct()
    )
    rows = await db.execute(stmt)
    return [row[0] for row in rows.all()]


async def _get_dns_ips(db: AsyncSession, project_id: int) -> list[str]:
    """Extract unique IPs from dnsx A-record results."""
    stmt = (
        select(ScanResult.metadata_json)
        .join(Scan)
        .where(Scan.project_id == project_id)
        .where(ScanResult.result_type == "dns_record")
    )
    rows = await db.execute(stmt)
    ips = set()
    for (meta_json,) in rows.all():
        try:
            meta = json.loads(meta_json or "{}")
            for ip in (meta.get("a") or []):
                ips.add(ip)
        except json.JSONDecodeError:
            pass
    return list(ips)


async def _get_service_versions(db: AsyncSession, project_id: int) -> list[dict]:
    """Extract unique service+version pairs from port results, with affected hosts."""
    stmt = (
        select(ScanResult.value, ScanResult.metadata_json)
        .join(Scan)
        .where(Scan.project_id == project_id)
        .where(ScanResult.result_type == "port")
    )
    rows = await db.execute(stmt)
    # Group: "Apache httpd 2.4.49" → ["10.1.1.5:80", "10.1.1.12:8080"]
    query_hosts: dict[str, list[str]] = {}
    for value, meta_json in rows.all():
        meta = json.loads(meta_json or "{}")
        service = meta.get("service", "")
        version = meta.get("version", "")
        if not service:
            continue
        query = f"{service} {version}".strip()
        query_hosts.setdefault(query, []).append(value)
    return [{"query": q, "hosts": h} for q, h in query_hosts.items()]


async def _get_project_category(db: AsyncSession, project_id: int) -> str | None:
    stmt = select(Project.category).where(Project.id == project_id)
    result = await db.execute(stmt)
    row = result.first()
    return row[0].value if row else None


def _ports_to_http_targets(port_values: list[str]) -> list[str]:
    """Convert host:port strings into HTTP URLs for probing.
    Common HTTP ports get https://, others get http://.
    """
    https_ports = {"443", "8443", "4443", "9443"}
    urls = []
    for hp in port_values:
        if ":" not in hp:
            continue
        host, port = hp.rsplit(":", 1)
        scheme = "https" if port in https_ports else "http"
        # Skip default ports in URL to avoid duplicates
        if (scheme == "http" and port == "80") or (scheme == "https" and port == "443"):
            urls.append(f"{scheme}://{host}")
        else:
            urls.append(f"{scheme}://{host}:{port}")
    return urls


async def _resolve_chain(
    db: AsyncSession,
    project_id: int,
    tool_name: str,
    targets: list[str],
) -> list[str]:
    """Resolve what targets a tool should actually scan based on upstream
    results.  Every tool has a defined chain — if no upstream data exists
    yet, falls back to raw project targets (appropriately formatted).
    """
    stripped = [t.lstrip("*.") for t in targets]
    as_urls = [t if t.startswith("http") else f"https://{t}" for t in targets]

    # ── Phase 1: Subdomain discovery (root tools — use raw targets) ──
    if tool_name in ("subfinder", "assetfinder"):
        return stripped

    # ── Phase 1b: Subdomain permutation ← subdomains ────────────────
    if tool_name == "alterx":
        subs = await _get_previous_results(db, project_id, ["subdomain"])
        return subs if subs else stripped

    # ── Phase 2: DNS resolution ← subdomains ────────────────────────
    if tool_name == "dnsx":
        subs = await _get_previous_results(db, project_id, ["subdomain"])
        return subs if subs else stripped

    # ── Phase 3a: Port scanning (rustscan) ← subdomains + DNS IPs ───
    if tool_name == "rustscan":
        subs = await _get_previous_results(db, project_id, ["subdomain"])
        dns_ips = await _get_dns_ips(db, project_id)
        chained = list(set(subs + dns_ips))
        return chained if chained else stripped

    # ── Phase 3b: Port scanning (nmap) ← rustscan ports OR subs+IPs ─
    if tool_name == "nmap":
        port_results = await _get_previous_results(db, project_id, ["port"])
        if port_results:
            return port_results  # host:port format → _run_scan parses into port spec
        subs = await _get_previous_results(db, project_id, ["subdomain"])
        dns_ips = await _get_dns_ips(db, project_id)
        chained = list(set(subs + dns_ips))
        return chained if chained else stripped

    # ── Phase 4: Live host discovery ← subdomains + port URLs ───────
    if tool_name == "httpx":
        category = await _get_project_category(db, project_id)
        subs = await _get_previous_results(db, project_id, ["subdomain"])
        ports = await _get_previous_results(db, project_id, ["port"])
        if category in ("single_ip", "cidr_range", "ip_list"):
            chained = _ports_to_http_targets(ports) if ports else []
            if not chained:
                chained = [f"http://{t}" for t in stripped] + [f"https://{t}" for t in stripped]
            return list(set(chained))
        else:
            chained = list(set(subs + _ports_to_http_targets(ports)))
            return chained if chained else stripped

    # ── Phase 5: URL discovery ← live hosts / subdomains ────────────
    if tool_name == "katana":
        live = await _get_previous_results(db, project_id, ["live_host"])
        return live if live else as_urls

    if tool_name in ("gau", "waybackurls"):
        subs = await _get_previous_results(db, project_id, ["subdomain"])
        return subs if subs else stripped

    # ── Phase 6: Directory fuzzing ← live hosts / port URLs ─────────
    if tool_name == "ffuf":
        live = await _get_previous_results(db, project_id, ["live_host"])
        if live:
            return live
        ports = await _get_previous_results(db, project_id, ["port"])
        if ports:
            return _ports_to_http_targets(ports)
        return as_urls

    # ── Phase 7: Vulnerability scanning ← everything discovered ─────
    if tool_name == "nuclei":
        live = await _get_previous_results(db, project_id, ["live_host"])
        urls = await _get_previous_results(db, project_id, ["url"])
        dirs = await _get_previous_results(db, project_id, ["directory"])
        chained = list(set(live + urls + dirs))
        return chained if chained else as_urls

    if tool_name == "dalfox":
        urls = await _get_previous_results(db, project_id, ["url"])
        live = await _get_previous_results(db, project_id, ["live_host"])
        chained = list(set(urls + live))
        return chained if chained else as_urls

    if tool_name == "subjack":
        subs = await _get_previous_results(db, project_id, ["subdomain"])
        return subs if subs else stripped

    # ── Exploit lookup ← port results with service versions ─────────
    if tool_name == "searchsploit":
        port_results = await _get_previous_results(db, project_id, ["port"])
        return port_results if port_results else []

    # ── Phase 8: Screenshots ← live hosts ───────────────────────────
    if tool_name == "gowitness":
        live = await _get_previous_results(db, project_id, ["live_host"])
        return live if live else as_urls

    # Unknown tool — use raw targets
    return targets


# ── Core scan execution ─────────────────────────────────────────────

async def start_scan(
    scan_id: int,
    project_id: int,
    tool_name: str,
    scan_type: str,
    target_override: str | None,
    options: dict,
) -> None:
    """Launch a single scan as background task (fire-and-forget)."""
    asyncio.create_task(_run_scan(
        scan_id, project_id, tool_name, scan_type, target_override, options
    ))


async def start_pipeline(
    steps: list[dict],
) -> None:
    """Launch a pipeline of scans sequentially as a background task.
    Each step waits for the previous one to complete before starting.
    Steps is a list of dicts with keys: scan_id, project_id, tool_name, scan_type, target_override, options.
    """
    asyncio.create_task(_run_pipeline(steps))


async def _run_pipeline(steps: list[dict]) -> None:
    """Execute pipeline steps one after another."""
    for step in steps:
        try:
            await _run_scan(
                scan_id=step["scan_id"],
                project_id=step["project_id"],
                tool_name=step["tool_name"],
                scan_type=step["scan_type"],
                target_override=step.get("target_override"),
                options=step.get("options", {}),
            )
        except Exception:
            logger.exception(
                "Pipeline step %s (scan %d) failed, continuing to next step",
                step["tool_name"], step["scan_id"],
            )


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

            # Resolve raw project targets
            if target_override:
                raw_targets = [target_override]
            else:
                result = await db.execute(
                    select(Target).where(Target.project_id == project_id)
                )
                all_targets = result.scalars().all()
                raw_targets = [
                    t.value for t in all_targets
                    if t.direction.value == "in_scope"
                ]

            if not raw_targets:
                scan.status = ScanStatus.failed
                scan.error_message = "No in-scope targets"
                scan.completed_at = datetime.now(timezone.utc)
                await db.commit()
                return

            # Resolve chained targets from upstream scan results
            chained = await _resolve_chain(db, project_id, tool_name, raw_targets)
            chain_count = len(chained)

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

            # ── Prepare tool-specific inputs ─────────────────────────
            stdin_data = None

            if tool_name in ("httpx", "dnsx"):
                # stdin-based tools: pipe chained targets
                stdin_data = "\n".join(chained).encode()
                cmd = builder(raw_targets, options)  # builder doesn't use targets for these
                logger.info("Scan %d: %s ← %d targets via stdin",
                            scan_id, tool_name, chain_count)

            elif tool_name == "alterx":
                stdin_data = "\n".join(chained).encode()
                cmd = builder(raw_targets, options)
                logger.info("Scan %d: alterx ← %d subdomains via stdin",
                            scan_id, chain_count)

            elif tool_name == "dalfox":
                stdin_data = "\n".join(chained).encode()
                cmd = builder(raw_targets, options)
                logger.info("Scan %d: dalfox ← %d URLs via stdin",
                            scan_id, chain_count)

            elif tool_name == "nuclei":
                # nuclei: write targets to file for -l flag
                target_file = f"/tmp/nuclei_{project_id}_{scan_id}.txt"
                Path(target_file).write_text("\n".join(chained))
                options["_target_file"] = target_file
                cmd = builder(raw_targets, options)
                logger.info("Scan %d: nuclei ← %d targets via -l file",
                            scan_id, chain_count)

            elif tool_name == "subjack":
                # subjack: write targets to file for -w flag
                input_file = f"/tmp/subjack_{project_id}.txt"
                Path(input_file).write_text("\n".join(chained))
                options["input_file"] = input_file
                cmd = builder(raw_targets, options)
                logger.info("Scan %d: subjack ← %d subdomains via file",
                            scan_id, chain_count)

            elif tool_name == "gowitness":
                # gowitness: write URLs to file for -f flag
                screenshot_dir = f"/tmp/gowitness/project_{project_id}"
                Path(screenshot_dir).mkdir(parents=True, exist_ok=True)
                url_file = f"/tmp/gowitness/project_{project_id}_urls.txt"
                Path(url_file).write_text("\n".join(chained))
                options["screenshot_dir"] = screenshot_dir
                options["url_file"] = url_file
                cmd = builder(raw_targets, options)
                logger.info("Scan %d: gowitness ← %d live hosts via file",
                            scan_id, chain_count)

            elif tool_name == "rustscan":
                cmd = builder(chained, options)
                logger.info("Scan %d: rustscan ← %d hosts/IPs", scan_id, chain_count)

            elif tool_name == "nmap":
                has_port_data = any(":" in t for t in chained)
                if has_port_data:
                    # Chaining from rustscan — parse host:port into grouped format
                    host_ports: dict[str, set[str]] = {}
                    plain_hosts: list[str] = []
                    for t in chained:
                        if ":" in t:
                            host, port = t.rsplit(":", 1)
                            host_ports.setdefault(host, set()).add(port)
                        else:
                            plain_hosts.append(t)
                    all_ports = set()
                    all_hosts = list(host_ports.keys()) + plain_hosts
                    for ps in host_ports.values():
                        all_ports.update(ps)
                    port_str = ",".join(sorted(all_ports, key=lambda p: int(p) if p.isdigit() else 0))
                    options["ports"] = port_str
                    cmd = builder(list(set(all_hosts)), options)
                    logger.info("Scan %d: nmap -sC -sV ← %d hosts, ports %s (from rustscan)",
                                scan_id, len(all_hosts), port_str)
                else:
                    cmd = builder(chained, options)
                    logger.info("Scan %d: nmap ← %d hosts/IPs", scan_id, chain_count)

            elif tool_name == "searchsploit":
                # Multi-query: one searchsploit call per unique service+version
                svc_versions = await _get_service_versions(db, project_id)
                result_count = 0
                seen = set()
                scan.command = f"searchsploit × {len(svc_versions)} service queries"
                scan.status = ScanStatus.running
                scan.started_at = datetime.now(timezone.utc)
                await db.commit()

                for sv in svc_versions:
                    query = sv["query"]
                    hosts = sv["hosts"]
                    if not query or len(query) < 3:
                        continue
                    search_cmd = [tool_path, "--json", query]
                    try:
                        proc = await asyncio.create_subprocess_exec(
                            *search_cmd,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE,
                        )
                        stdout_bytes = await proc.stdout.read()
                        await proc.wait()
                        text = stdout_bytes.decode("utf-8", errors="replace").strip()
                        if not text:
                            continue
                        data = json.loads(text)
                        for exploit in data.get("RESULTS_EXPLOIT", []):
                            title = exploit.get("Title", "")
                            edb_id = exploit.get("EDB-ID", "")
                            if not title:
                                continue
                            value = f"EDB-{edb_id}: {title}"
                            if value in seen:
                                continue
                            seen.add(value)
                            db.add(ScanResult(
                                scan_id=scan_id,
                                result_type="exploit",
                                value=value,
                                metadata_json=json.dumps({
                                    "edb_id": edb_id,
                                    "title": title,
                                    "query": query,
                                    "type": exploit.get("Type", ""),
                                    "platform": exploit.get("Platform", ""),
                                    "path": exploit.get("Path", ""),
                                    "codes": exploit.get("Codes", ""),
                                    "affected_hosts": hosts[:20],
                                }),
                            ))
                            result_count += 1
                        await db.commit()
                    except (json.JSONDecodeError, Exception):
                        logger.exception("searchsploit failed for: %s", query)

                scan.status = ScanStatus.completed
                scan.completed_at = datetime.now(timezone.utc)
                await db.commit()
                logger.info("Scan %d (searchsploit) completed: %d exploits found", scan_id, result_count)
                _running.pop(scan_id, None)
                return

            elif tool_name in ("katana", "gau", "waybackurls"):
                # CLI-arg tools: pass chained targets directly
                cmd = builder(chained, options)
                logger.info("Scan %d: %s ← %d chained targets",
                            scan_id, tool_name, chain_count)

            else:
                # Root tools (subfinder, assetfinder) or unknown
                cmd = builder(chained, options)

            # Replace tool name with full path
            cmd[0] = tool_path

            scan.command = " ".join(cmd)
            scan.status = ScanStatus.running
            scan.started_at = datetime.now(timezone.utc)
            await db.commit()

            # ── Multi-host ffuf (fuzz each live host separately) ─────
            if tool_name == "ffuf" and chain_count > 1:
                result_count = 0
                seen = set()
                scan.command = f"ffuf × {chain_count} hosts"
                await db.commit()

                for host_url in chained:
                    if scan_id not in _running and result_count > 0:
                        break  # cancelled
                    host_cmd = builder([host_url], options)
                    host_cmd[0] = tool_path
                    logger.info("Scan %d: ffuf fuzzing %s", scan_id, host_url)
                    try:
                        host_proc = await asyncio.create_subprocess_exec(
                            *host_cmd,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE,
                            limit=4 * 1024 * 1024,
                        )
                        _running[scan_id] = host_proc
                        stdout_bytes = await host_proc.stdout.read()
                        await host_proc.wait()
                        stdout_text = stdout_bytes.decode("utf-8", errors="replace").strip()
                        if stdout_text:
                            for rt, value, metadata in _parse_ffuf_json(stdout_text):
                                if not value or value in seen:
                                    continue
                                seen.add(value)
                                if not enforcer.is_in_scope(value):
                                    continue
                                db.add(ScanResult(
                                    scan_id=scan_id, result_type=rt,
                                    value=value, metadata_json=metadata,
                                ))
                                result_count += 1
                            await db.commit()
                    except Exception:
                        logger.exception("Scan %d: ffuf failed on %s", scan_id, host_url)

                scan.status = ScanStatus.completed
                scan.completed_at = datetime.now(timezone.utc)
                await db.commit()
                logger.info("Scan %d (ffuf multi-host) completed: %d results", scan_id, result_count)
                _running.pop(scan_id, None)
                return

            # ── Execute single-process tools ─────────────────────────
            logger.info("Running scan %d: %s", scan_id, scan.command)
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE if stdin_data else None,
                limit=4 * 1024 * 1024,  # 4MB readline limit (katana JSON can be huge)
            )
            _running[scan_id] = proc

            if stdin_data:
                proc.stdin.write(stdin_data)
                proc.stdin.close()

            # Read output and parse results
            result_count = 0
            seen = set()

            if tool_name == "ffuf":
                # ffuf outputs a single JSON document, not JSONL — read all at once
                stdout_bytes = await proc.stdout.read()
                await proc.wait()
                stderr = (await proc.stderr.read()).decode("utf-8", errors="replace")
                stdout_text = stdout_bytes.decode("utf-8", errors="replace").strip()
                if stdout_text:
                    parsed_results = _parse_ffuf_json(stdout_text)
                    for result_type, value, metadata in parsed_results:
                        if not value:
                            continue
                        if value in seen:
                            continue
                        seen.add(value)
                        if not enforcer.is_in_scope(value):
                            continue
                        db.add(ScanResult(
                            scan_id=scan_id,
                            result_type=result_type,
                            value=value,
                            metadata_json=metadata,
                        ))
                        result_count += 1
                    await db.commit()
            else:
                # Line-by-line streaming for all other tools
                while True:
                    line_bytes = await proc.stdout.readline()
                    if not line_bytes:
                        break
                    line = line_bytes.decode("utf-8", errors="replace").strip()
                    if not line:
                        continue

                    parsed_results = _parse_line(tool_name, line)
                    for result_type, value, metadata in parsed_results:
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

            # Gowitness post-processing: scan output dir for screenshots
            if tool_name == "gowitness":
                screenshot_dir = Path(f"/tmp/gowitness/project_{project_id}")
                if screenshot_dir.is_dir():
                    for png_file in screenshot_dir.glob("*.png"):
                        value = png_file.name
                        if value in seen:
                            continue
                        seen.add(value)
                        db.add(ScanResult(
                            scan_id=scan_id,
                            result_type="screenshot",
                            value=value,
                            metadata_json=json.dumps({
                                "screenshot_path": str(png_file),
                                "project_id": project_id,
                            }),
                        ))
                        result_count += 1
                    await db.commit()

            # Check if scan was cancelled (terminated by cancel_scan)
            if proc.returncode and proc.returncode < 0:
                # Negative return code = killed by signal (SIGTERM=-15, SIGKILL=-9)
                scan.status = ScanStatus.cancelled
            else:
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
        # Update DB status to cancelled
        async with async_session() as db:
            scan = await db.get(Scan, scan_id)
            if scan and scan.status == ScanStatus.running:
                scan.status = ScanStatus.cancelled
                scan.completed_at = datetime.now(timezone.utc)
                await db.commit()
        return True
    return False


def get_running_scan_ids() -> list[int]:
    return list(_running.keys())
