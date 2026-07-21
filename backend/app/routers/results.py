"""
Phase 6: Aggregated results across all scans for a project.
Provides deduplication, filtering by type, search, and consolidation view.
"""

import json
import re
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from sqlalchemy import select, func, distinct
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.engine import get_db
from app.db.models import ScanResult, Scan, ScanStatus, Project
from app.services.roi_scorer import calculate_roi_score
from pydantic import BaseModel

router = APIRouter(tags=["results"])


class AggregatedResult(BaseModel):
    value: str
    result_type: str
    count: int  # how many scans found this
    latest_scan_id: int
    metadata_json: str


class ResultStats(BaseModel):
    total: int
    subdomains: int
    urls: int
    live_hosts: int
    ports: int
    directories: int
    vulnerabilities: int
    dns_records: int
    screenshots: int


# ── Consolidation models ─────────────────────────────────────────────

class ConsolidatedEndpoint(BaseModel):
    value: str
    result_type: str
    count: int
    status_code: int | None = None
    title: str | None = None
    server: str | None = None
    tech: list[str] = []
    ip: str | None = None
    content_length: int | None = None
    screenshot_filename: str | None = None
    vulnerability_count: int = 0
    source_tools: list[str] = []
    roi_score: int = 0
    roi_priority: str = "low"
    metadata_json: str = "{}"


class ConsolidationStats(BaseModel):
    total_endpoints: int
    by_type: dict[str, int]
    by_status: dict[str, int]
    by_priority: dict[str, int]


class ConsolidationResponse(BaseModel):
    stats: ConsolidationStats
    endpoints: list[ConsolidatedEndpoint]


class ConsolidateRequest(BaseModel):
    run_screenshots: bool = False
    threads: int = 10


@router.get("/api/projects/{project_id}/results/stats", response_model=ResultStats)
async def get_result_stats(project_id: int, db: AsyncSession = Depends(get_db)):
    base = (
        select(ScanResult.result_type, func.count(distinct(ScanResult.value)))
        .join(Scan)
        .where(Scan.project_id == project_id)
        .group_by(ScanResult.result_type)
    )
    result = await db.execute(base)
    counts = {row[0]: row[1] for row in result.all()}

    total = sum(counts.values())
    return ResultStats(
        total=total,
        subdomains=counts.get("subdomain", 0),
        urls=counts.get("url", 0),
        live_hosts=counts.get("live_host", 0),
        ports=counts.get("port", 0),
        directories=counts.get("directory", 0),
        vulnerabilities=counts.get("vulnerability", 0),
        dns_records=counts.get("dns_record", 0),
        screenshots=counts.get("screenshot", 0),
    )


@router.get("/api/projects/{project_id}/results", response_model=list[AggregatedResult])
async def get_results(
    project_id: int,
    result_type: str | None = Query(None),
    search: str | None = Query(None),
    limit: int = Query(200, le=1000),
    offset: int = Query(0),
    db: AsyncSession = Depends(get_db),
):
    """Get deduplicated results across all scans for a project."""
    stmt = (
        select(
            ScanResult.value,
            ScanResult.result_type,
            func.count(ScanResult.id).label("count"),
            func.max(ScanResult.scan_id).label("latest_scan_id"),
            ScanResult.metadata_json,
        )
        .join(Scan)
        .where(Scan.project_id == project_id)
    )

    if result_type:
        stmt = stmt.where(ScanResult.result_type == result_type)

    if search:
        stmt = stmt.where(ScanResult.value.contains(search))

    stmt = (
        stmt
        .group_by(ScanResult.value, ScanResult.result_type)
        .order_by(func.count(ScanResult.id).desc())
        .offset(offset)
        .limit(limit)
    )

    result = await db.execute(stmt)
    return [
        AggregatedResult(
            value=row.value,
            result_type=row.result_type,
            count=row.count,
            latest_scan_id=row.latest_scan_id,
            metadata_json=row.metadata_json or "{}",
        )
        for row in result.all()
    ]


@router.delete("/api/projects/{project_id}/results")
async def clear_results(project_id: int, db: AsyncSession = Depends(get_db)):
    """Delete all scan results for a project (keeps scan records)."""
    stmt = select(Scan.id).where(Scan.project_id == project_id)
    result = await db.execute(stmt)
    scan_ids = [row[0] for row in result.all()]

    if scan_ids:
        from sqlalchemy import delete
        await db.execute(
            delete(ScanResult).where(ScanResult.scan_id.in_(scan_ids))
        )
        await db.commit()

    return {"message": "Results cleared"}


# ── Consolidation endpoints ──────────────────────────────────────────


def _safe_parse(raw: str | None) -> dict:
    try:
        return json.loads(raw or "{}")
    except (json.JSONDecodeError, TypeError):
        return {}


def _status_class(code: int | None) -> str | None:
    if code is None:
        return None
    if 200 <= code < 300:
        return "2xx"
    if 300 <= code < 400:
        return "3xx"
    if 400 <= code < 500:
        return "4xx"
    if 500 <= code < 600:
        return "5xx"
    return None


def _extract_host(value: str) -> str:
    """Extract hostname from a URL or subdomain value for cross-referencing."""
    v = value
    if "://" in v:
        v = v.split("://", 1)[1]
    v = v.split("/", 1)[0]
    v = v.split(":", 1)[0]
    return v.lower()


@router.get("/api/projects/{project_id}/consolidation", response_model=ConsolidationResponse)
async def get_consolidation(
    project_id: int,
    result_type: str | None = Query(None),
    status_class: str | None = Query(None, pattern="^[2345]xx$"),
    priority: str | None = Query(None, pattern="^(critical|high|medium|low)$"),
    search: str | None = Query(None),
    sort_by: str = Query("roi_score", pattern="^(roi_score|status_code|value|count)$"),
    sort_dir: str = Query("desc", pattern="^(asc|desc)$"),
    limit: int = Query(200, le=1000),
    offset: int = Query(0),
    db: AsyncSession = Depends(get_db),
):
    """Consolidated view: deduplicated endpoints with ROI scoring."""

    # 1. GROUP BY (value, result_type) for dedup + count
    base = (
        select(
            ScanResult.value,
            ScanResult.result_type,
            func.count(ScanResult.id).label("count"),
            func.max(ScanResult.metadata_json).label("metadata_json"),
        )
        .join(Scan)
        .where(Scan.project_id == project_id)
    )
    # Exclude screenshots from consolidation view (they're shown inline)
    base = base.where(ScanResult.result_type != "screenshot")

    if result_type:
        base = base.where(ScanResult.result_type == result_type)
    if search:
        base = base.where(ScanResult.value.contains(search))

    base = base.group_by(ScanResult.value, ScanResult.result_type)
    result = await db.execute(base)
    raw_rows = result.all()

    # 2. Build lookup: value → list of tool_names
    tool_stmt = (
        select(ScanResult.value, Scan.tool_name)
        .join(Scan)
        .where(Scan.project_id == project_id)
        .where(ScanResult.result_type != "screenshot")
        .group_by(ScanResult.value, Scan.tool_name)
    )
    tool_result = await db.execute(tool_stmt)
    tool_map: dict[str, list[str]] = {}
    for row in tool_result.all():
        tool_map.setdefault(row[0], []).append(row[1])

    # 3. Build lookup: host → live_host metadata (status_code, title, tech, etc.)
    live_stmt = (
        select(ScanResult.value, ScanResult.metadata_json)
        .join(Scan)
        .where(Scan.project_id == project_id)
        .where(ScanResult.result_type == "live_host")
    )
    live_result = await db.execute(live_stmt)
    live_map: dict[str, dict] = {}  # host → metadata
    live_url_map: dict[str, dict] = {}  # full URL → metadata
    for row in live_result.all():
        meta = _safe_parse(row[1])
        live_url_map[row[0]] = meta
        host = _extract_host(row[0])
        live_map[host] = meta

    # 4. Build lookup: host → vuln count
    vuln_stmt = (
        select(ScanResult.value, func.count(ScanResult.id).label("vc"))
        .join(Scan)
        .where(Scan.project_id == project_id)
        .where(ScanResult.result_type == "vulnerability")
        .group_by(ScanResult.value)
    )
    vuln_result = await db.execute(vuln_stmt)
    vuln_map: dict[str, int] = {row[0]: row[1] for row in vuln_result.all()}

    # 5. Build lookup: screenshot filenames by host
    ss_stmt = (
        select(ScanResult.value)
        .join(Scan)
        .where(Scan.project_id == project_id)
        .where(ScanResult.result_type == "screenshot")
    )
    ss_result = await db.execute(ss_stmt)
    screenshot_files: set[str] = {row[0] for row in ss_result.all()}

    # 6. Build consolidated endpoints
    endpoints: list[ConsolidatedEndpoint] = []
    stats_by_type: dict[str, int] = {}
    stats_by_status: dict[str, int] = {}
    stats_by_priority: dict[str, int] = {}

    for row in raw_rows:
        value = row[0]
        rtype = row[1]
        count = row[2]
        raw_meta = row[3]

        meta = _safe_parse(raw_meta)
        host = _extract_host(value)

        # Cross-reference live_host data for non-live_host result types
        if rtype == "live_host":
            live_meta = meta
        else:
            live_meta = live_url_map.get(value) or live_map.get(host) or {}

        status_code = live_meta.get("status_code") or meta.get("status_code")
        title = live_meta.get("title") or meta.get("title")
        server = live_meta.get("server") or meta.get("server", "")
        tech = live_meta.get("tech") or meta.get("tech", [])
        if not isinstance(tech, list):
            tech = []
        ip = live_meta.get("ip") or meta.get("ip")
        content_length = live_meta.get("content_length") or meta.get("content_length")

        # Vulnerability count for this host
        vc = vuln_map.get(value, 0) or vuln_map.get(host, 0)

        # Source tools
        tools = tool_map.get(value, [])

        # Screenshot filename match (heuristic: filename contains host)
        ss_file = None
        for sf in screenshot_files:
            if host in sf.lower():
                ss_file = sf
                break

        # ROI scoring
        score_meta = {
            "status_code": status_code,
            "tech": tech,
            "server": server,
        }
        roi_score, roi_priority = calculate_roi_score(
            value, rtype, score_meta, count, vc
        )

        ep = ConsolidatedEndpoint(
            value=value,
            result_type=rtype,
            count=count,
            status_code=status_code,
            title=title,
            server=server,
            tech=tech,
            ip=ip,
            content_length=content_length,
            screenshot_filename=ss_file,
            vulnerability_count=vc,
            source_tools=tools,
            roi_score=roi_score,
            roi_priority=roi_priority,
            metadata_json=raw_meta or "{}",
        )

        # Apply post-query filters on computed fields
        if status_class and _status_class(status_code) != status_class:
            continue
        if priority and roi_priority != priority:
            continue

        endpoints.append(ep)

        # Stats
        stats_by_type[rtype] = stats_by_type.get(rtype, 0) + 1
        sc = _status_class(status_code)
        if sc:
            stats_by_status[sc] = stats_by_status.get(sc, 0) + 1
        stats_by_priority[roi_priority] = stats_by_priority.get(roi_priority, 0) + 1

    # Sort
    reverse = sort_dir == "desc"
    if sort_by == "roi_score":
        endpoints.sort(key=lambda e: e.roi_score, reverse=reverse)
    elif sort_by == "status_code":
        endpoints.sort(key=lambda e: e.status_code or 0, reverse=reverse)
    elif sort_by == "value":
        endpoints.sort(key=lambda e: e.value, reverse=reverse)
    elif sort_by == "count":
        endpoints.sort(key=lambda e: e.count, reverse=reverse)

    total = len(endpoints)
    paginated = endpoints[offset : offset + limit]

    return ConsolidationResponse(
        stats=ConsolidationStats(
            total_endpoints=total,
            by_type=stats_by_type,
            by_status=stats_by_status,
            by_priority=stats_by_priority,
        ),
        endpoints=paginated,
    )


@router.post("/api/projects/{project_id}/consolidate")
async def run_consolidation(
    project_id: int,
    body: ConsolidateRequest,
    db: AsyncSession = Depends(get_db),
):
    """Trigger httpx probe on unprobed subdomains/URLs."""
    from app.services.scan_runner import start_scan

    # Verify project exists
    proj = await db.execute(select(Project).where(Project.id == project_id))
    if not proj.scalar_one_or_none():
        raise HTTPException(404, "Project not found")

    # Get unique subdomains + URLs that have NO matching live_host result
    sub_stmt = (
        select(distinct(ScanResult.value))
        .join(Scan)
        .where(Scan.project_id == project_id)
        .where(ScanResult.result_type.in_(["subdomain", "url"]))
    )
    sub_result = await db.execute(sub_stmt)
    all_targets = {row[0] for row in sub_result.all()}

    # Get already-probed values (live_host results)
    live_stmt = (
        select(distinct(ScanResult.value))
        .join(Scan)
        .where(Scan.project_id == project_id)
        .where(ScanResult.result_type == "live_host")
    )
    live_result = await db.execute(live_stmt)
    probed_urls = {row[0] for row in live_result.all()}

    # Also match by host extraction
    probed_hosts = {_extract_host(u) for u in probed_urls}
    unprobed = [
        t for t in all_targets
        if t not in probed_urls and _extract_host(t) not in probed_hosts
    ]

    if not unprobed:
        return {"scan_id": None, "target_count": 0, "message": "All endpoints already probed"}

    # Create consolidation scan
    scan = Scan(
        project_id=project_id,
        scan_type="consolidation",
        tool_name="httpx",
        status=ScanStatus.pending,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Launch httpx with stdin_targets
    await start_scan(
        scan_id=scan.id,
        project_id=project_id,
        tool_name="httpx",
        scan_type="consolidation",
        target_override=None,
        options={
            "threads": body.threads,
            "stdin_targets": unprobed,
        },
    )

    result_payload = {
        "scan_id": scan.id,
        "target_count": len(unprobed),
    }

    # Queue gowitness if requested
    if body.run_screenshots:
        ss_scan = Scan(
            project_id=project_id,
            scan_type="consolidation",
            tool_name="gowitness",
            status=ScanStatus.pending,
        )
        db.add(ss_scan)
        await db.commit()
        await db.refresh(ss_scan)

        await start_scan(
            scan_id=ss_scan.id,
            project_id=project_id,
            tool_name="gowitness",
            scan_type="consolidation",
            target_override=None,
            options={"threads": body.threads},
        )
        result_payload["screenshot_scan_id"] = ss_scan.id

    return result_payload


# Filename validation: alphanumeric, dashes, underscores, dots — no path separators
_SAFE_FILENAME = re.compile(r"^[a-zA-Z0-9._-]+\.png$")


@router.get("/api/screenshots/{project_id}/{filename}")
async def serve_screenshot(project_id: int, filename: str):
    """Serve gowitness screenshot PNG files."""
    if not _SAFE_FILENAME.match(filename):
        raise HTTPException(400, "Invalid filename")

    file_path = Path(f"/tmp/gowitness/project_{project_id}") / filename
    if not file_path.is_file():
        raise HTTPException(404, "Screenshot not found")

    return FileResponse(file_path, media_type="image/png")
