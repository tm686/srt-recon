from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.engine import get_db
from app.db.models import Project, Scan, ScanResult, ScanStatus
from app.schemas.scan import ScanCreate, ScanOut, ScanResultOut, ScanListOut, ScanLaunchConfig
from app.services.scan_runner import start_scan, cancel_scan, get_running_scan_ids
from app.services.autoscan import get_pipeline, get_quick_pipeline, get_deep_pipeline, get_threads, get_tools_for_category
from app.services.settings_service import get_setting

from pathlib import Path

_BUNDLED_WORDLISTS = Path(__file__).resolve().parents[3] / "wordlists"

router = APIRouter(tags=["scans"])


def _scan_to_out(scan: Scan, result_count: int = 0) -> ScanOut:
    return ScanOut(
        id=scan.id,
        project_id=scan.project_id,
        scan_type=scan.scan_type,
        status=scan.status.value if scan.status else "pending",
        tool_name=scan.tool_name,
        command=scan.command or "",
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        error_message=scan.error_message,
        result_count=result_count,
    )


@router.get("/api/projects/{project_id}/scans", response_model=ScanListOut)
async def list_scans(project_id: int, db: AsyncSession = Depends(get_db)):
    stmt = (
        select(Scan, func.count(ScanResult.id).label("result_count"))
        .outerjoin(ScanResult)
        .where(Scan.project_id == project_id)
        .group_by(Scan.id)
        .order_by(Scan.id.desc())
    )
    result = await db.execute(stmt)
    scans = [_scan_to_out(row[0], row[1]) for row in result.all()]
    running = len(get_running_scan_ids())
    return ScanListOut(scans=scans, running_count=running)


@router.post("/api/projects/{project_id}/scans", response_model=ScanOut, status_code=201)
async def create_scan(
    project_id: int, body: ScanCreate, db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Project).where(Project.id == project_id))
    if not result.scalar_one_or_none():
        raise HTTPException(404, "Project not found")

    scan = Scan(
        project_id=project_id,
        scan_type=body.scan_type,
        tool_name=body.tool_name,
        status=ScanStatus.pending,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    await start_scan(
        scan_id=scan.id,
        project_id=project_id,
        tool_name=body.tool_name,
        scan_type=body.scan_type,
        target_override=body.target_override,
        options=body.options,
    )

    return _scan_to_out(scan)


# --- Specific paths MUST come before parameterized {scan_id} routes ---


@router.post("/api/projects/{project_id}/scans/quick", response_model=list[ScanOut])
async def quick_scan(
    project_id: int,
    config: ScanLaunchConfig | None = None,
    db: AsyncSession = Depends(get_db),
):
    """Launch a reduced quick-scan pipeline with small wordlists and fewer tools."""
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")

    base_threads = int(await get_setting(db, "default_threads") or "10")
    threads = max(1, base_threads // 2)  # half threads for quick scan

    pipeline = get_quick_pipeline(project.category.value)
    created_scans = []

    for step in pipeline:
        scan = Scan(
            project_id=project_id,
            scan_type=step["type"],
            tool_name=step["tool"],
            status=ScanStatus.pending,
        )
        db.add(scan)
        await db.commit()
        await db.refresh(scan)

        opts: dict = {"threads": threads}
        # Quick scan overrides
        if step["tool"] == "nmap":
            opts["ports"] = config.ports if config and config.ports else "--top-ports 100"
        if step["tool"] == "nuclei":
            opts["severity"] = "high,critical"

        await start_scan(
            scan_id=scan.id,
            project_id=project_id,
            tool_name=step["tool"],
            scan_type=step["type"],
            target_override=None,
            options=opts,
        )
        created_scans.append(_scan_to_out(scan))

    return created_scans


@router.post("/api/projects/{project_id}/scans/auto", response_model=list[ScanOut])
async def auto_scan(
    project_id: int,
    config: ScanLaunchConfig | None = None,
    db: AsyncSession = Depends(get_db),
):
    """Launch all relevant tools for this project's category in smart order."""
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")

    aggressiveness = await get_setting(db, "aggressiveness") or "normal"
    base_threads = int(await get_setting(db, "default_threads") or "10")
    threads = get_threads(base_threads, aggressiveness)

    pipeline = get_pipeline(project.category.value, aggressiveness)
    created_scans = []

    for step in pipeline:
        scan = Scan(
            project_id=project_id,
            scan_type=step["type"],
            tool_name=step["tool"],
            status=ScanStatus.pending,
        )
        db.add(scan)
        await db.commit()
        await db.refresh(scan)

        opts: dict = {"threads": threads}
        if step["tool"] == "nmap" and config and config.ports:
            opts["ports"] = config.ports

        await start_scan(
            scan_id=scan.id,
            project_id=project_id,
            tool_name=step["tool"],
            scan_type=step["type"],
            target_override=None,
            options=opts,
        )
        created_scans.append(_scan_to_out(scan))

    return created_scans


@router.post("/api/projects/{project_id}/scans/deep", response_model=list[ScanOut])
async def deep_scan(
    project_id: int,
    config: ScanLaunchConfig | None = None,
    db: AsyncSession = Depends(get_db),
):
    """Launch thorough deep-scan: all tools, long wordlists, all ports, all severities."""
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")

    base_threads = int(await get_setting(db, "default_threads") or "10")
    threads = get_threads(base_threads, "aggressive")

    pipeline = get_deep_pipeline(project.category.value)
    created_scans = []

    # Resolve wordlist: prefer long bundled wordlist for deep scan
    deep_wordlist = str(_BUNDLED_WORDLISTS / "ffuf-wordlist-default-long.txt")
    wl_setting = await get_setting(db, "wordlist_ffuf")
    # Only override if user explicitly set one; otherwise use deep default
    ffuf_wordlist = wl_setting if wl_setting else deep_wordlist

    for step in pipeline:
        scan = Scan(
            project_id=project_id,
            scan_type=step["type"],
            tool_name=step["tool"],
            status=ScanStatus.pending,
        )
        db.add(scan)
        await db.commit()
        await db.refresh(scan)

        opts: dict = {"threads": threads}
        if step["tool"] == "nmap":
            opts["ports"] = config.ports if config and config.ports else "1-65535"
        if step["tool"] == "ffuf":
            opts["wordlist"] = ffuf_wordlist
        if step["tool"] == "nuclei":
            opts["severity"] = "info,low,medium,high,critical"
        if step["tool"] == "katana":
            opts["depth"] = 5

        await start_scan(
            scan_id=scan.id,
            project_id=project_id,
            tool_name=step["tool"],
            scan_type=step["type"],
            target_override=None,
            options=opts,
        )
        created_scans.append(_scan_to_out(scan))

    return created_scans


@router.get("/api/projects/{project_id}/scans/pipeline")
async def get_project_pipeline(project_id: int, db: AsyncSession = Depends(get_db)):
    """Get the auto-scan pipeline for a project based on its category."""
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")

    aggressiveness = await get_setting(db, "aggressiveness") or "normal"
    pipeline = get_pipeline(project.category.value, aggressiveness)
    relevant_tools = get_tools_for_category(project.category.value)

    return {
        "category": project.category.value,
        "aggressiveness": aggressiveness,
        "pipeline": pipeline,
        "relevant_tools": relevant_tools,
    }


# --- Parameterized {scan_id} routes ---


@router.get("/api/projects/{project_id}/scans/{scan_id}", response_model=ScanOut)
async def get_scan(project_id: int, scan_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Scan, func.count(ScanResult.id).label("rc"))
        .outerjoin(ScanResult)
        .where(Scan.id == scan_id, Scan.project_id == project_id)
        .group_by(Scan.id)
    )
    row = result.first()
    if not row:
        raise HTTPException(404, "Scan not found")
    return _scan_to_out(row[0], row[1])


@router.get("/api/projects/{project_id}/scans/{scan_id}/results", response_model=list[ScanResultOut])
async def get_scan_results(
    project_id: int,
    scan_id: int,
    limit: int = 500,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
):
    # Verify scan belongs to project
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.project_id == project_id)
    )
    if not result.scalar_one_or_none():
        raise HTTPException(404, "Scan not found")

    result = await db.execute(
        select(ScanResult)
        .where(ScanResult.scan_id == scan_id)
        .offset(offset)
        .limit(limit)
    )
    return result.scalars().all()


@router.post("/api/projects/{project_id}/scans/{scan_id}/cancel")
async def cancel_scan_endpoint(
    project_id: int, scan_id: int, db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.project_id == project_id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(404, "Scan not found")

    if scan.status != ScanStatus.running:
        raise HTTPException(400, "Scan is not running")

    cancelled = await cancel_scan(scan_id)
    if cancelled:
        scan.status = ScanStatus.cancelled
        await db.commit()

    return {"message": "Scan cancelled" if cancelled else "Scan not found in running processes"}


@router.delete("/api/projects/{project_id}/scans/{scan_id}")
async def delete_scan(project_id: int, scan_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id, Scan.project_id == project_id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(404, "Scan not found")

    if scan.status == ScanStatus.running:
        await cancel_scan(scan_id)

    await db.delete(scan)
    await db.commit()
    return {"message": "Scan deleted"}
