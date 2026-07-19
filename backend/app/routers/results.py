"""
Phase 6: Aggregated results across all scans for a project.
Provides deduplication, filtering by type, and search.
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, func, distinct
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.engine import get_db
from app.db.models import ScanResult, Scan
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
