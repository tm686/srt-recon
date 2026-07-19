"""
Phase 7: Export results in multiple formats (JSON, CSV, Markdown).
"""

import csv
import io
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import select, func, distinct
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.engine import get_db
from app.db.models import Scan, ScanResult, Project, Target

router = APIRouter(tags=["export"])


async def _get_project_results(
    project_id: int, result_type: str | None, db: AsyncSession
) -> list[dict]:
    stmt = (
        select(
            ScanResult.value,
            ScanResult.result_type,
            ScanResult.metadata_json,
            func.count(ScanResult.id).label("count"),
        )
        .join(Scan)
        .where(Scan.project_id == project_id)
    )
    if result_type:
        stmt = stmt.where(ScanResult.result_type == result_type)

    stmt = stmt.group_by(ScanResult.value, ScanResult.result_type).order_by(
        ScanResult.result_type, ScanResult.value
    )
    result = await db.execute(stmt)
    return [
        {
            "value": row.value,
            "type": row.result_type,
            "metadata": row.metadata_json or "{}",
            "scan_count": row.count,
        }
        for row in result.all()
    ]


@router.get("/api/projects/{project_id}/export/json")
async def export_json(
    project_id: int,
    result_type: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        return {"error": "Project not found"}

    results = await _get_project_results(project_id, result_type, db)
    export = {
        "project": project.name,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "result_count": len(results),
        "filter": result_type or "all",
        "results": results,
    }

    content = json.dumps(export, indent=2)
    return StreamingResponse(
        io.BytesIO(content.encode()),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{project.name}_results.json"'},
    )


@router.get("/api/projects/{project_id}/export/csv")
async def export_csv(
    project_id: int,
    result_type: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        return {"error": "Project not found"}

    results = await _get_project_results(project_id, result_type, db)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["value", "type", "metadata", "scan_count"])
    for r in results:
        writer.writerow([r["value"], r["type"], r["metadata"], r["scan_count"]])

    content = output.getvalue()
    return StreamingResponse(
        io.BytesIO(content.encode()),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{project.name}_results.csv"'},
    )


@router.get("/api/projects/{project_id}/export/markdown")
async def export_markdown(
    project_id: int,
    result_type: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        return {"error": "Project not found"}

    # Get targets
    target_result = await db.execute(select(Target).where(Target.project_id == project_id))
    targets = target_result.scalars().all()

    results = await _get_project_results(project_id, result_type, db)

    # Group by type
    grouped: dict[str, list] = {}
    for r in results:
        grouped.setdefault(r["type"], []).append(r)

    lines = [
        f"# Recon Report: {project.name}",
        f"",
        f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"**Total unique findings:** {len(results)}",
        f"",
        f"## Scope",
        f"",
    ]

    in_scope = [t for t in targets if t.direction.value == "in_scope"]
    out_scope = [t for t in targets if t.direction.value == "out_of_scope"]

    if in_scope:
        lines.append("**In scope:**")
        for t in in_scope:
            lines.append(f"- `{t.value}` ({t.target_type.value})")
        lines.append("")

    if out_scope:
        lines.append("**Out of scope:**")
        for t in out_scope:
            lines.append(f"- `{t.value}` ({t.target_type.value})")
        lines.append("")

    lines.append("## Findings")
    lines.append("")

    type_labels = {
        "subdomain": "Subdomains",
        "live_host": "Live Hosts",
        "url": "URLs",
        "port": "Ports / Services",
        "directory": "Directories",
        "vulnerability": "Vulnerabilities",
        "dns_record": "DNS Records",
    }

    for rtype, items in grouped.items():
        label = type_labels.get(rtype, rtype.replace("_", " ").title())
        lines.append(f"### {label} ({len(items)})")
        lines.append("")

        if rtype == "vulnerability":
            lines.append("| Host | Template | Severity |")
            lines.append("|------|----------|----------|")
            for item in items:
                meta = json.loads(item["metadata"]) if item["metadata"] != "{}" else {}
                lines.append(
                    f"| `{item['value']}` | {meta.get('template_id', '')} | {meta.get('severity', '')} |"
                )
        elif rtype == "live_host":
            lines.append("| URL | Status | Title |")
            lines.append("|-----|--------|-------|")
            for item in items[:100]:
                meta = json.loads(item["metadata"]) if item["metadata"] != "{}" else {}
                lines.append(
                    f"| `{item['value']}` | {meta.get('status_code', '')} | {meta.get('title', '')} |"
                )
            if len(items) > 100:
                lines.append(f"| ... | {len(items) - 100} more | |")
        else:
            for item in items[:200]:
                lines.append(f"- `{item['value']}`")
            if len(items) > 200:
                lines.append(f"- ... and {len(items) - 200} more")

        lines.append("")

    content = "\n".join(lines)
    return StreamingResponse(
        io.BytesIO(content.encode()),
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="{project.name}_report.md"'},
    )


@router.get("/api/projects/{project_id}/export/targets")
async def export_targets(
    project_id: int,
    result_type: str = Query("subdomain"),
    db: AsyncSession = Depends(get_db),
):
    """Export unique values as a plain-text list (one per line) for piping into tools."""
    stmt = (
        select(distinct(ScanResult.value))
        .join(Scan)
        .where(Scan.project_id == project_id, ScanResult.result_type == result_type)
        .order_by(ScanResult.value)
    )
    result = await db.execute(stmt)
    values = [row[0] for row in result.all()]
    content = "\n".join(values) + "\n"

    return StreamingResponse(
        io.BytesIO(content.encode()),
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="{result_type}s.txt"'},
    )
