from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db.engine import get_db
from app.db.models import Project, ProjectCategory, Target, TargetType, ScopeDirection
from app.schemas.project import (
    ProjectCreate,
    ProjectUpdate,
    ProjectOut,
    ProjectListOut,
    TargetCreate,
    TargetUpdate,
    TargetOut,
    ScopeValidateRequest,
    ScopeValidateResponse,
)
from app.services.scope import ScopeEnforcer

router = APIRouter(tags=["projects"])


@router.get("/api/projects", response_model=list[ProjectListOut])
async def list_projects(db: AsyncSession = Depends(get_db)):
    stmt = (
        select(
            Project.id,
            Project.name,
            Project.description,
            Project.category,
            Project.target_value,
            Project.created_at,
            Project.updated_at,
            func.count(Target.id).label("target_count"),
        )
        .outerjoin(Target)
        .group_by(Project.id)
        .order_by(Project.updated_at.desc())
    )
    result = await db.execute(stmt)
    return [ProjectListOut.model_validate(dict(r._mapping)) for r in result.all()]


@router.post("/api/projects", response_model=ProjectOut, status_code=201)
async def create_project(body: ProjectCreate, db: AsyncSession = Depends(get_db)):
    existing = await db.execute(select(Project).where(Project.name == body.name))
    if existing.scalar_one_or_none():
        raise HTTPException(409, "Project with this name already exists")

    project = Project(
        name=body.name,
        description=body.description,
        category=body.category,
        target_value=body.target_value,
    )
    db.add(project)
    await db.commit()
    await db.refresh(project)

    # Auto-create initial in-scope target(s) from target_value + category
    if body.target_value:
        target_type_map = {
            ProjectCategory.wildcard_domain: TargetType.wildcard_domain,
            ProjectCategory.single_host: TargetType.url,
            ProjectCategory.single_ip: TargetType.ip,
            ProjectCategory.cidr_range: TargetType.ip_range,
            ProjectCategory.ip_list: TargetType.ip,
        }
        tt = target_type_map.get(body.category, TargetType.wildcard_domain)

        if body.category == ProjectCategory.ip_list:
            # Parse multi-line IP list: one Target per non-empty line
            # Reverse so bottom IPs get scanned first (avoid overlap with other testers)
            ips = [line.strip() for line in body.target_value.splitlines() if line.strip()]
            ips.reverse()
            for ip in ips:
                db.add(Target(
                    project_id=project.id,
                    value=ip,
                    target_type=TargetType.ip,
                    direction=ScopeDirection.in_scope,
                ))
        else:
            db.add(Target(
                project_id=project.id,
                value=body.target_value,
                target_type=tt,
                direction=ScopeDirection.in_scope,
            ))
        await db.commit()

    result = await db.execute(
        select(Project).options(selectinload(Project.targets)).where(Project.id == project.id)
    )
    return result.scalar_one()


@router.get("/api/projects/{project_id}", response_model=ProjectOut)
async def get_project(project_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Project).options(selectinload(Project.targets)).where(Project.id == project_id)
    )
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")
    return project


@router.put("/api/projects/{project_id}", response_model=ProjectOut)
async def update_project(
    project_id: int, body: ProjectUpdate, db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(Project).options(selectinload(Project.targets)).where(Project.id == project_id)
    )
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")

    if body.name is not None:
        project.name = body.name
    if body.description is not None:
        project.description = body.description

    await db.commit()
    await db.refresh(project)
    return project


@router.delete("/api/projects/{project_id}")
async def delete_project(project_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")

    await db.delete(project)
    await db.commit()
    return {"message": "Project deleted"}


# --- Targets ---


@router.get("/api/projects/{project_id}/targets", response_model=list[TargetOut])
async def list_targets(project_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Target).where(Target.project_id == project_id))
    return result.scalars().all()


@router.post("/api/projects/{project_id}/targets", response_model=TargetOut, status_code=201)
async def create_target(
    project_id: int, body: TargetCreate, db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Project).where(Project.id == project_id))
    if not result.scalar_one_or_none():
        raise HTTPException(404, "Project not found")

    target = Target(
        project_id=project_id,
        value=body.value,
        target_type=body.target_type,
        direction=body.direction,
    )
    db.add(target)
    await db.commit()
    await db.refresh(target)
    return target


@router.put("/api/projects/{project_id}/targets/{target_id}", response_model=TargetOut)
async def update_target(
    project_id: int, target_id: int, body: TargetUpdate, db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(Target).where(Target.id == target_id, Target.project_id == project_id)
    )
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(404, "Target not found")

    if body.value is not None:
        target.value = body.value
    if body.target_type is not None:
        target.target_type = body.target_type
    if body.direction is not None:
        target.direction = body.direction

    await db.commit()
    await db.refresh(target)
    return target


@router.delete("/api/projects/{project_id}/targets/{target_id}")
async def delete_target(
    project_id: int, target_id: int, db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(Target).where(Target.id == target_id, Target.project_id == project_id)
    )
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(404, "Target not found")

    await db.delete(target)
    await db.commit()
    return {"message": "Target deleted"}


@router.post("/api/projects/{project_id}/targets/validate", response_model=ScopeValidateResponse)
async def validate_scope(
    project_id: int, body: ScopeValidateRequest, db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Target).where(Target.project_id == project_id))
    targets = result.scalars().all()

    enforcer = ScopeEnforcer(targets)
    in_scope = []
    out_of_scope = []
    for v in body.values:
        if enforcer.is_in_scope(v):
            in_scope.append(v)
        else:
            out_of_scope.append(v)

    return ScopeValidateResponse(in_scope=in_scope, out_of_scope=out_of_scope)
