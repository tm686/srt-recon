from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.engine import get_db
from app.db.models import ApiKey, Project
from app.schemas.api_key import ApiKeyCreate, ApiKeyUpdate, ApiKeyOut, ApiKeyTestResult
from app.services.crypto import encrypt_value, decrypt_value, mask_key
from app.services.key_tester import test_api_key

router = APIRouter(tags=["api_keys"])


def _require_fernet(request: Request) -> bytes:
    fernet_key = getattr(request.app.state, "fernet_key", None)
    if not fernet_key:
        raise HTTPException(423, "Vault is locked. Unlock first.")
    return fernet_key


def _to_out(api_key: ApiKey, fernet_key: bytes) -> ApiKeyOut:
    try:
        plaintext = decrypt_value(api_key.encrypted_key, fernet_key)
        masked = mask_key(plaintext)
    except Exception:
        masked = "****"
    return ApiKeyOut(
        id=api_key.id,
        project_id=api_key.project_id,
        provider=api_key.provider,
        masked_key=masked,
        is_valid=api_key.is_valid,
        last_tested_at=api_key.last_tested_at,
    )


@router.get("/api/projects/{project_id}/keys", response_model=list[ApiKeyOut])
async def list_keys(
    project_id: int, request: Request, db: AsyncSession = Depends(get_db)
):
    fernet_key = _require_fernet(request)
    result = await db.execute(select(ApiKey).where(ApiKey.project_id == project_id))
    return [_to_out(k, fernet_key) for k in result.scalars().all()]


@router.post("/api/projects/{project_id}/keys", response_model=ApiKeyOut, status_code=201)
async def create_key(
    project_id: int,
    body: ApiKeyCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    fernet_key = _require_fernet(request)

    result = await db.execute(select(Project).where(Project.id == project_id))
    if not result.scalar_one_or_none():
        raise HTTPException(404, "Project not found")

    encrypted = encrypt_value(body.key, fernet_key)
    api_key = ApiKey(
        project_id=project_id,
        provider=body.provider,
        encrypted_key=encrypted,
    )
    db.add(api_key)
    await db.commit()
    await db.refresh(api_key)
    return _to_out(api_key, fernet_key)


@router.put("/api/projects/{project_id}/keys/{key_id}", response_model=ApiKeyOut)
async def update_key(
    project_id: int,
    key_id: int,
    body: ApiKeyUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    fernet_key = _require_fernet(request)
    result = await db.execute(
        select(ApiKey).where(ApiKey.id == key_id, ApiKey.project_id == project_id)
    )
    api_key = result.scalar_one_or_none()
    if not api_key:
        raise HTTPException(404, "API key not found")

    if body.provider is not None:
        api_key.provider = body.provider
    if body.key is not None:
        api_key.encrypted_key = encrypt_value(body.key, fernet_key)
        api_key.is_valid = False
        api_key.last_tested_at = None

    await db.commit()
    await db.refresh(api_key)
    return _to_out(api_key, fernet_key)


@router.delete("/api/projects/{project_id}/keys/{key_id}")
async def delete_key(
    project_id: int, key_id: int, db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(ApiKey).where(ApiKey.id == key_id, ApiKey.project_id == project_id)
    )
    api_key = result.scalar_one_or_none()
    if not api_key:
        raise HTTPException(404, "API key not found")

    await db.delete(api_key)
    await db.commit()
    return {"message": "API key deleted"}


@router.post("/api/projects/{project_id}/keys/{key_id}/test", response_model=ApiKeyTestResult)
async def test_key(
    project_id: int,
    key_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    fernet_key = _require_fernet(request)
    result = await db.execute(
        select(ApiKey).where(ApiKey.id == key_id, ApiKey.project_id == project_id)
    )
    api_key = result.scalar_one_or_none()
    if not api_key:
        raise HTTPException(404, "API key not found")

    plaintext = decrypt_value(api_key.encrypted_key, fernet_key)
    is_valid, message = await test_api_key(api_key.provider, plaintext)

    api_key.is_valid = is_valid
    api_key.last_tested_at = datetime.now(timezone.utc)
    await db.commit()

    return ApiKeyTestResult(
        id=api_key.id,
        provider=api_key.provider,
        is_valid=is_valid,
        message=message,
    )
