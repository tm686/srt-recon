import base64
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, Body
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.engine import get_db
from app.schemas.settings import (
    SetupRequest,
    UnlockRequest,
    SettingsOut,
    SettingsUpdate,
    PathValidateRequest,
    PathValidateResponse,
    SetupStatusResponse,
    WordlistOption,
)
from app.services.crypto import generate_salt, hash_password, verify_password, derive_fernet_key
from app.services.settings_service import get_setting, set_setting, get_all_settings
from app.services.tool_check import check_tools

# Project root for bundled wordlists
_PROJECT_ROOT = Path(__file__).resolve().parents[3]
_BUNDLED_WORDLISTS = _PROJECT_ROOT / "wordlists"

router = APIRouter(tags=["settings"])


@router.get("/api/setup/status")
async def setup_status(request: Request, db: AsyncSession = Depends(get_db)):
    setup_complete = await get_setting(db, "setup_complete")
    return SetupStatusResponse(
        setup_complete=setup_complete == "true",
        vault_unlocked=getattr(request.app.state, "fernet_key", None) is not None,
    )


@router.post("/api/setup/master-password")
async def setup_master_password(
    body: SetupRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    existing = await get_setting(db, "setup_complete")
    if existing == "true":
        raise HTTPException(400, "Master password already set")

    if body.password != body.confirm_password:
        raise HTTPException(400, "Passwords do not match")

    salt = generate_salt()
    pw_hash = hash_password(body.password, salt)
    fernet_key = derive_fernet_key(body.password, salt)

    await set_setting(db, "master_password_hash", pw_hash)
    await set_setting(db, "master_password_salt", base64.b64encode(salt).decode())
    await set_setting(db, "setup_complete", "true")

    request.app.state.fernet_key = fernet_key
    return {"message": "Master password set successfully"}


@router.post("/api/auth/unlock")
async def unlock_vault(
    body: UnlockRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    stored_hash = await get_setting(db, "master_password_hash")
    salt_b64 = await get_setting(db, "master_password_salt")

    if not stored_hash or not salt_b64:
        raise HTTPException(400, "Master password not set up")

    salt = base64.b64decode(salt_b64)
    if not verify_password(body.password, salt, stored_hash):
        raise HTTPException(401, "Invalid password")

    request.app.state.fernet_key = derive_fernet_key(body.password, salt)
    return {"message": "Vault unlocked"}


@router.post("/api/auth/lock")
async def lock_vault(request: Request):
    request.app.state.fernet_key = None
    return {"message": "Vault locked"}


@router.get("/api/settings")
async def get_settings(db: AsyncSession = Depends(get_db)):
    all_settings = await get_all_settings(db)
    return SettingsOut(
        seclists_path=all_settings.get("seclists_path", "/usr/share/seclists"),
        go_tools_path=all_settings.get("go_tools_path", ""),
        default_threads=int(all_settings.get("default_threads", "10")),
        aggressiveness=all_settings.get("aggressiveness", "normal"),
        wordlist_ffuf=all_settings.get("wordlist_ffuf", ""),
        setup_complete=all_settings.get("setup_complete") == "true",
    )


@router.put("/api/settings")
async def update_settings(body: SettingsUpdate, db: AsyncSession = Depends(get_db)):
    if body.seclists_path is not None:
        await set_setting(db, "seclists_path", body.seclists_path)
    if body.go_tools_path is not None:
        await set_setting(db, "go_tools_path", body.go_tools_path)
    if body.default_threads is not None:
        await set_setting(db, "default_threads", str(body.default_threads))
    if body.aggressiveness is not None:
        if body.aggressiveness in ("conservative", "normal", "aggressive"):
            await set_setting(db, "aggressiveness", body.aggressiveness)
    if body.wordlist_ffuf is not None:
        await set_setting(db, "wordlist_ffuf", body.wordlist_ffuf)
    return {"message": "Settings updated"}


@router.get("/api/settings/wordlists", response_model=list[WordlistOption])
async def list_wordlists(db: AsyncSession = Depends(get_db)):
    """Scan bundled and SecLists directories for .txt wordlists."""
    results: list[dict] = []

    # Bundled wordlists
    if _BUNDLED_WORDLISTS.is_dir():
        for f in sorted(_BUNDLED_WORDLISTS.glob("*.txt")):
            results.append({
                "name": f.name,
                "path": str(f),
                "size_kb": round(f.stat().st_size / 1024, 1),
                "source": "bundled",
            })

    # SecLists Discovery/Web-Content
    seclists_path = await get_setting(db, "seclists_path") or "/usr/share/seclists"
    web_content = Path(seclists_path) / "Discovery" / "Web-Content"
    if web_content.is_dir():
        for f in sorted(web_content.glob("*.txt")):
            results.append({
                "name": f.name,
                "path": str(f),
                "size_kb": round(f.stat().st_size / 1024, 1),
                "source": "seclists",
            })

    return results


@router.post("/api/settings/wordlists/custom")
async def save_custom_wordlist(body: str = Body(..., media_type="text/plain")):
    """Save raw text as a custom wordlist."""
    dest = _BUNDLED_WORDLISTS / "custom.txt"
    _BUNDLED_WORDLISTS.mkdir(parents=True, exist_ok=True)
    dest.write_text(body)
    return {
        "message": "Custom wordlist saved",
        "path": str(dest),
        "size_kb": round(dest.stat().st_size / 1024, 1),
    }


@router.post("/api/settings/validate-path")
async def validate_path(body: PathValidateRequest):
    p = Path(body.path)
    return PathValidateResponse(
        path=body.path,
        exists=p.exists(),
        is_directory=p.is_dir(),
    )


@router.get("/api/settings/tools")
async def get_tool_status(db: AsyncSession = Depends(get_db)):
    go_path = await get_setting(db, "go_tools_path")
    extra_paths = [go_path] if go_path else []
    return check_tools(extra_paths)
