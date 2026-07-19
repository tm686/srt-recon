from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Setting


async def get_setting(db: AsyncSession, key: str) -> str | None:
    result = await db.execute(select(Setting).where(Setting.key == key))
    setting = result.scalar_one_or_none()
    return setting.value if setting else None


async def set_setting(db: AsyncSession, key: str, value: str) -> None:
    result = await db.execute(select(Setting).where(Setting.key == key))
    setting = result.scalar_one_or_none()
    if setting:
        setting.value = value
    else:
        db.add(Setting(key=key, value=value))
    await db.commit()


async def get_all_settings(db: AsyncSession) -> dict[str, str]:
    result = await db.execute(select(Setting))
    return {s.key: s.value for s in result.scalars().all()}


DEFAULTS = {
    "seclists_path": "/usr/share/seclists",
    "go_tools_path": "",
    "default_threads": "10",
    "aggressiveness": "normal",  # conservative, normal, aggressive
    "wordlist_ffuf": "",  # empty = use bundled ffuf-wordlist-default-small.txt
    "setup_complete": "false",
}


async def seed_defaults(db: AsyncSession) -> None:
    for key, value in DEFAULTS.items():
        existing = await get_setting(db, key)
        if existing is None:
            await set_setting(db, key, value)
