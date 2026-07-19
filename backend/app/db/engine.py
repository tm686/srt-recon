from sqlalchemy import text, inspect
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.config import settings

engine = create_async_engine(settings.database_url, echo=settings.debug)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def get_db():
    async with async_session() as session:
        yield session


def _migrate_columns(conn):
    """Add missing columns to existing tables (lightweight migration for dev)."""
    inspector = inspect(conn)

    # Projects table: add category and target_value if missing
    if inspector.has_table("projects"):
        columns = {col["name"] for col in inspector.get_columns("projects")}
        if "category" not in columns:
            conn.execute(text(
                "ALTER TABLE projects ADD COLUMN category VARCHAR(50) DEFAULT 'wildcard_domain' NOT NULL"
            ))
        if "target_value" not in columns:
            conn.execute(text(
                "ALTER TABLE projects ADD COLUMN target_value VARCHAR(512) DEFAULT ''"
            ))


async def init_db():
    from app.db.models import Base

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.run_sync(_migrate_columns)
