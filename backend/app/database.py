"""Database engine, session factory, and dependency for FastAPI."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import inspect, text

from app.config import settings

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    future=True,
)

async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""
    pass


async def init_db() -> None:
    """Create all tables if they don't exist."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # This MVP has no migration framework. Add the three backwards
        # compatible optional runtime columns to databases created by older
        # versions, rather than leaving create_all's existing-table gap.
        def upgrade(sync_conn):
            columns = {col["name"] for col in inspect(sync_conn).get_columns("analyses")}
            additions = {
                "dynamic_requested": "BOOLEAN NOT NULL DEFAULT FALSE",
                "dynamic_status": "VARCHAR(24) NOT NULL DEFAULT 'NOT_REQUESTED'",
                "dynamic_error": "TEXT NULL",
            }
            for name, definition in additions.items():
                if name not in columns:
                    sync_conn.execute(text(f"ALTER TABLE analyses ADD COLUMN {name} {definition}"))
        await conn.run_sync(upgrade)


async def get_db() -> AsyncSession:  # type: ignore[misc]
    """FastAPI dependency that yields an async database session."""
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
