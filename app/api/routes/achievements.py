"""Achievement catalog management; automatic award rules remain in services."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, status

from app.api.deps import AdminUser, CurrentUser, DatabaseDep
from app.core.database import ACHIEVEMENT_DEFINITIONS
from app.schemas import AchievementCreate, AchievementPublic, AchievementUpdate, Message

router = APIRouter(prefix="/achievements", tags=["achievements"])
BUILTINS = {definition[0] for definition in ACHIEVEMENT_DEFINITIONS}


def _public(row) -> AchievementPublic:
    return AchievementPublic.model_validate({**dict(row), "is_builtin": row["slug"] in BUILTINS})


@router.get("", response_model=list[AchievementPublic])
async def list_achievements(_: CurrentUser, database: DatabaseDep):
    with database.connect() as connection:
        rows = connection.execute(
            "SELECT slug, name, description, acquisition, icon FROM achievements ORDER BY created_at, slug"
        ).fetchall()
    return [_public(row) for row in rows]


@router.post("", response_model=AchievementPublic, status_code=status.HTTP_201_CREATED)
async def create_achievement(payload: AchievementCreate, _: AdminUser, database: DatabaseDep):
    try:
        with database.connect() as connection:
            connection.execute(
                "INSERT INTO achievements (slug, name, description, acquisition, icon, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (payload.slug, payload.name, payload.description, payload.acquisition, payload.icon,
                 datetime.now(UTC).isoformat()),
            )
            row = connection.execute("SELECT * FROM achievements WHERE slug = ?", (payload.slug,)).fetchone()
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="Achievement slug already exists") from exc
    return _public(row)


@router.patch("/{slug}", response_model=AchievementPublic)
async def update_achievement(slug: str, payload: AchievementUpdate, _: AdminUser, database: DatabaseDep):
    fields = payload.model_dump(exclude_unset=True, exclude_none=True)
    if not fields:
        raise HTTPException(status_code=400, detail="No changes supplied")
    with database.connect() as connection:
        updated = connection.execute(
            f"UPDATE achievements SET {', '.join(f'{key} = ?' for key in fields)} WHERE slug = ?",
            (*fields.values(), slug),
        )
        if not updated.rowcount:
            raise HTTPException(status_code=404, detail="Achievement not found")
        row = connection.execute("SELECT * FROM achievements WHERE slug = ?", (slug,)).fetchone()
    return _public(row)


@router.delete("/{slug}", response_model=Message)
async def delete_achievement(slug: str, _: AdminUser, database: DatabaseDep):
    if slug in BUILTINS:
        raise HTTPException(status_code=409, detail="Built-in achievements cannot be deleted")
    with database.connect() as connection:
        existing = connection.execute("SELECT 1 FROM achievements WHERE slug = ?", (slug,)).fetchone()
        if not existing:
            raise HTTPException(status_code=404, detail="Achievement not found")
        awarded = connection.execute(
            "SELECT 1 FROM user_achievements WHERE achievement_slug = ? LIMIT 1", (slug,)
        ).fetchone()
        if awarded:
            raise HTTPException(status_code=409, detail="Revoke this achievement from users before deleting it")
        connection.execute("DELETE FROM achievements WHERE slug = ?", (slug,))
    return Message(message="Achievement deleted")
