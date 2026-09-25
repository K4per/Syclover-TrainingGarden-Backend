"""Announcements and curated challenge collections."""

from __future__ import annotations

import sqlite3
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, status

from app.api.deps import AdminUser, CurrentUser, DatabaseDep
from app.schemas import (
    AnnouncementCreate, AnnouncementPublic, AnnouncementUpdate,
    CollectionCreate, CollectionPublic, CollectionUpdate, Message,
)

announcements = APIRouter(prefix="/announcements", tags=["announcements"])
collections = APIRouter(prefix="/collections", tags=["collections"])


def _announcement(connection, announcement_id: str):
    return connection.execute(
        "SELECT a.*, u.username AS author FROM announcements a "
        "LEFT JOIN users u ON u.id = a.created_by WHERE a.id = ?",
        (announcement_id,),
    ).fetchone()


@announcements.get("", response_model=list[AnnouncementPublic])
async def list_announcements(user: CurrentUser, database: DatabaseDep):
    where = "" if user["role"] in {"admin", "root_admin"} else "WHERE a.status = 'published'"
    with database.connect() as connection:
        rows = connection.execute(
            f"SELECT a.*, u.username AS author FROM announcements a "
            f"LEFT JOIN users u ON u.id = a.created_by {where} "
            "ORDER BY a.created_at DESC, a.id DESC"
        ).fetchall()
    return [AnnouncementPublic.model_validate(dict(row)) for row in rows]


@announcements.post("", response_model=AnnouncementPublic, status_code=status.HTTP_201_CREATED)
async def create_announcement(payload: AnnouncementCreate, admin: AdminUser, database: DatabaseDep):
    now = datetime.now(UTC).isoformat()
    announcement_id = str(uuid.uuid4())
    with database.connect() as connection:
        connection.execute(
            "INSERT INTO announcements (id, title, content, status, created_by, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (announcement_id, payload.title, payload.content, payload.status, admin["id"], now, now),
        )
        row = _announcement(connection, announcement_id)
    return AnnouncementPublic.model_validate(dict(row))


@announcements.patch("/{announcement_id}", response_model=AnnouncementPublic)
async def update_announcement(
    announcement_id: str, payload: AnnouncementUpdate, _: AdminUser, database: DatabaseDep
):
    fields = payload.model_dump(exclude_unset=True, exclude_none=True)
    if not fields:
        raise HTTPException(status_code=400, detail="No changes supplied")
    fields["updated_at"] = datetime.now(UTC).isoformat()
    with database.connect() as connection:
        updated = connection.execute(
            f"UPDATE announcements SET {', '.join(f'{key} = ?' for key in fields)} WHERE id = ?",
            (*fields.values(), announcement_id),
        )
        if not updated.rowcount:
            raise HTTPException(status_code=404, detail="Announcement not found")
        row = _announcement(connection, announcement_id)
    return AnnouncementPublic.model_validate(dict(row))


@announcements.delete("/{announcement_id}", response_model=Message)
async def delete_announcement(announcement_id: str, _: AdminUser, database: DatabaseDep):
    with database.connect() as connection:
        removed = connection.execute("DELETE FROM announcements WHERE id = ?", (announcement_id,))
    if not removed.rowcount:
        raise HTTPException(status_code=404, detail="Announcement not found")
    return Message(message="Announcement deleted")


def _collection(connection, row, admin: bool) -> CollectionPublic:
    condition = "" if admin else "AND c.status = 'published'"
    members = connection.execute(
        "SELECT cc.challenge_id FROM collection_challenges cc "
        "JOIN challenges c ON c.id = cc.challenge_id "
        f"WHERE cc.collection_id = ? {condition} ORDER BY cc.sort_order, cc.challenge_id",
        (row["id"],),
    ).fetchall()
    ids = [member["challenge_id"] for member in members]
    return CollectionPublic.model_validate({**dict(row), "challenge_ids": ids, "challenge_count": len(ids)})


def _set_members(connection, collection_id: str, ids: list[str]) -> None:
    if len(ids) != len(set(ids)):
        raise HTTPException(status_code=422, detail="Duplicate challenge IDs are not allowed")
    if ids:
        found = connection.execute(
            f"SELECT id FROM challenges WHERE id IN ({','.join('?' for _ in ids)})", ids
        ).fetchall()
        if len(found) != len(ids):
            raise HTTPException(status_code=422, detail="One or more challenges do not exist")
    connection.execute("DELETE FROM collection_challenges WHERE collection_id = ?", (collection_id,))
    connection.executemany(
        "INSERT INTO collection_challenges (collection_id, challenge_id, sort_order) VALUES (?, ?, ?)",
        [(collection_id, challenge_id, position) for position, challenge_id in enumerate(ids)],
    )


@collections.get("", response_model=list[CollectionPublic])
async def list_collections(user: CurrentUser, database: DatabaseDep):
    where = "" if user["role"] in {"admin", "root_admin"} else "WHERE status = 'published'"
    with database.connect() as connection:
        rows = connection.execute(
            f"SELECT * FROM collections {where} ORDER BY created_at DESC, id DESC"
        ).fetchall()
        return [_collection(connection, row, user["role"] in {"admin", "root_admin"}) for row in rows]


@collections.get("/{collection_id}", response_model=CollectionPublic)
async def get_collection(collection_id: str, user: CurrentUser, database: DatabaseDep):
    with database.connect() as connection:
        row = connection.execute("SELECT * FROM collections WHERE id = ?", (collection_id,)).fetchone()
        if not row or (row["status"] != "published" and user["role"] not in {"admin", "root_admin"}):
            raise HTTPException(status_code=404, detail="Collection not found")
        return _collection(connection, row, user["role"] in {"admin", "root_admin"})


@collections.post("", response_model=CollectionPublic, status_code=status.HTTP_201_CREATED)
async def create_collection(payload: CollectionCreate, _: AdminUser, database: DatabaseDep):
    now = datetime.now(UTC).isoformat()
    collection_id = str(uuid.uuid4())
    try:
        with database.connect() as connection:
            connection.execute(
                "INSERT INTO collections (id, title, slug, description, status, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (collection_id, payload.title, payload.slug, payload.description, payload.status, now, now),
            )
            _set_members(connection, collection_id, payload.challenge_ids)
            row = connection.execute("SELECT * FROM collections WHERE id = ?", (collection_id,)).fetchone()
            result = _collection(connection, row, True)
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="Collection slug already exists") from exc
    return result


@collections.patch("/{collection_id}", response_model=CollectionPublic)
async def update_collection(
    collection_id: str, payload: CollectionUpdate, _: AdminUser, database: DatabaseDep
):
    fields = payload.model_dump(exclude_unset=True, exclude_none=True)
    members = fields.pop("challenge_ids", None)
    if not fields and members is None:
        raise HTTPException(status_code=400, detail="No changes supplied")
    try:
        with database.connect() as connection:
            if not connection.execute("SELECT 1 FROM collections WHERE id = ?", (collection_id,)).fetchone():
                raise HTTPException(status_code=404, detail="Collection not found")
            if fields or members is not None:
                fields["updated_at"] = datetime.now(UTC).isoformat()
                connection.execute(
                    f"UPDATE collections SET {', '.join(f'{key} = ?' for key in fields)} WHERE id = ?",
                    (*fields.values(), collection_id),
                )
            if members is not None:
                _set_members(connection, collection_id, members)
            row = connection.execute("SELECT * FROM collections WHERE id = ?", (collection_id,)).fetchone()
            result = _collection(connection, row, True)
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="Collection slug already exists") from exc
    return result


@collections.delete("/{collection_id}", response_model=Message)
async def delete_collection(collection_id: str, _: AdminUser, database: DatabaseDep):
    with database.connect() as connection:
        removed = connection.execute("DELETE FROM collections WHERE id = ?", (collection_id,))
    if not removed.rowcount:
        raise HTTPException(status_code=404, detail="Collection not found")
    return Message(message="Collection deleted")
