from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.api.deps import CurrentUser, DatabaseDep, DockerDep, RootAdminUser, SettingsDep
from app.core.security import hash_password, verify_password
from app.schemas import (
    AchievementPublic,
    Message,
    PasswordChange,
    ProfileUpdate,
    UserProfile,
    UserPublic,
    UserUpdate,
)
from app.services.achievements import grant_achievement, user_achievement_slugs, user_achievements
from app.services.docker import ContainerError

router = APIRouter(prefix="/users", tags=["users"])


def _serialize(row, connection=None) -> UserPublic:
    data = dict(row)
    data["is_active"] = bool(data["is_active"])
    if connection is not None:
        data["achievement_slugs"] = user_achievement_slugs(connection, data["id"])
    return UserPublic.model_validate(data)


def _profile(connection, user_id: str) -> UserProfile | None:
    row = connection.execute(
        "SELECT id, username, role, is_active, avatar_url, signature, direction, created_at "
        "FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
    if not row:
        return None
    stats = connection.execute(
        """
        SELECT COALESCE(SUM(CASE WHEN correct = 1 AND awarded_points > 0 THEN awarded_points ELSE 0 END), 0) AS score,
               COUNT(CASE WHEN correct = 1 AND awarded_points > 0 THEN 1 END) AS solves
        FROM submissions WHERE user_id = ?
        """,
        (user_id,),
    ).fetchone()
    rank = None
    if row["role"] == "player" and row["is_active"]:
        ranked = connection.execute(
            """
            SELECT u.id, COALESCE(SUM(CASE WHEN s.correct = 1 AND s.awarded_points > 0
                THEN s.awarded_points ELSE 0 END), 0) AS score,
                MAX(CASE WHEN s.correct = 1 AND s.awarded_points > 0 THEN s.created_at END) AS last_solve_at,
                u.created_at
            FROM users u
            LEFT JOIN submissions s ON s.user_id = u.id
            WHERE u.role = 'player' AND u.is_active = 1
            GROUP BY u.id
            ORDER BY score DESC, last_solve_at ASC, u.created_at ASC
            """
        ).fetchall()
        rank = next((index for index, item in enumerate(ranked, start=1) if item["id"] == user_id), None)
    data = dict(row)
    data["is_active"] = bool(data["is_active"])
    data["achievement_slugs"] = user_achievement_slugs(connection, user_id)
    data["score"] = int(stats["score"] or 0)
    data["solves"] = int(stats["solves"] or 0)
    data["rank"] = rank
    data["achievements"] = user_achievements(connection, user_id)
    return UserProfile.model_validate(data)


@router.get("", response_model=list[UserPublic])
async def list_users(_: RootAdminUser, database: DatabaseDep) -> list[UserPublic]:
    with database.connect() as connection:
        rows = connection.execute(
            "SELECT id, username, role, is_active, avatar_url, signature, direction, created_at "
            "FROM users ORDER BY created_at DESC"
        ).fetchall()
        return [_serialize(row, connection) for row in rows]


@router.get("/achievements/catalog", response_model=list[AchievementPublic])
async def list_achievements(_: CurrentUser, database: DatabaseDep) -> list[AchievementPublic]:
    with database.connect() as connection:
        rows = connection.execute(
            "SELECT slug, name, description, acquisition, icon FROM achievements ORDER BY created_at, slug"
        ).fetchall()
    return [AchievementPublic.model_validate(dict(row)) for row in rows]


@router.get("/me/profile", response_model=UserProfile)
async def my_profile(user: CurrentUser, database: DatabaseDep) -> UserProfile:
    with database.connect() as connection:
        profile = _profile(connection, user["id"])
    if profile is None:
        raise HTTPException(status_code=404, detail="User not found")
    return profile


@router.patch("/me/profile", response_model=UserProfile)
async def update_profile(
    payload: ProfileUpdate,
    user: CurrentUser,
    database: DatabaseDep,
) -> UserProfile:
    fields = payload.model_dump(exclude_unset=True)
    if not fields:
        raise HTTPException(status_code=400, detail="No changes supplied")
    assignments = ", ".join(f"{key} = ?" for key in fields)
    with database.connect() as connection:
        connection.execute(
            f"UPDATE users SET {assignments} WHERE id = ?",
            (*fields.values(), user["id"]),
        )
        profile = _profile(connection, user["id"])
    if profile is None:
        raise HTTPException(status_code=404, detail="User not found")
    return profile


@router.post("/me/password", response_model=Message)
async def change_password(
    payload: PasswordChange,
    user: CurrentUser,
    database: DatabaseDep,
) -> Message:
    with database.connect() as connection:
        row = connection.execute("SELECT password_hash FROM users WHERE id = ?", (user["id"],)).fetchone()
        if not row or not verify_password(payload.current_password, row["password_hash"]):
            raise HTTPException(status_code=400, detail="Current password is incorrect")
        if payload.current_password == payload.new_password:
            raise HTTPException(status_code=400, detail="New password must be different")
        connection.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (hash_password(payload.new_password), user["id"]),
        )
    return Message(message="Password updated")


@router.patch("/{user_id}", response_model=UserPublic)
async def update_user(user_id: str, payload: UserUpdate, admin: RootAdminUser, database: DatabaseDep) -> UserPublic:
    if admin["id"] == user_id and payload.is_active is False:
        raise HTTPException(status_code=400, detail="You cannot disable your own account")
    fields = payload.model_dump(exclude_unset=True)
    if not fields:
        raise HTTPException(status_code=400, detail="No changes supplied")
    assignments = ", ".join(f"{key} = ?" for key in fields)
    values = [int(value) if isinstance(value, bool) else value for value in fields.values()]
    with database.connect() as connection:
        target = connection.execute("SELECT role FROM users WHERE id = ?", (user_id,)).fetchone()
        if target and target["role"] == "root_admin":
            raise HTTPException(status_code=400, detail="Root administrator accounts are fixed")
        cursor = connection.execute(
            f"UPDATE users SET {assignments} WHERE id = ?", (*values, user_id)
        )
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="User not found")
        row = connection.execute(
            "SELECT id, username, role, is_active, avatar_url, signature, direction, created_at "
            "FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        return _serialize(row, connection)


@router.post("/{user_id}/achievements/{achievement_slug}", response_model=AchievementPublic)
async def grant_user_achievement(
    user_id: str,
    achievement_slug: str,
    admin: RootAdminUser,
    database: DatabaseDep,
) -> AchievementPublic:
    with database.connect() as connection:
        if not connection.execute("SELECT 1 FROM users WHERE id = ?", (user_id,)).fetchone():
            raise HTTPException(status_code=404, detail="User not found")
        achievement = connection.execute(
            "SELECT slug, name, description, acquisition, icon FROM achievements WHERE slug = ?",
            (achievement_slug,),
        ).fetchone()
        if not achievement:
            raise HTTPException(status_code=404, detail="Achievement not found")
        grant_achievement(connection, user_id, achievement_slug, admin["id"])
        awarded = connection.execute(
            "SELECT a.slug, a.name, a.description, a.acquisition, a.icon, ua.awarded_at "
            "FROM achievements a JOIN user_achievements ua ON ua.achievement_slug = a.slug "
            "WHERE ua.user_id = ? AND a.slug = ?",
            (user_id, achievement_slug),
        ).fetchone()
    return AchievementPublic.model_validate(dict(awarded))


@router.get("/{user_id}/profile", response_model=UserProfile)
async def user_profile(user_id: str, _: CurrentUser, database: DatabaseDep) -> UserProfile:
    with database.connect() as connection:
        profile = _profile(connection, user_id)
    if profile is None:
        raise HTTPException(status_code=404, detail="User not found")
    return profile


@router.delete("/{user_id}/achievements/{achievement_slug}", response_model=Message)
async def revoke_user_achievement(
    user_id: str, achievement_slug: str, _: RootAdminUser, database: DatabaseDep
) -> Message:
    # Progress badges would be recreated by the next solve or startup backfill.
    with database.connect() as connection:
        achievement = connection.execute(
            "SELECT 1 FROM achievements WHERE slug = ?", (achievement_slug,)
        ).fetchone()
        if not achievement:
            raise HTTPException(status_code=404, detail="Achievement not found")
        if achievement_slug not in {"core_member", "peak_geek_2025"}:
            from app.core.database import ACHIEVEMENT_DEFINITIONS
            if achievement_slug in {item[0] for item in ACHIEVEMENT_DEFINITIONS}:
                raise HTTPException(status_code=409, detail="Automatic achievements cannot be revoked")
        removed = connection.execute(
            "DELETE FROM user_achievements WHERE user_id = ? AND achievement_slug = ?",
            (user_id, achievement_slug),
        )
        if not removed.rowcount:
            raise HTTPException(status_code=404, detail="User achievement not found")
        if achievement_slug == "core_member":
            grant_achievement(connection, user_id, "sprout_member")
    return Message(message="Achievement revoked")


@router.delete("/{user_id}", response_model=Message)
async def delete_user(
    user_id: str,
    admin: RootAdminUser,
    database: DatabaseDep,
    settings: SettingsDep,
    docker: DockerDep,
) -> Message:
    if admin["id"] == user_id:
        raise HTTPException(status_code=400, detail="You cannot delete your own account")
    with database.connect() as connection:
        user = connection.execute("SELECT id FROM users WHERE id = ?", (user_id,)).fetchone()
        instances = connection.execute(
            "SELECT container_id FROM instances WHERE user_id = ? AND status IN ('starting', 'running')",
            (user_id,),
        ).fetchall()
        assets = connection.execute(
            "SELECT stored_name FROM assets WHERE user_id = ? AND kind = 'patch'", (user_id,)
        ).fetchall()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    for instance in instances:
        if instance["container_id"]:
            try:
                docker.stop(instance["container_id"])
            except ContainerError:
                pass
    with database.connect() as connection:
        connection.execute("DELETE FROM defense_solves WHERE user_id = ?", (user_id,))
        connection.execute(
            "DELETE FROM deployment_events WHERE user_id = ? OR instance_id IN "
            "(SELECT id FROM instances WHERE user_id = ?) OR asset_id IN "
            "(SELECT id FROM assets WHERE user_id = ? AND kind = 'patch')",
            (user_id, user_id, user_id),
        )
        connection.execute("DELETE FROM submissions WHERE user_id = ?", (user_id,))
        connection.execute("DELETE FROM instances WHERE user_id = ?", (user_id,))
        connection.execute(
            "UPDATE assets SET user_id = NULL WHERE user_id = ? "
            "AND kind IN ('check_script', 'fix_script')",
            (user_id,),
        )
        connection.execute("DELETE FROM assets WHERE user_id = ?", (user_id,))
        connection.execute("DELETE FROM users WHERE id = ?", (user_id,))
    for asset in assets:
        (settings.storage_path / asset["stored_name"]).unlink(missing_ok=True)
    return Message(message="User deleted")
