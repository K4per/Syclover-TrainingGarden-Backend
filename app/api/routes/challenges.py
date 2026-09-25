from __future__ import annotations

import asyncio
import json
import logging
import re
import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi import APIRouter, HTTPException, Query, Request, Response, status
from fastapi.responses import StreamingResponse

from app.api.deps import AdminUser, CurrentUser, DatabaseDep, DockerDep, SettingsDep
from app.core.security import digest_flag
from app.schemas import (
    AssetPublic,
    BuildProgress,
    BuildResult,
    ChallengeCreate,
    ChallengePublic,
    ChallengeUpdate,
    HintCreate,
    HintPublic,
    HintUpdate,
    Message,
    SubmissionRequest,
    SubmissionResult,
    TagCreate,
    TagPublic,
    TagUpdate,
    category_is_valid,
)
from app.services.assets import (
    detect_exposed_port,
    extract_build_archive,
    safe_filename,
    store_bytes,
)
from app.services.achievements import maybe_grant_peak_geek_2025, sync_progress_achievements
from app.services.build_log import IDLE_LIMIT_SECONDS, POLL_SECONDS, registry
from app.services.docker import ContainerError
from app.services.flags import (
    dynamic_flag_for_template,
    normalize_template,
    template_wants_random,
)
from app.services.tags import (
    STATE_TAGS,
    set_challenge_tags,
    slugify_tag,
    state_tag_for,
    tags_for_challenge,
)

router = APIRouter(prefix="/challenges", tags=["challenges"])
logger = logging.getLogger("syclover.challenges")


def _asset(row) -> AssetPublic:
    data = dict(row)
    data["download_url"] = f"/api/v1/challenges/assets/{data['id']}/download"
    return AssetPublic.model_validate(data)


def _challenge_stats(connection, challenge_id: str, mode: str) -> dict:
    attack_rows = connection.execute(
        """
        SELECT u.id AS user_id, u.username, MIN(s.created_at) AS solved_at
        FROM submissions s JOIN users u ON u.id = s.user_id
        WHERE s.challenge_id = ? AND s.correct = 1 AND s.awarded_points > 0
          AND u.role = 'player'
        GROUP BY u.id, u.username ORDER BY solved_at ASC, u.username ASC
        """,
        (challenge_id,),
    ).fetchall()
    attack_bloods = [
        {"rank": index, **dict(row)} for index, row in enumerate(attack_rows[:3], start=1)
    ]
    defense_rows = []
    if mode == "awdp":
        defense_rows = connection.execute(
            """
            SELECT u.id AS user_id, u.username, ds.created_at AS solved_at
            FROM defense_solves ds JOIN users u ON u.id = ds.user_id
            WHERE ds.challenge_id = ? AND u.role = 'player'
            ORDER BY ds.created_at ASC, u.username ASC
            """,
            (challenge_id,),
        ).fetchall()
    defense_bloods = [
        {"rank": index, **dict(row)} for index, row in enumerate(defense_rows[:3], start=1)
    ]
    return {
        "solves": len(attack_rows),
        "bloods": attack_bloods,
        "attack_solves": len(attack_rows),
        "attack_bloods": attack_bloods,
        "defense_solves": len(defense_rows),
        "defense_bloods": defense_bloods,
    }


def _challenge(
    row,
    solved: bool = False,
    attachments: list | None = None,
    stats: dict | None = None,
    reveal_template: bool = False,
    tags: list[str] | None = None,
) -> ChallengePublic:
    data = {
        **dict(row),
        "solved": solved,
        "attachments": attachments or [],
        "tags": tags or [],
        **(stats or {}),
    }
    template = data.get("flag_template")
    if not reveal_template and template_wants_random(template):
        # A per-instance template is no use to players and should not be advertised.
        data["flag_template"] = None
    data["dynamic_flag"] = bool(data.get("dynamic_flag"))
    return ChallengePublic.model_validate(data)


def _tags_of(rows, connection) -> dict[str, list[str]]:
    """Resolve topic tags for many challenges in one query, then append state tags."""
    if not rows:
        return {}
    ids = [row["id"] for row in rows]
    placeholders = ", ".join("?" for _ in ids)
    collected: dict[str, list[str]] = {challenge_id: [] for challenge_id in ids}
    for row in connection.execute(
        f"""
        SELECT ct.challenge_id, t.name FROM challenge_tags ct JOIN tags t ON t.id = ct.tag_id
        WHERE ct.challenge_id IN ({placeholders}) ORDER BY t.sort_order, t.name
        """,
        tuple(ids),
    ).fetchall():
        collected[row["challenge_id"]].append(row["name"])
    for row in rows:
        collected[row["id"]].append(state_tag_for(row["docker_image"], row["internal_port"]))
    return collected


@router.get("", response_model=list[ChallengePublic])
async def list_challenges(
    user: CurrentUser,
    database: DatabaseDep,
    mode: str | None = Query(default=None, pattern="^(ctf|awdp)$"),
    tag: str | None = Query(default=None, max_length=32),
) -> list[ChallengePublic]:
    conditions = [] if user["role"] in {"admin", "root_admin"} else ["c.status = 'published'"]
    values: list[str] = []
    if mode:
        conditions.append("c.mode = ?")
        values.append(mode)
    if tag:
        wanted = slugify_tag(tag)
        if wanted in STATE_TAGS:
            conditions.append(
                "(c.docker_image IS NOT NULL AND c.internal_port IS NOT NULL)"
                if wanted == "dynamic"
                else "(c.docker_image IS NULL OR c.internal_port IS NULL)"
            )
        else:
            conditions.append(
                "EXISTS(SELECT 1 FROM challenge_tags ct JOIN tags t ON t.id = ct.tag_id "
                "WHERE ct.challenge_id = c.id AND t.name = ?)"
            )
            values.append(wanted)
    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    with database.connect() as connection:
        rows = connection.execute(
            f"""
            SELECT c.*,
                   EXISTS(
                       SELECT 1 FROM submissions s
                       WHERE s.challenge_id = c.id AND s.user_id = ? AND s.correct = 1
                   ) AS solved,
                   EXISTS(
                       SELECT 1 FROM assets a WHERE a.challenge_id = c.id
                       AND a.kind = 'check_script' AND a.validation_status = 'valid'
                   ) AS check_script_configured,
                   EXISTS(
                       SELECT 1 FROM assets a WHERE a.challenge_id = c.id
                       AND a.kind = 'fix_script' AND a.validation_status = 'valid'
                   ) AS fix_script_configured
            FROM challenges c {where}
            ORDER BY CASE c.difficulty
                WHEN 'noob' THEN 1 WHEN 'easy' THEN 2 WHEN 'normal' THEN 3
                WHEN 'hard' THEN 4 ELSE 5 END, c.title
            """,
            (user["id"], *values),
        ).fetchall()
        tag_map = _tags_of(rows, connection)
        results = [
            _challenge(
                row,
                bool(row["solved"]),
                stats=_challenge_stats(connection, row["id"], row["mode"]),
                reveal_template=user["role"] in {"admin", "root_admin"},
                tags=tag_map.get(row["id"], []),
            )
            for row in rows
        ]
    return results


@router.get("/{challenge_id}", response_model=ChallengePublic)
async def get_challenge(challenge_id: str, user: CurrentUser, database: DatabaseDep) -> ChallengePublic:
    with database.connect() as connection:
        row = connection.execute(
            """
            SELECT c.*,
                   EXISTS(SELECT 1 FROM assets a WHERE a.challenge_id = c.id
                          AND a.kind = 'check_script' AND a.validation_status = 'valid')
                       AS check_script_configured,
                   EXISTS(SELECT 1 FROM assets a WHERE a.challenge_id = c.id
                          AND a.kind = 'fix_script' AND a.validation_status = 'valid')
                       AS fix_script_configured
            FROM challenges c WHERE c.id = ?
            """,
            (challenge_id,),
        ).fetchone()
        if not row or (row["status"] != "published" and user["role"] not in {"admin", "root_admin"}):
            raise HTTPException(status_code=404, detail="Challenge not found")
        solved = connection.execute(
            "SELECT 1 FROM submissions WHERE challenge_id = ? AND user_id = ? AND correct = 1",
            (challenge_id, user["id"]),
        ).fetchone()
        assets = connection.execute(
            "SELECT * FROM assets WHERE challenge_id = ? AND kind = 'attachment' ORDER BY created_at",
            (challenge_id,),
        ).fetchall()
        stats = _challenge_stats(connection, challenge_id, row["mode"])
        tags = tags_for_challenge(connection, challenge_id, row["docker_image"], row["internal_port"])
    return _challenge(
        row,
        bool(solved),
        [_asset(asset) for asset in assets],
        stats,
        reveal_template=user["role"] in {"admin", "root_admin"},
        tags=tags,
    )


@router.post("/{challenge_id}/submit", response_model=SubmissionResult)
async def submit_flag(
    challenge_id: str,
    payload: SubmissionRequest,
    user: CurrentUser,
    database: DatabaseDep,
    settings: SettingsDep,
) -> SubmissionResult:
    with database.connect() as connection:
        challenge = connection.execute(
            "SELECT id, points, flag_digest, status FROM challenges WHERE id = ?", (challenge_id,)
        ).fetchone()
        if not challenge or (challenge["status"] != "published" and user["role"] not in {"admin", "root_admin"}):
            raise HTTPException(status_code=404, detail="Challenge not found")
        active_instance = connection.execute(
            "SELECT id, instance_flag FROM instances WHERE user_id = ? AND challenge_id = ? "
            "AND status IN ('starting', 'running') ORDER BY created_at DESC LIMIT 1",
            (user["id"], challenge_id),
        ).fetchone()
        correct = (
            digest_flag(payload.flag, settings.secret_key) == challenge["flag_digest"]
            or (
                active_instance is not None
                and active_instance["instance_flag"] is not None
                and payload.flag.strip() == active_instance["instance_flag"]
            )
        )
        previous = connection.execute(
            "SELECT 1 FROM submissions WHERE user_id = ? AND challenge_id = ? AND correct = 1",
            (user["id"], challenge_id),
        ).fetchone()
        awarded = challenge["points"] if correct and not previous else 0
        connection.execute(
            "INSERT INTO submissions (id, user_id, challenge_id, correct, awarded_points, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                str(uuid.uuid4()),
                user["id"],
                challenge_id,
                int(correct),
                awarded,
                datetime.now(UTC).isoformat(),
            ),
        )
        if correct:
            sync_progress_achievements(connection, user["id"])
            maybe_grant_peak_geek_2025(connection, user["id"])
    if not correct:
        return SubmissionResult(correct=False, awarded_points=0, message="Flag is incorrect")
    if awarded == 0:
        return SubmissionResult(correct=True, awarded_points=0, message="Challenge was already solved")
    return SubmissionResult(correct=True, awarded_points=awarded, message="Correct flag")


@router.post("/{challenge_id}/build", response_model=BuildResult)
async def build_challenge_image(
    challenge_id: str,
    request: Request,
    _: AdminUser,
    database: DatabaseDep,
    settings: SettingsDep,
    docker: DockerDep,
    filename: str = Query(min_length=1, max_length=120),
) -> BuildResult:
    if not filename.lower().endswith(".zip"):
        raise HTTPException(status_code=422, detail="Build file must be a ZIP archive")
    content = await request.body()
    if not content or len(content) > settings.max_build_upload_bytes:
        raise HTTPException(status_code=413, detail="Build archive is empty or exceeds the upload limit")
    with database.connect() as connection:
        challenge = connection.execute(
            "SELECT id, slug, internal_port FROM challenges WHERE id = ?", (challenge_id,)
        ).fetchone()
    if not challenge:
        raise HTTPException(status_code=404, detail="Challenge not found")

    stored_name, archive_path = store_bytes(settings.storage_path, challenge_id, filename, content)
    asset_id = str(uuid.uuid4())
    now = datetime.now(UTC).isoformat()
    with database.connect() as connection:
        connection.execute(
            """
            INSERT INTO assets (
                id, challenge_id, user_id, kind, original_name, stored_name, size_bytes,
                validation_status, validation_output, created_at
            ) VALUES (?, ?, NULL, 'build_archive', ?, ?, ?, 'pending', 'Build queued.', ?)
            """,
            (asset_id, challenge_id, safe_filename(filename), stored_name, len(content), now),
        )
        connection.execute(
            "UPDATE challenges SET build_status = 'building', build_output = 'Build started.', updated_at = ? "
            "WHERE id = ?",
            (now, challenge_id),
        )

    image = f"syclover/training-garden-{challenge['slug']}:alpha0.0.3-hotfix.2"
    registry.start(challenge_id)
    registry.append(
        challenge_id,
        f"$ docker build --tag {image} {safe_filename(filename)}\n",
    )
    try:
        with TemporaryDirectory(prefix="syclover-build-") as temporary:
            registry.append(challenge_id, "· 正在安全解包构建包\n")
            context = extract_build_archive(archive_path, Path(temporary))
            detected_port = detect_exposed_port(context)
            registry.append(
                challenge_id,
                f"· 构建上下文已就绪，自动识别端口 {detected_port or '未识别'}\n",
            )
            output = await docker.build(
                context=context,
                image=image,
                on_output=lambda chunk: registry.append(challenge_id, chunk),
            )
    except ValueError as exc:
        output = str(exc)
        registry.finish(challenge_id, "failed", output)
        with database.connect() as connection:
            connection.execute(
                "UPDATE assets SET validation_status = 'invalid', validation_output = ? WHERE id = ?",
                (output, asset_id),
            )
            connection.execute(
                "UPDATE challenges SET build_status = 'failed', build_output = ?, updated_at = ? WHERE id = ?",
                (output, datetime.now(UTC).isoformat(), challenge_id),
            )
        raise HTTPException(status_code=422, detail=output) from exc
    except ContainerError as exc:
        output = str(exc)
        registry.finish(challenge_id, "failed", output)
        with database.connect() as connection:
            connection.execute(
                "UPDATE assets SET validation_status = 'invalid', validation_output = ? WHERE id = ?",
                (output[:20_000], asset_id),
            )
            connection.execute(
                "UPDATE challenges SET build_status = 'failed', build_output = ?, updated_at = ? WHERE id = ?",
                (output[:20_000], datetime.now(UTC).isoformat(), challenge_id),
            )
        raise HTTPException(status_code=503, detail=f"Image build failed: {output[-4_000:]}") from exc

    internal_port = challenge["internal_port"] or detected_port
    port_warning = None
    configured_port = challenge["internal_port"]
    if configured_port and detected_port and configured_port != detected_port:
        port_warning = (
            f"题目填写的容器端口是 {configured_port}，但 Dockerfile 的 EXPOSE 是 {detected_port}。"
            f"若两者不一致，宿主机映射到 {configured_port} 上不会有人监听，选手连接会被拒绝。"
            "请确认服务真实监听的端口后改成正确值。"
        )
    summary = output or "Image built successfully."
    if port_warning:
        summary = f"{summary}\n\n[端口校验警告] {port_warning}"
    registry.finish(challenge_id, "success", summary)
    with database.connect() as connection:
        connection.execute(
            "UPDATE assets SET validation_status = 'valid', validation_output = ? WHERE id = ?",
            ((output or "Image built successfully.")[:20_000], asset_id),
        )
        connection.execute(
            "UPDATE challenges SET docker_image = ?, internal_port = ?, detected_port = ?, "
            "build_status = 'success', build_output = ?, updated_at = ? WHERE id = ?",
            (
                image,
                internal_port,
                detected_port,
                summary[:20_000],
                datetime.now(UTC).isoformat(),
                challenge_id,
            ),
        )
    return BuildResult(
        challenge_id=challenge_id,
        image=image,
        status="success",
        output=summary[-20_000:],
        internal_port=internal_port,
        detected_port=detected_port,
        port_warning=port_warning,
    )


@router.get("/{challenge_id}/build/progress", response_model=BuildProgress)
async def build_progress(
    challenge_id: str,
    _: AdminUser,
    database: DatabaseDep,
    cursor: int = Query(default=0, ge=0),
) -> BuildProgress:
    """Incremental build log for the admin console.

    The client asks for everything after ``cursor`` and appends the returned ``data``
    to its log pane, which keeps polling cheap for long builds.
    """
    with database.connect() as connection:
        stored = connection.execute(
            "SELECT build_status, build_output FROM challenges WHERE id = ?", (challenge_id,)
        ).fetchone()
    if not stored:
        raise HTTPException(status_code=404, detail="Challenge not found")

    record = registry.snapshot(challenge_id)
    if record is None:
        # No live build: hand back the persisted log once, then report the stored state.
        text = stored["build_output"] or ""
        chunk = text[cursor:]
        return BuildProgress(
            challenge_id=challenge_id,
            status=stored["build_status"],
            data=chunk,
            cursor=len(text),
            finished=True,
            percent=100 if stored["build_status"] == "success" else 0,
        )

    text = record.log
    chunk = text[cursor:] if cursor <= len(text) else text
    next_cursor = len(text) if cursor <= len(text) else len(text)
    percent = _build_percent(text, record.status)
    warning = _port_warning_from(text)
    return BuildProgress(
        challenge_id=challenge_id,
        status=record.status,
        data=chunk,
        cursor=next_cursor,
        finished=record.finished,
        truncated=record.truncated,
        percent=percent,
        port_warning=warning,
    )


def _build_percent(text: str, status: str) -> int:
    """Estimate progress from docker's ``Step X/Y`` markers."""
    if status == "success":
        return 100
    steps = re.findall(r"Step (\d+)/(\d+)", text)
    if steps:
        current, total = (int(value) for value in steps[-1])
        if total:
            return min(96, max(5, int(current * 100 / total)))
    if status == "failed":
        return 100
    return 5


def _port_warning_from(text: str) -> str | None:
    marker = "[端口校验警告] "
    index = text.find(marker)
    if index < 0:
        return None
    return text[index + len(marker) :].splitlines()[0].strip() or None


def _sse(payload: dict) -> str:
    return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"


@router.get("/tags/catalog", response_model=list[TagPublic])
async def tag_catalog(user: CurrentUser, database: DatabaseDep) -> list[TagPublic]:
    """Every tag, including the derived static/dynamic states and their usage counts."""
    is_admin = user["role"] in {"admin", "root_admin"}
    visibility = "" if is_admin else "AND c.status = 'published'"
    topic_visibility = "" if is_admin else (
        "WHERE EXISTS (SELECT 1 FROM challenge_tags visible "
        "JOIN challenges c ON c.id = visible.challenge_id "
        "WHERE visible.tag_id = t.id AND c.status = 'published')"
    )
    with database.connect() as connection:
        rows = connection.execute(
            f"SELECT t.id, t.name, t.kind, t.description, t.sort_order, "
            f"(SELECT COUNT(*) FROM challenge_tags ct JOIN challenges c ON c.id = ct.challenge_id "
            f"WHERE ct.tag_id = t.id {visibility}) AS challenge_count "
            f"FROM tags t {topic_visibility} ORDER BY t.sort_order, t.name"
        ).fetchall()
        dynamic_count = connection.execute(
            "SELECT COUNT(*) AS total FROM challenges c "
            f"WHERE docker_image IS NOT NULL AND internal_port IS NOT NULL {visibility}"
        ).fetchone()["total"]
        static_count = connection.execute(
            "SELECT COUNT(*) AS total FROM challenges c "
            f"WHERE (docker_image IS NULL OR internal_port IS NULL) {visibility}"
        ).fetchone()["total"]
    catalog = [TagPublic.model_validate(dict(row)) for row in rows]
    catalog.append(
        TagPublic(
            id="state:dynamic",
            name="dynamic",
            kind="state",
            description="动态题目：启动独立 Docker 实例",
            challenge_count=dynamic_count,
            sort_order=10000,
        )
    )
    catalog.append(
        TagPublic(
            id="state:static",
            name="static",
            kind="state",
            description="静态题目：仅附件与描述",
            challenge_count=static_count,
            sort_order=10000,
        )
    )
    return catalog


@router.post("/tags", response_model=TagPublic, status_code=status.HTTP_201_CREATED)
async def create_tag(payload: TagCreate, _: AdminUser, database: DatabaseDep) -> TagPublic:
    """Create a topic tag up front so it can be attached to challenges afterwards."""
    name = slugify_tag(payload.name)
    if not name:
        raise HTTPException(status_code=422, detail="Tag name is empty after normalization")
    if name in STATE_TAGS:
        raise HTTPException(
            status_code=422, detail="static/dynamic are reserved tag names"
        )
    tag_id = str(uuid.uuid4())
    try:
        with database.connect() as connection:
            connection.execute(
                "INSERT INTO tags (id, name, kind, description, sort_order, created_at) "
                "VALUES (?, ?, 'topic', ?, ?, ?)",
                (tag_id, name, payload.description, payload.sort_order, datetime.now(UTC).isoformat()),
            )
            row = connection.execute(
                """
                SELECT t.id, t.name, t.kind, t.description, t.sort_order,
                       (SELECT COUNT(*) FROM challenge_tags ct WHERE ct.tag_id = t.id) AS challenge_count
                FROM tags t WHERE t.id = ?
                """,
                (tag_id,),
            ).fetchone()
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="A tag with that name already exists") from exc
    return TagPublic.model_validate(dict(row))


@router.patch("/tags/{tag_id}", response_model=TagPublic)
async def rename_tag(
    tag_id: str, payload: TagUpdate, _: AdminUser, database: DatabaseDep
) -> TagPublic:
    """Rename or re-describe a topic tag; state tags are derived and cannot be edited."""
    if tag_id.startswith("state:"):
        raise HTTPException(
            status_code=422, detail="static/dynamic tags are derived from the challenge environment"
        )
    fields = payload.model_dump(exclude_unset=True, exclude_none=True)
    if not fields:
        raise HTTPException(status_code=400, detail="No changes supplied")
    if "name" in fields:
        fields["name"] = slugify_tag(fields["name"])
        if not fields["name"]:
            raise HTTPException(status_code=422, detail="Tag name is empty after normalization")
        if fields["name"] in STATE_TAGS:
            raise HTTPException(status_code=422, detail="static/dynamic are reserved tag names")
    assignments = ", ".join(f"{key} = ?" for key in fields)
    try:
        with database.connect() as connection:
            cursor = connection.execute(
                f"UPDATE tags SET {assignments} WHERE id = ?", (*fields.values(), tag_id)
            )
            if cursor.rowcount == 0:
                raise HTTPException(status_code=404, detail="Tag not found")
            row = connection.execute(
                """
                SELECT t.id, t.name, t.kind, t.description, t.sort_order,
                       (SELECT COUNT(*) FROM challenge_tags ct WHERE ct.tag_id = t.id) AS challenge_count
                FROM tags t WHERE t.id = ?
                """,
                (tag_id,),
            ).fetchone()
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="A tag with that name already exists") from exc
    return TagPublic.model_validate(dict(row))


@router.delete("/tags/{tag_id}", response_model=Message)
async def delete_tag(tag_id: str, _: AdminUser, database: DatabaseDep) -> Message:
    if tag_id.startswith("state:"):
        raise HTTPException(
            status_code=422, detail="static/dynamic tags are derived from the challenge environment"
        )
    with database.connect() as connection:
        connection.execute("DELETE FROM challenge_tags WHERE tag_id = ?", (tag_id,))
        cursor = connection.execute("DELETE FROM tags WHERE id = ?", (tag_id,))
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Tag not found")
    return Message(message="Tag deleted")


@router.post("", response_model=ChallengePublic, status_code=status.HTTP_201_CREATED)
async def create_challenge(
    payload: ChallengeCreate, _: AdminUser, database: DatabaseDep, settings: SettingsDep
) -> ChallengePublic:
    if payload.mode == "awdp" and payload.status == "published":
        raise HTTPException(
            status_code=422,
            detail="Create AWDP challenges offline, upload Check and Fix scripts, then publish them",
        )
    challenge_id = str(uuid.uuid4())
    now = datetime.now(UTC).isoformat()
    data = payload.model_dump(exclude={"flag", "tags", "dynamic_flag"})
    requested_tags = list(payload.tags)
    # The legacy <RANDOM> token must be detected on the raw input: normalisation rewrites
    # it to RAND, which is otherwise a plain literal.
    dynamic_flag = dynamic_flag_for_template(payload.flag, payload.dynamic_flag)
    flag_template = normalize_template(payload.flag, settings.flag_prefix)
    try:
        with database.connect() as connection:
            connection.execute(
                """
                INSERT INTO challenges (
                    id, title, slug, description, category, mode, difficulty, points,
                    docker_image, internal_port, flag_template, dynamic_flag, flag_digest,
                    status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    challenge_id,
                    data["title"],
                    data["slug"],
                    data["description"],
                    data["category"],
                    data["mode"],
                    data["difficulty"],
                    data["points"],
                    data["docker_image"],
                    data["internal_port"],
                    flag_template,
                    int(dynamic_flag),
                    digest_flag(payload.flag, settings.secret_key),
                    data["status"],
                    now,
                    now,
                ),
            )
            row = connection.execute(
                """
                SELECT c.*,
                       EXISTS(SELECT 1 FROM assets a WHERE a.challenge_id = c.id
                              AND a.kind = 'check_script' AND a.validation_status = 'valid')
                           AS check_script_configured,
                       EXISTS(SELECT 1 FROM assets a WHERE a.challenge_id = c.id
                              AND a.kind = 'fix_script' AND a.validation_status = 'valid')
                           AS fix_script_configured
                FROM challenges c WHERE c.id = ?
                """,
                (challenge_id,),
            ).fetchone()
            tags = set_challenge_tags(connection, challenge_id, requested_tags)
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="Challenge slug already exists") from exc
    return _challenge(row, reveal_template=True, tags=tags)


@router.patch("/{challenge_id}", response_model=ChallengePublic)
async def update_challenge(
    challenge_id: str,
    payload: ChallengeUpdate,
    _: AdminUser,
    database: DatabaseDep,
    settings: SettingsDep,
) -> ChallengePublic:
    fields = payload.model_dump(exclude_unset=True)
    flag = fields.pop("flag", None)
    new_tags = fields.pop("tags", None)
    requested_dynamic = fields.pop("dynamic_flag", None)
    if flag:
        fields["flag_digest"] = digest_flag(flag, settings.secret_key)
        fields["flag_template"] = normalize_template(flag, settings.flag_prefix)
        fields["dynamic_flag"] = int(
            dynamic_flag_for_template(flag, True)
            if requested_dynamic is None
            else dynamic_flag_for_template(flag, requested_dynamic)
        )
    elif requested_dynamic is not None:
        # Toggling the switch alone keeps the stored flag text as the template.
        fields["dynamic_flag"] = int(requested_dynamic)
    try:
        with database.connect() as connection:
            existing = connection.execute(
                "SELECT * FROM challenges WHERE id = ?", (challenge_id,)
            ).fetchone()
            if not existing:
                raise HTTPException(status_code=404, detail="Challenge not found")
            resulting_mode = fields.get("mode", existing["mode"])
            resulting_category = fields.get("category", existing["category"])
            if not category_is_valid(resulting_mode, resulting_category):
                raise HTTPException(
                    status_code=422,
                    detail=f"{resulting_category} is not valid for {resulting_mode.upper()}",
                )
            resulting_status = fields.get("status", existing["status"])
            if resulting_mode == "awdp" and resulting_status == "published":
                script_kinds = {
                    row["kind"]
                    for row in connection.execute(
                        "SELECT DISTINCT kind FROM assets WHERE challenge_id = ? "
                        "AND kind IN ('check_script', 'fix_script') AND validation_status = 'valid'",
                        (challenge_id,),
                    ).fetchall()
                }
                missing = {"check_script", "fix_script"} - script_kinds
                if missing:
                    names = ", ".join(sorted(kind.replace("_script", "").title() for kind in missing))
                    raise HTTPException(
                        status_code=422,
                        detail=f"Upload valid {names} scripts before publishing this AWDP challenge",
                    )
            fields["updated_at"] = datetime.now(UTC).isoformat()
            assignments = ", ".join(f"{key} = ?" for key in fields)
            cursor = connection.execute(
                f"UPDATE challenges SET {assignments} WHERE id = ?", (*fields.values(), challenge_id)
            )
            row = connection.execute(
                """
                SELECT c.*,
                       EXISTS(SELECT 1 FROM assets a WHERE a.challenge_id = c.id
                              AND a.kind = 'check_script' AND a.validation_status = 'valid')
                           AS check_script_configured,
                       EXISTS(SELECT 1 FROM assets a WHERE a.challenge_id = c.id
                              AND a.kind = 'fix_script' AND a.validation_status = 'valid')
                           AS fix_script_configured
                FROM challenges c WHERE c.id = ?
                """,
                (challenge_id,),
            ).fetchone()
            if new_tags is None:
                tags = tags_for_challenge(
                    connection, challenge_id, row["docker_image"], row["internal_port"]
                )
            else:
                tags = set_challenge_tags(connection, challenge_id, new_tags)
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="Challenge update conflicts with existing data") from exc
    return _challenge(row, reveal_template=True, tags=tags)


@router.delete("/{challenge_id}", response_model=Message)
async def delete_challenge(
    challenge_id: str,
    _: AdminUser,
    database: DatabaseDep,
    settings: SettingsDep,
    docker: DockerDep,
) -> Message:
    with database.connect() as connection:
        challenge = connection.execute(
            "SELECT id, docker_image FROM challenges WHERE id = ?", (challenge_id,)
        ).fetchone()
        instances = connection.execute(
            "SELECT container_id FROM instances WHERE challenge_id = ? AND status IN ('starting', 'running')",
            (challenge_id,),
        ).fetchall()
        assets = connection.execute(
            "SELECT stored_name FROM assets WHERE challenge_id = ?", (challenge_id,)
        ).fetchall()
    if not challenge:
        raise HTTPException(status_code=404, detail="Challenge not found")
    for instance in instances:
        if instance["container_id"]:
            try:
                docker.stop(instance["container_id"])
            except ContainerError:
                pass
    with database.connect() as connection:
        connection.execute("DELETE FROM defense_solves WHERE challenge_id = ?", (challenge_id,))
        connection.execute(
            "DELETE FROM deployment_events WHERE instance_id IN "
            "(SELECT id FROM instances WHERE challenge_id = ?) OR asset_id IN "
            "(SELECT id FROM assets WHERE challenge_id = ?)",
            (challenge_id, challenge_id),
        )
        connection.execute("DELETE FROM submissions WHERE challenge_id = ?", (challenge_id,))
        connection.execute("DELETE FROM hints WHERE challenge_id = ?", (challenge_id,))
        connection.execute("DELETE FROM challenge_tags WHERE challenge_id = ?", (challenge_id,))
        connection.execute("DELETE FROM collection_challenges WHERE challenge_id = ?", (challenge_id,))
        connection.execute("DELETE FROM instances WHERE challenge_id = ?", (challenge_id,))
        connection.execute("DELETE FROM assets WHERE challenge_id = ?", (challenge_id,))
        connection.execute("DELETE FROM challenges WHERE id = ?", (challenge_id,))
    for asset in assets:
        (settings.storage_path / asset["stored_name"]).unlink(missing_ok=True)
    image = challenge["docker_image"]
    if image and image.startswith("syclover/training-garden-"):
        # The platform built this image from the challenge archive, so it is removed with
        # the challenge. Shared base images are left alone.
        try:
            docker.remove_image(image)
        except ContainerError as exc:
            logger.warning("Challenge image %s could not be removed: %s", image, exc)
    return Message(message="Challenge deleted")


@router.post("/{challenge_id}/attachments", response_model=AssetPublic, status_code=201)
async def upload_attachment(
    challenge_id: str,
    request: Request,
    _: AdminUser,
    database: DatabaseDep,
    settings: SettingsDep,
    filename: str = Query(min_length=1, max_length=120),
) -> AssetPublic:
    content = await request.body()
    if not content or len(content) > settings.max_upload_bytes:
        raise HTTPException(status_code=413, detail="Attachment is empty or exceeds the upload limit")
    with database.connect() as connection:
        if not connection.execute("SELECT 1 FROM challenges WHERE id = ?", (challenge_id,)).fetchone():
            raise HTTPException(status_code=404, detail="Challenge not found")
    stored_name, _ = store_bytes(settings.storage_path, challenge_id, filename, content)
    asset_id = str(uuid.uuid4())
    now = datetime.now(UTC).isoformat()
    with database.connect() as connection:
        connection.execute(
            """
            INSERT INTO assets (
                id, challenge_id, user_id, kind, original_name, stored_name, size_bytes,
                validation_status, validation_output, created_at
            ) VALUES (?, ?, NULL, 'attachment', ?, ?, ?, 'valid', 'Attachment is available.', ?)
            """,
            (asset_id, challenge_id, safe_filename(filename), stored_name, len(content), now),
        )
        row = connection.execute("SELECT * FROM assets WHERE id = ?", (asset_id,)).fetchone()
    return _asset(row)


@router.get("/{challenge_id}/hints", response_model=list[HintPublic])
async def list_hints(
    challenge_id: str, user: CurrentUser, database: DatabaseDep
) -> list[HintPublic]:
    with database.connect() as connection:
        challenge = connection.execute(
            "SELECT status FROM challenges WHERE id = ?", (challenge_id,)
        ).fetchone()
        if not challenge or (challenge["status"] != "published" and user["role"] not in {"admin", "root_admin"}):
            raise HTTPException(status_code=404, detail="Challenge not found")
        if user["role"] in {"admin", "root_admin"}:
            rows = connection.execute(
                "SELECT * FROM hints WHERE challenge_id = ? ORDER BY created_at",
                (challenge_id,),
            ).fetchall()
        else:
            rows = connection.execute(
                "SELECT * FROM hints WHERE challenge_id = ? AND status = 'published' ORDER BY created_at",
                (challenge_id,),
            ).fetchall()
    return [HintPublic.model_validate(dict(row)) for row in rows]


@router.post("/{challenge_id}/hints", response_model=HintPublic, status_code=201)
async def create_hint(
    challenge_id: str,
    payload: HintCreate,
    _: AdminUser,
    database: DatabaseDep,
) -> HintPublic:
    hint_id = str(uuid.uuid4())
    now = datetime.now(UTC).isoformat()
    with database.connect() as connection:
        if not connection.execute(
            "SELECT 1 FROM challenges WHERE id = ?", (challenge_id,)
        ).fetchone():
            raise HTTPException(status_code=404, detail="Challenge not found")
        connection.execute(
            "INSERT INTO hints (id, challenge_id, title, content, status, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (hint_id, challenge_id, payload.title, payload.content, payload.status, now, now),
        )
        row = connection.execute("SELECT * FROM hints WHERE id = ?", (hint_id,)).fetchone()
    return HintPublic.model_validate(dict(row))


@router.patch("/hints/{hint_id}", response_model=HintPublic)
async def update_hint(
    hint_id: str, payload: HintUpdate, _: AdminUser, database: DatabaseDep
) -> HintPublic:
    fields = payload.model_dump(exclude_unset=True, exclude_none=True)
    if not fields:
        raise HTTPException(status_code=400, detail="No changes supplied")
    fields["updated_at"] = datetime.now(UTC).isoformat()
    assignments = ", ".join(f"{key} = ?" for key in fields)
    with database.connect() as connection:
        cursor = connection.execute(
            f"UPDATE hints SET {assignments} WHERE id = ?", (*fields.values(), hint_id)
        )
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Hint not found")
        row = connection.execute("SELECT * FROM hints WHERE id = ?", (hint_id,)).fetchone()
    return HintPublic.model_validate(dict(row))


@router.delete("/hints/{hint_id}", response_model=Message)
async def delete_hint(hint_id: str, _: AdminUser, database: DatabaseDep) -> Message:
    with database.connect() as connection:
        cursor = connection.execute("DELETE FROM hints WHERE id = ?", (hint_id,))
    if cursor.rowcount == 0:
        raise HTTPException(status_code=404, detail="Hint not found")
    return Message(message="Hint deleted")


@router.get("/assets/{asset_id}/download")
async def download_asset(asset_id: str, user: CurrentUser, database: DatabaseDep, settings: SettingsDep):
    with database.connect() as connection:
        row = connection.execute("SELECT * FROM assets WHERE id = ?", (asset_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Asset not found")
    if row["kind"] != "attachment" and row["user_id"] != user["id"] and user["role"] not in {"admin", "root_admin"}:
        raise HTTPException(status_code=404, detail="Asset not found")
    path = settings.storage_path / row["stored_name"]
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Asset file is missing")
    return Response(
        content=path.read_bytes(),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{row["original_name"]}"'},
    )
