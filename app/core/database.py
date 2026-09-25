from __future__ import annotations

import sqlite3
import uuid
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterator

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'player' CHECK (role IN ('player', 'admin', 'root_admin')),
    is_active INTEGER NOT NULL DEFAULT 1,
    avatar_url TEXT,
    signature TEXT,
    direction TEXT CHECK (direction IN ('Web', 'Pwn', 'Reverse', 'Crypto', 'Misc')),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS achievements (
    slug TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    acquisition TEXT NOT NULL,
    icon TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS user_achievements (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    achievement_slug TEXT NOT NULL REFERENCES achievements(slug) ON DELETE CASCADE,
    awarded_at TEXT NOT NULL,
    awarded_by TEXT REFERENCES users(id) ON DELETE SET NULL,
    PRIMARY KEY (user_id, achievement_slug)
);

CREATE INDEX IF NOT EXISTS idx_user_achievements_user ON user_achievements(user_id);

CREATE TABLE IF NOT EXISTS challenges (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL,
    category TEXT NOT NULL,
    mode TEXT NOT NULL CHECK (mode IN ('ctf', 'awdp')),
    difficulty TEXT NOT NULL CHECK (difficulty IN ('noob', 'easy', 'normal', 'hard', 'insane')),
    points INTEGER NOT NULL CHECK (points > 0),
    docker_image TEXT,
    internal_port INTEGER,
    build_status TEXT NOT NULL DEFAULT 'none' CHECK (build_status IN ('none', 'building', 'success', 'failed')),
    build_output TEXT,
    detected_port INTEGER,
    flag_template TEXT,
    dynamic_flag INTEGER NOT NULL DEFAULT 0,
    flag_digest TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'published', 'archived')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS instances (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    challenge_id TEXT NOT NULL REFERENCES challenges(id),
    container_id TEXT,
    container_name TEXT NOT NULL,
    public_host TEXT,
    public_port INTEGER,
    instance_flag TEXT,
    status TEXT NOT NULL CHECK (status IN ('starting', 'running', 'stopped', 'failed')),
    error_message TEXT,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    stopped_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_instances_user_status ON instances(user_id, status);

CREATE TABLE IF NOT EXISTS submissions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    challenge_id TEXT NOT NULL REFERENCES challenges(id),
    correct INTEGER NOT NULL,
    awarded_points INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_submissions_score ON submissions(user_id, correct);

CREATE TABLE IF NOT EXISTS assets (
    id TEXT PRIMARY KEY,
    challenge_id TEXT NOT NULL REFERENCES challenges(id),
    user_id TEXT REFERENCES users(id),
    kind TEXT NOT NULL CHECK (kind IN ('attachment', 'build_archive', 'patch', 'check_script', 'fix_script')),
    original_name TEXT NOT NULL,
    stored_name TEXT NOT NULL UNIQUE,
    size_bytes INTEGER NOT NULL,
    validation_status TEXT NOT NULL DEFAULT 'pending' CHECK (validation_status IN ('pending', 'valid', 'invalid')),
    validation_output TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS deployment_events (
    id TEXT PRIMARY KEY,
    instance_id TEXT NOT NULL REFERENCES instances(id),
    asset_id TEXT NOT NULL REFERENCES assets(id),
    user_id TEXT NOT NULL REFERENCES users(id),
    success INTEGER NOT NULL,
    output TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS defense_solves (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    challenge_id TEXT NOT NULL REFERENCES challenges(id),
    event_id TEXT NOT NULL UNIQUE REFERENCES deployment_events(id),
    created_at TEXT NOT NULL,
    UNIQUE(user_id, challenge_id)
);

CREATE TABLE IF NOT EXISTS hints (
    id TEXT PRIMARY KEY,
    challenge_id TEXT NOT NULL REFERENCES challenges(id),
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'published')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tags (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
    kind TEXT NOT NULL DEFAULT 'topic' CHECK (kind IN ('topic', 'state')),
    description TEXT,
    sort_order INTEGER NOT NULL DEFAULT 100,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS challenge_tags (
    challenge_id TEXT NOT NULL REFERENCES challenges(id),
    tag_id TEXT NOT NULL REFERENCES tags(id),
    created_at TEXT NOT NULL,
    PRIMARY KEY (challenge_id, tag_id)
);

CREATE TABLE IF NOT EXISTS invite_codes (
    id TEXT PRIMARY KEY,
    code TEXT NOT NULL UNIQUE COLLATE NOCASE,
    note TEXT,
    created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
    used_by TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL,
    used_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_invite_codes_used_at ON invite_codes(used_at);

CREATE INDEX IF NOT EXISTS idx_submissions_challenge_correct_created
ON submissions(challenge_id, correct, created_at);
CREATE INDEX IF NOT EXISTS idx_defense_solves_challenge_created
ON defense_solves(challenge_id, created_at);
CREATE INDEX IF NOT EXISTS idx_hints_challenge_status_created
ON hints(challenge_id, status, created_at);
CREATE INDEX IF NOT EXISTS idx_challenge_tags_tag ON challenge_tags(tag_id);

CREATE TABLE IF NOT EXISTS announcements (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'published')),
    created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_announcements_status_created ON announcements(status, created_at);

CREATE TABLE IF NOT EXISTS collections (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'published')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS collection_challenges (
    collection_id TEXT NOT NULL REFERENCES collections(id) ON DELETE CASCADE,
    challenge_id TEXT NOT NULL REFERENCES challenges(id),
    sort_order INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (collection_id, challenge_id)
);
CREATE INDEX IF NOT EXISTS idx_collection_challenges_challenge ON collection_challenges(challenge_id);
"""

# Knowledge-point tags seeded on first start; administrators may rename or remove them.
DEFAULT_TAGS = (
    ("web", "topic", "Web 方向知识点", 10),
    ("pwn", "topic", "二进制利用", 20),
    ("reverse", "topic", "逆向工程", 30),
    ("crypto", "topic", "密码学", 40),
    ("misc", "topic", "杂项与综合", 50),
)

ACHIEVEMENT_DEFINITIONS = (
    ("sprout_member", "新芽组成员", "学习、汲取、成长", "注册自动获取", "sprout"),
    ("core_member", "核心组成员", "热爱、坚持、成就", "管理员下发", "core"),
    ("peak_geek_2025", "Peak Geek 2025", "完成 2025 极客大挑战所有题目", "完成 2025 极客大挑战全部题目", "peak-geek"),
    ("first_solve", "破土而出", "解开第一道题，训练旅程正式开始", "首次正确解题", "first-solve"),
    ("five_solves", "渐入佳境", "累计解开 5 道不同题目", "累计解开 5 道题", "five-solves"),
    ("ten_solves", "稳步生长", "累计解开 10 道不同题目", "累计解开 10 道题", "ten-solves"),
    ("first_defense", "守护新芽", "首次成功部署修复并通过防御检查", "首次完成 AWDP 防御", "first-defense"),
    ("first_try", "一发入魂", "没有试错，首次提交就解开一道题", "任意题目首次提交即正确", "first-try"),
    ("comeback", "越挫越勇", "一次次尝试后终于找到正确答案", "同一道题答错至少 3 次后解出", "comeback"),
    ("versatile", "跨界玩家", "在三个不同方向留下解题记录", "解开 3 个不同分类的题目", "versatile"),
)


class Database:
    def __init__(self, path: Path):
        self.path = path

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._migrate_legacy_constraints()
        with self.connect() as connection:
            connection.executescript(SCHEMA)
        self._migrate_user_profile()
        self._migrate_user_roles()
        self._migrate_achievement_catalog()
        self._migrate_flags()
        self._seed_tags()
        self._seed_achievements()
        self._backfill_progress_achievements()

    def _migrate_user_profile(self) -> None:
        """Add profile fields to databases created before Alpha0.0.5."""
        with self.connect() as connection:
            columns = {
                row[1] for row in connection.execute("PRAGMA table_info(users)").fetchall()
            }
            if "avatar_url" not in columns:
                connection.execute("ALTER TABLE users ADD COLUMN avatar_url TEXT")
            if "signature" not in columns:
                connection.execute("ALTER TABLE users ADD COLUMN signature TEXT")
            if "direction" not in columns:
                connection.execute("ALTER TABLE users ADD COLUMN direction TEXT")

    def _seed_achievements(self) -> None:
        """Keep the built-in achievement catalog and registration badge available."""
        now = datetime.now(UTC).isoformat()
        with self.connect() as connection:
            for slug, name, description, acquisition, icon in ACHIEVEMENT_DEFINITIONS:
                connection.execute(
                    "INSERT OR IGNORE INTO achievements "
                    "(slug, name, description, acquisition, icon, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (slug, name, description, acquisition, icon, now),
                )
            user_rows = connection.execute("SELECT id FROM users").fetchall()
            connection.executemany(
                "INSERT OR IGNORE INTO user_achievements "
                "(user_id, achievement_slug, awarded_at) VALUES (?, 'sprout_member', ?)",
                [(row["id"], now) for row in user_rows],
            )
            connection.execute(
                "DELETE FROM user_achievements WHERE achievement_slug = 'sprout_member' "
                "AND EXISTS (SELECT 1 FROM user_achievements core WHERE core.user_id = user_achievements.user_id "
                "AND core.achievement_slug = 'core_member')"
            )

    def _backfill_progress_achievements(self) -> None:
        """Award newly introduced milestones for solves recorded before this release."""
        from app.services.achievements import sync_progress_achievements

        with self.connect() as connection:
            rows = connection.execute(
                "SELECT user_id FROM submissions WHERE correct = 1 AND awarded_points > 0 "
                "UNION SELECT user_id FROM defense_solves"
            ).fetchall()
            for row in rows:
                sync_progress_achievements(connection, row["user_id"])

    def _migrate_achievement_catalog(self) -> None:
        with self.connect() as connection:
            columns = {row[1] for row in connection.execute("PRAGMA table_info(achievements)").fetchall()}
            if columns and "acquisition" not in columns:
                connection.execute(
                    "ALTER TABLE achievements ADD COLUMN acquisition TEXT NOT NULL DEFAULT '管理员下发'"
                )

    def _migrate_user_roles(self) -> None:
        """Allow root administrators and promote legacy administrators during upgrade."""
        connection = sqlite3.connect(self.path, timeout=10)
        try:
            connection.execute("PRAGMA foreign_keys = OFF")
            table = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'users'"
            ).fetchone()
            if not table or "'root_admin'" in table[0]:
                return
            connection.executescript(
                """
                CREATE TABLE users_v2 (
                    id TEXT PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'player' CHECK (role IN ('player', 'admin', 'root_admin')),
                    is_active INTEGER NOT NULL DEFAULT 1,
                    avatar_url TEXT,
                    signature TEXT,
                    direction TEXT CHECK (direction IN ('Web', 'Pwn', 'Reverse', 'Crypto', 'Misc')),
                    created_at TEXT NOT NULL
                );
                INSERT INTO users_v2 (id, username, password_hash, role, is_active, avatar_url, signature, direction, created_at)
                SELECT id, username, password_hash, role,
                       is_active, avatar_url, signature, direction, created_at
                FROM users;
                DROP TABLE users;
                ALTER TABLE users_v2 RENAME TO users;
                """
            )
            connection.commit()
        finally:
            connection.close()

    def _migrate_flags(self) -> None:
        """Convert Alpha0.0.2 ``<RANDOM>`` templates to the RAND token used since 0.0.3.

        Without this an old template would be rendered literally (or rejected), which is
        exactly what produced "Unsafe instance flag value" when starting an instance.
        """
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT id, flag_template, dynamic_flag FROM challenges "
                "WHERE flag_template LIKE '%<RANDOM>%'"
            ).fetchall()
            for row in rows:
                template = (row["flag_template"] or "").replace("<RANDOM>", "RAND")
                connection.execute(
                    "UPDATE challenges SET flag_template = ?, dynamic_flag = 1 WHERE id = ?",
                    (template, row["id"]),
                )

    def _seed_tags(self) -> None:
        """Insert the default knowledge-point tags once, without touching later edits."""
        with self.connect() as connection:
            for name, kind, description, order in DEFAULT_TAGS:
                connection.execute(
                    "INSERT OR IGNORE INTO tags (id, name, kind, description, sort_order, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (str(uuid.uuid4()), name, kind, description, order, datetime.now(UTC).isoformat()),
                )

    def _migrate_legacy_constraints(self) -> None:
        """Rebuild constrained SQLite tables introduced before Alpha0.0.1."""
        connection = sqlite3.connect(self.path, timeout=10)
        try:
            connection.execute("PRAGMA foreign_keys = OFF")
            challenge_sql = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'challenges'"
            ).fetchone()
            if challenge_sql and "'normal'" not in challenge_sql[0]:
                connection.executescript(
                    """
                    CREATE TABLE challenges_v2 (
                        id TEXT PRIMARY KEY, title TEXT NOT NULL, slug TEXT NOT NULL UNIQUE,
                        description TEXT NOT NULL, category TEXT NOT NULL,
                        mode TEXT NOT NULL CHECK (mode IN ('ctf', 'awdp')),
                        difficulty TEXT NOT NULL CHECK (difficulty IN ('noob', 'easy', 'normal', 'hard', 'insane')),
                        points INTEGER NOT NULL CHECK (points > 0), docker_image TEXT,
                        internal_port INTEGER,
                        build_status TEXT NOT NULL DEFAULT 'none'
                            CHECK (build_status IN ('none', 'building', 'success', 'failed')),
                        build_output TEXT, detected_port INTEGER,
                        flag_template TEXT, dynamic_flag INTEGER NOT NULL DEFAULT 0,
                        flag_digest TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'published', 'archived')),
                        created_at TEXT NOT NULL, updated_at TEXT NOT NULL
                    );
                    INSERT INTO challenges_v2 (
                        id, title, slug, description, category, mode, difficulty, points,
                        docker_image, internal_port, flag_digest, status, created_at, updated_at
                    )
                    SELECT id, title, slug, description, category, mode,
                           CASE difficulty WHEN 'medium' THEN 'normal' ELSE difficulty END,
                           points, docker_image, internal_port, flag_digest, status, created_at, updated_at
                    FROM challenges;
                    DROP TABLE challenges;
                    ALTER TABLE challenges_v2 RENAME TO challenges;
                    """
                )

            asset_sql = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'assets'"
            ).fetchone()
            if asset_sql and "'build_archive'" not in asset_sql[0]:
                connection.executescript(
                    """
                    CREATE TABLE assets_v2 (
                        id TEXT PRIMARY KEY,
                        challenge_id TEXT NOT NULL REFERENCES challenges(id),
                        user_id TEXT REFERENCES users(id),
                        kind TEXT NOT NULL CHECK (kind IN ('attachment', 'build_archive', 'patch', 'check_script', 'fix_script')),
                        original_name TEXT NOT NULL, stored_name TEXT NOT NULL UNIQUE,
                        size_bytes INTEGER NOT NULL,
                        validation_status TEXT NOT NULL DEFAULT 'pending'
                            CHECK (validation_status IN ('pending', 'valid', 'invalid')),
                        validation_output TEXT, created_at TEXT NOT NULL
                    );
                    INSERT INTO assets_v2 SELECT * FROM assets;
                    DROP TABLE assets;
                    ALTER TABLE assets_v2 RENAME TO assets;
                    """
                )
            challenge_columns = {
                row[1] for row in connection.execute("PRAGMA table_info(challenges)").fetchall()
            }
            if challenge_columns and "build_status" not in challenge_columns:
                connection.execute(
                    "ALTER TABLE challenges ADD COLUMN build_status TEXT NOT NULL DEFAULT 'none'"
                )
            if challenge_columns and "build_output" not in challenge_columns:
                connection.execute("ALTER TABLE challenges ADD COLUMN build_output TEXT")
            if challenge_columns and "flag_template" not in challenge_columns:
                connection.execute("ALTER TABLE challenges ADD COLUMN flag_template TEXT")
            if challenge_columns and "detected_port" not in challenge_columns:
                connection.execute("ALTER TABLE challenges ADD COLUMN detected_port INTEGER")
            if challenge_columns and "dynamic_flag" not in challenge_columns:
                connection.execute(
                    "ALTER TABLE challenges ADD COLUMN dynamic_flag INTEGER NOT NULL DEFAULT 0"
                )
                # Challenges created before the switch existed expressed randomness via a token.
                connection.execute(
                    "UPDATE challenges SET dynamic_flag = 1 "
                    "WHERE flag_template LIKE '%<RANDOM>%'"
                )
            instance_columns = {
                row[1] for row in connection.execute("PRAGMA table_info(instances)").fetchall()
            }
            if instance_columns and "instance_flag" not in instance_columns:
                connection.execute("ALTER TABLE instances ADD COLUMN instance_flag TEXT")
            connection.commit()
        finally:
            connection.close()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
