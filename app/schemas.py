from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from app.services.flags import template_wants_random
from app.services.invites import MAX_CODES_PER_REQUEST

CTF_CATEGORIES = ("Web", "Pwn", "Reverse", "Misc", "Crypto")
AWDP_CATEGORIES = ("Web", "Pwn")
USER_DIRECTIONS = CTF_CATEGORIES


def category_is_valid(mode: str, category: str) -> bool:
    allowed = AWDP_CATEGORIES if mode == "awdp" else CTF_CATEGORIES
    return category in allowed


class Message(BaseModel):
    message: str


class UserPublic(BaseModel):
    id: str
    username: str
    role: Literal["player", "admin", "root_admin"]
    is_active: bool
    avatar_url: str | None = None
    signature: str | None = None
    direction: Literal["Web", "Pwn", "Reverse", "Crypto", "Misc"] | None = None
    created_at: datetime
    achievement_slugs: list[str] = Field(default_factory=list)


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=32, pattern=r"^[A-Za-z0-9_-]+$")
    password: str = Field(min_length=8, max_length=128)
    invite_code: str = Field(min_length=4, max_length=64)


class InviteCodePublic(BaseModel):
    id: str
    code: str
    note: str | None = None
    status: Literal["unused", "used"]
    created_by: str | None = None
    created_by_username: str | None = None
    used_by: str | None = None
    used_by_username: str | None = None
    created_at: datetime
    used_at: datetime | None = None


class InviteCodeCreate(BaseModel):
    count: int = Field(default=1, ge=1, le=MAX_CODES_PER_REQUEST)
    note: str | None = Field(default=None, max_length=120)

    @field_validator("note")
    @classmethod
    def normalize_note(cls, value: str | None) -> str | None:
        return value.strip() if value and value.strip() else None


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserPublic


class UserUpdate(BaseModel):
    role: Literal["player", "admin"] | None = None
    is_active: bool | None = None


class ProfileUpdate(BaseModel):
    avatar_url: str | None = Field(default=None, max_length=500)
    signature: str | None = Field(default=None, max_length=160)
    direction: Literal["Web", "Pwn", "Reverse", "Crypto", "Misc"] | None = None


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=8, max_length=128)
    new_password: str = Field(min_length=8, max_length=128)


class AchievementPublic(BaseModel):
    slug: str
    name: str
    description: str
    acquisition: str
    icon: str
    awarded_at: datetime | None = None
    is_builtin: bool = False


class AchievementCreate(BaseModel):
    slug: str = Field(min_length=2, max_length=48, pattern=r"^[a-z0-9_]+$")
    name: str = Field(min_length=1, max_length=80)
    description: str = Field(min_length=1, max_length=300)
    acquisition: str = Field(min_length=1, max_length=200)
    icon: str = Field(default="core", min_length=1, max_length=48, pattern=r"^[a-z0-9-]+$")


class AchievementUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=80)
    description: str | None = Field(default=None, min_length=1, max_length=300)
    acquisition: str | None = Field(default=None, min_length=1, max_length=200)
    icon: str | None = Field(default=None, min_length=1, max_length=48, pattern=r"^[a-z0-9-]+$")


class AnnouncementCreate(BaseModel):
    title: str = Field(min_length=1, max_length=120)
    content: str = Field(min_length=1, max_length=10000)
    status: Literal["draft", "published"] = "draft"


class AnnouncementUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=120)
    content: str | None = Field(default=None, min_length=1, max_length=10000)
    status: Literal["draft", "published"] | None = None


class AnnouncementPublic(AnnouncementCreate):
    id: str
    author: str | None = None
    created_at: datetime
    updated_at: datetime


class CollectionCreate(BaseModel):
    title: str = Field(min_length=1, max_length=120)
    slug: str = Field(min_length=2, max_length=80, pattern=r"^[a-z0-9-]+$")
    description: str = Field(min_length=1, max_length=5000)
    status: Literal["draft", "published"] = "draft"
    challenge_ids: list[str] = Field(default_factory=list, max_length=200)


class CollectionUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=120)
    slug: str | None = Field(default=None, min_length=2, max_length=80, pattern=r"^[a-z0-9-]+$")
    description: str | None = Field(default=None, min_length=1, max_length=5000)
    status: Literal["draft", "published"] | None = None
    challenge_ids: list[str] | None = Field(default=None, max_length=200)


class CollectionPublic(CollectionCreate):
    id: str
    challenge_count: int = 0
    created_at: datetime
    updated_at: datetime


class UserProfile(UserPublic):
    score: int = 0
    solves: int = 0
    rank: int | None = None
    achievements: list[AchievementPublic] = Field(default_factory=list)


class ChallengeCreate(BaseModel):
    title: str = Field(min_length=2, max_length=100)
    slug: str = Field(min_length=2, max_length=80, pattern=r"^[a-z0-9-]+$")
    description: str = Field(min_length=10, max_length=10_000)
    category: Literal["Web", "Pwn", "Reverse", "Misc", "Crypto"]
    mode: Literal["ctf", "awdp"]
    difficulty: Literal["noob", "easy", "normal", "hard", "insane"]
    points: int = Field(ge=1, le=10_000)
    docker_image: str | None = Field(default=None, max_length=255)
    internal_port: int | None = Field(default=None, ge=1, le=65535)
    flag: str = Field(min_length=3, max_length=512)
    dynamic_flag: bool = False
    tags: list[str] = Field(default_factory=list, max_length=20)
    status: Literal["draft", "published", "archived"] = "draft"

    @field_validator("docker_image")
    @classmethod
    def normalize_image(cls, value: str | None) -> str | None:
        return value.strip() if value and value.strip() else None

    @model_validator(mode="after")
    def validate_category_for_mode(self):
        if not category_is_valid(self.mode, self.category):
            raise ValueError(f"{self.category} is not a valid category for {self.mode.upper()}")
        return self


class ChallengeUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=2, max_length=100)
    description: str | None = Field(default=None, min_length=10, max_length=10_000)
    category: Literal["Web", "Pwn", "Reverse", "Misc", "Crypto"] | None = None
    mode: Literal["ctf", "awdp"] | None = None
    difficulty: Literal["noob", "easy", "normal", "hard", "insane"] | None = None
    points: int | None = Field(default=None, ge=1, le=10_000)
    docker_image: str | None = Field(default=None, max_length=255)
    internal_port: int | None = Field(default=None, ge=1, le=65535)
    flag: str | None = Field(default=None, min_length=3, max_length=512)
    dynamic_flag: bool | None = None
    tags: list[str] | None = Field(default=None, max_length=20)
    status: Literal["draft", "published", "archived"] | None = None


class TagPublic(BaseModel):
    id: str
    name: str
    kind: Literal["topic", "state"]
    description: str | None = None
    challenge_count: int = 0
    sort_order: int = 100


class TagCreate(BaseModel):
    name: str = Field(min_length=1, max_length=32)
    description: str | None = Field(default=None, max_length=200)
    sort_order: int = Field(default=100, ge=0, le=10000)


class TagUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=32)
    description: str | None = Field(default=None, max_length=200)
    sort_order: int | None = Field(default=None, ge=0, le=10000)


class AssetPublic(BaseModel):
    id: str
    challenge_id: str
    user_id: str | None
    kind: Literal["attachment", "build_archive", "patch", "check_script", "fix_script"]
    original_name: str
    size_bytes: int
    validation_status: Literal["pending", "valid", "invalid"]
    validation_output: str | None
    created_at: datetime
    download_url: str


class BloodEntry(BaseModel):
    rank: int
    user_id: str
    username: str
    solved_at: datetime


class HintPublic(BaseModel):
    id: str
    challenge_id: str
    title: str
    content: str
    status: Literal["draft", "published"]
    created_at: datetime
    updated_at: datetime


class HintCreate(BaseModel):
    title: str = Field(min_length=1, max_length=100)
    content: str = Field(min_length=1, max_length=20_000)
    status: Literal["draft", "published"] = "draft"


class HintUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=100)
    content: str | None = Field(default=None, min_length=1, max_length=20_000)
    status: Literal["draft", "published"] | None = None


class BuildResult(BaseModel):
    challenge_id: str
    image: str
    status: Literal["success", "failed"]
    output: str
    internal_port: int | None
    detected_port: int | None = None
    port_warning: str | None = None


class BuildProgress(BaseModel):
    challenge_id: str
    status: Literal["none", "building", "success", "failed"]
    data: str = ""
    cursor: int = 0
    finished: bool = False
    truncated: bool = False
    percent: int = 0
    port_warning: str | None = None


class ChallengePublic(BaseModel):
    id: str
    title: str
    slug: str
    description: str
    category: str
    mode: Literal["ctf", "awdp"]
    difficulty: Literal["noob", "easy", "normal", "hard", "insane"]
    points: int
    docker_image: str | None
    internal_port: int | None
    build_status: Literal["none", "building", "success", "failed"] = "none"
    detected_port: int | None = None
    status: Literal["draft", "published", "archived"]
    flag_template: str | None = None
    dynamic_flag: bool = False
    tags: list[str] = Field(default_factory=list)
    solved: bool = False
    attachments: list[AssetPublic] = Field(default_factory=list)
    check_script_configured: bool = False
    fix_script_configured: bool = False
    solves: int = 0
    bloods: list[BloodEntry] = Field(default_factory=list)
    attack_solves: int = 0
    defense_solves: int = 0
    attack_bloods: list[BloodEntry] = Field(default_factory=list)
    defense_bloods: list[BloodEntry] = Field(default_factory=list)


class InstancePublic(BaseModel):
    id: str
    challenge_id: str
    challenge_title: str | None = None
    public_host: str | None
    public_port: int | None
    instance_flag: str | None = None
    status: Literal["starting", "running", "stopped", "failed"]
    error_message: str | None
    expires_at: datetime
    created_at: datetime

    @model_validator(mode="after")
    def add_access_hints(self):
        """Give the browser everything it needs to reach the instance.

        Web-style challenges are opened over HTTP; everything else is a raw TCP
        service, so the UI shows a ready-to-paste ``nc`` command instead.
        """
        if self.public_host and self.public_port:
            host = f"[{self.public_host}]" if ":" in self.public_host else self.public_host
            self.connect_command = f"nc {host} {self.public_port}"
            self.access_url = f"http://{host}:{self.public_port}"
            self.listen_address = f"{host}:{self.public_port}"
        return self

    connect_command: str | None = None
    access_url: str | None = None
    listen_address: str | None = None

    @model_validator(mode="before")
    @classmethod
    def hide_instance_flag_from_players(cls, value: Any) -> Any:
        """The instance flag is an administrator-only answer key.

        Players must recover it from the deployed service; leaking it in the API would
        hand over the solution the moment an environment starts.
        """
        if isinstance(value, dict) and not value.get("is_admin", False):
            data = dict(value)
            data["instance_flag"] = None
            return data
        return value


class SubmissionRequest(BaseModel):
    flag: str = Field(min_length=1, max_length=512)


class SubmissionResult(BaseModel):
    correct: bool
    awarded_points: int
    message: str


class ScoreEntry(BaseModel):
    rank: int
    user_id: str
    username: str
    score: int
    solves: int
    last_solve_at: datetime | None


class ScoreboardResponse(BaseModel):
    participants: int
    published_challenges: int
    total_solves: int
    rankings: list[ScoreEntry]


class DeploymentEventPublic(BaseModel):
    id: str
    instance_id: str
    asset_id: str
    success: bool
    output: str
    created_at: datetime
