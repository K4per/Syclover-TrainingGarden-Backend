from __future__ import annotations

import io
from zipfile import ZipFile

from app.services.build_log import BuildRegistry
from app.services.tags import slugify_tag


def _challenge_payload(**overrides):
    payload = {
        "title": "Tagged Challenge",
        "slug": "tagged-challenge",
        "description": "A challenge used to exercise tag handling.",
        "category": "Web",
        "mode": "ctf",
        "difficulty": "easy",
        "points": 100,
        "flag": "SYC{tags}",
        "status": "draft",
    }
    payload.update(overrides)
    return payload


def test_default_tag_catalog_contains_topics_and_states(client, admin_headers):
    catalog = client.get("/api/v1/challenges/tags/catalog", headers=admin_headers)
    assert catalog.status_code == 200
    entries = catalog.json()
    names = {entry["name"] for entry in entries}
    assert {"web", "pwn", "reverse", "crypto", "misc"} <= names
    assert {"static", "dynamic"} <= names
    states = {entry["name"]: entry["kind"] for entry in entries if entry["kind"] == "state"}
    assert states == {"static": "state", "dynamic": "state"}
    # demo seed keeps one deployable and one attachment-only challenge published
    counts = {entry["name"]: entry["challenge_count"] for entry in entries}
    assert counts["dynamic"] >= 1
    assert counts["static"] >= 1


def test_tags_are_stored_derived_and_filterable(client, admin_headers, player_headers):
    created = client.post(
        "/api/v1/challenges",
        headers=admin_headers,
        json=_challenge_payload(tags=["Web", "sql injection", "web"], docker_image="nginx:alpine", internal_port=80),
    )
    assert created.status_code == 201
    body = created.json()
    challenge_id = body["id"]
    # duplicates and casing are normalized, dynamic is derived from the image
    assert body["tags"] == ["web", "sql-injection", "dynamic"]

    published = client.patch(
        f"/api/v1/challenges/{challenge_id}", headers=admin_headers, json={"status": "published"}
    )
    assert published.status_code == 200
    assert published.json()["tags"] == ["web", "sql-injection", "dynamic"]

    filtered = client.get("/api/v1/challenges?tag=sql-injection", headers=player_headers).json()
    assert [item["id"] for item in filtered] == [challenge_id]
    assert client.get("/api/v1/challenges?tag=web", headers=player_headers).json()
    assert client.get("/api/v1/challenges?tag=pwn", headers=player_headers).json() == []
    assert challenge_id not in [
        item["id"] for item in client.get("/api/v1/challenges?tag=static", headers=player_headers).json()
    ]

    # replacing the tag list is how an administrator re-classifies a challenge
    updated = client.patch(
        f"/api/v1/challenges/{challenge_id}", headers=admin_headers, json={"tags": ["misc"]}
    )
    assert updated.json()["tags"] == ["misc", "dynamic"]
    assert client.get("/api/v1/challenges?tag=sql-injection", headers=player_headers).json() == []


def test_static_state_tag_follows_the_environment(client, admin_headers):
    created = client.post(
        "/api/v1/challenges", headers=admin_headers, json=_challenge_payload(slug="static-tagged")
    ).json()
    assert created["tags"] == ["static"]
    promoted = client.patch(
        f"/api/v1/challenges/{created['id']}",
        headers=admin_headers,
        json={"docker_image": "nginx:alpine", "internal_port": 80},
    ).json()
    assert promoted["tags"] == ["dynamic"]


def test_deleting_a_challenge_removes_the_image_it_built(client, admin_headers, monkeypatch):
    removed: list[str] = []

    class RecordingDocker:
        def stop(self, container_id):
            return None

        def remove_image(self, image):
            removed.append(image)

    from app.api.deps import get_docker_service
    from app.main import create_app  # noqa: F401  (documents the dependency wire-up)

    app = client.app
    async def recording_docker():
        return RecordingDocker()

    app.dependency_overrides[get_docker_service] = recording_docker
    try:
        created = client.post(
            "/api/v1/challenges",
            headers=admin_headers,
            json=_challenge_payload(
                slug="image-cleanup",
                docker_image="syclover/training-garden-image-cleanup:alpha0.0.3-hotfix.2",
            ),
        ).json()
        assert client.delete(f"/api/v1/challenges/{created['id']}", headers=admin_headers).status_code == 200
        assert removed == ["syclover/training-garden-image-cleanup:alpha0.0.3-hotfix.2"]
    finally:
        app.dependency_overrides.pop(get_docker_service, None)


def test_deleting_a_tagged_challenge_removes_its_tag_links(client, admin_headers):
    created = client.post(
        "/api/v1/challenges",
        headers=admin_headers,
        json=_challenge_payload(slug="tagged-for-deletion", tags=["web", "misc"]),
    ).json()
    assert created["tags"] == ["web", "misc", "static"]
    assert client.delete(f"/api/v1/challenges/{created['id']}", headers=admin_headers).status_code == 200
    assert client.get(f"/api/v1/challenges/{created['id']}", headers=admin_headers).status_code == 404
    catalog = client.get("/api/v1/challenges/tags/catalog", headers=admin_headers).json()
    assert all(entry["name"] in {"web", "pwn", "reverse", "crypto", "misc", "static", "dynamic"} for entry in catalog)


def test_admin_can_create_a_tag_directly(client, admin_headers, player_headers):
    created = client.post(
        "/api/v1/challenges/tags",
        headers=admin_headers,
        json={"name": "Stack Overflow", "description": "栈溢出与利用"},
    )
    assert created.status_code == 201
    body = created.json()
    assert body["name"] == "stack-overflow"
    assert body["kind"] == "topic"
    assert body["challenge_count"] == 0

    duplicate = client.post(
        "/api/v1/challenges/tags", headers=admin_headers, json={"name": "stack-overflow"}
    )
    assert duplicate.status_code == 409
    reserved = client.post("/api/v1/challenges/tags", headers=admin_headers, json={"name": "dynamic"})
    assert reserved.status_code == 422
    empty = client.post("/api/v1/challenges/tags", headers=admin_headers, json={"name": "---"})
    assert empty.status_code == 422
    assert client.post(
        "/api/v1/challenges/tags", headers=player_headers, json={"name": "cheat"}
    ).status_code == 403

    catalog = client.get("/api/v1/challenges/tags/catalog", headers=admin_headers).json()
    assert "stack-overflow" in {entry["name"] for entry in catalog}

    # the new tag can immediately be attached to a challenge
    challenge = client.post(
        "/api/v1/challenges",
        headers=admin_headers,
        json=_challenge_payload(slug="created-tag-target", tags=["stack-overflow"]),
    ).json()
    assert challenge["tags"] == ["stack-overflow", "static"]
    assert client.get("/api/v1/challenges?tag=stack-overflow", headers=admin_headers).json()


def test_tag_rename_and_delete(client, admin_headers):
    catalog = client.get("/api/v1/challenges/tags/catalog", headers=admin_headers).json()
    web = next(entry for entry in catalog if entry["name"] == "web")

    renamed = client.patch(
        f"/api/v1/challenges/tags/{web['id']}",
        headers=admin_headers,
        json={"name": "Web Security", "description": "Web 方向"},
    )
    assert renamed.status_code == 200
    assert renamed.json()["name"] == "web-security"

    reserved = client.patch(
        f"/api/v1/challenges/tags/{web['id']}", headers=admin_headers, json={"name": "dynamic"}
    )
    assert reserved.status_code == 422
    state_tag = client.patch(
        "/api/v1/challenges/tags/state:dynamic", headers=admin_headers, json={"name": "anything"}
    )
    assert state_tag.status_code == 422

    deleted = client.delete(f"/api/v1/challenges/tags/{web['id']}", headers=admin_headers)
    assert deleted.status_code == 200
    assert "web-security" not in {
        entry["name"] for entry in client.get("/api/v1/challenges/tags/catalog", headers=admin_headers).json()
    }


def test_players_read_the_catalog_but_cannot_edit_tags(client, admin_headers, player_headers):
    # players need the catalog to filter the challenge list
    assert client.get("/api/v1/challenges/tags/catalog", headers=player_headers).status_code == 200
    catalog = client.get("/api/v1/challenges/tags/catalog", headers=admin_headers).json()
    tag_id = next(entry["id"] for entry in catalog if entry["kind"] == "topic")
    assert client.patch(
        f"/api/v1/challenges/tags/{tag_id}", headers=player_headers, json={"name": "hacked"}
    ).status_code == 403
    assert client.delete(f"/api/v1/challenges/tags/{tag_id}", headers=player_headers).status_code == 403
    assert client.post(
        "/api/v1/challenges", headers=player_headers, json=_challenge_payload()
    ).status_code == 403


def test_build_warns_when_configured_port_differs_from_expose(client, admin_headers):
    challenge = client.post(
        "/api/v1/challenges",
        headers=admin_headers,
        json=_challenge_payload(slug="port-audit", internal_port=7989),
    ).json()
    archive = io.BytesIO()
    with ZipFile(archive, "w") as bundle:
        bundle.writestr("svc/Dockerfile", "FROM alpine:3.20\nEXPOSE 9999\nCMD [\"true\"]\n")
    built = client.post(
        f"/api/v1/challenges/{challenge['id']}/build?filename=svc.zip",
        headers={**admin_headers, "Content-Type": "application/zip"},
        content=archive.getvalue(),
    )
    assert built.status_code == 200
    body = built.json()
    assert body["detected_port"] == 9999
    assert body["internal_port"] == 7989
    assert body["port_warning"] and "9999" in body["port_warning"]

    assert "端口校验警告" in body["output"]
    detail = client.get(f"/api/v1/challenges/{challenge['id']}", headers=admin_headers).json()
    assert detail["detected_port"] == 9999


def test_build_without_port_mismatch_has_no_warning(client, admin_headers):
    challenge = client.post(
        "/api/v1/challenges",
        headers=admin_headers,
        json=_challenge_payload(slug="port-match", internal_port=9999),
    ).json()
    archive = io.BytesIO()
    with ZipFile(archive, "w") as bundle:
        bundle.writestr("svc/Dockerfile", "FROM alpine:3.20\nEXPOSE 9999\nCMD [\"true\"]\n")
    built = client.post(
        f"/api/v1/challenges/{challenge['id']}/build?filename=svc.zip",
        headers={**admin_headers, "Content-Type": "application/zip"},
        content=archive.getvalue(),
    ).json()
    assert built["port_warning"] is None


def test_instance_exposes_reachable_address_and_commands(client, player_headers):
    challenge = next(
        item
        for item in client.get("/api/v1/challenges?mode=ctf", headers=player_headers).json()
        if item["slug"] == "welcome-header"
    )
    started = client.post(f"/api/v1/instances/{challenge['id']}", headers=player_headers)
    assert started.status_code == 201
    body = started.json()
    # the fixture binds instances to 127.0.0.1, so that is what players are told to use
    assert body["public_host"] == "127.0.0.1"
    assert body["public_port"]
    assert body["listen_address"] == f"127.0.0.1:{body['public_port']}"
    assert body["access_url"] == f"http://127.0.0.1:{body['public_port']}"
    assert body["connect_command"] == f"nc 127.0.0.1 {body['public_port']}"

    fetched = client.get(f"/api/v1/instances/{body['id']}", headers=player_headers)
    assert fetched.status_code == 200
    assert fetched.json()["connect_command"] == body["connect_command"]


def test_build_progress_endpoint_reports_incremental_log_and_percent(client, admin_headers):
    challenge = client.post(
        "/api/v1/challenges",
        headers=admin_headers,
        json=_challenge_payload(slug="progress-probe"),
    ).json()
    # without a live build the endpoint returns the persisted state and finishes
    empty = client.get(f"/api/v1/challenges/{challenge['id']}/build/progress", headers=admin_headers)
    assert empty.status_code == 200
    body = empty.json()
    assert body["finished"] is True and body["data"] == "" and body["status"] == "none"

    from app.services.build_log import registry

    registry.start(challenge["id"])
    registry.append(challenge["id"], "Step 1/4 : FROM alpine:3.20\n")
    registry.append(challenge["id"], "Step 2/4 : COPY . .\n")

    first = client.get(
        f"/api/v1/challenges/{challenge['id']}/build/progress?cursor=0", headers=admin_headers
    ).json()
    assert first["finished"] is False
    assert "Step 2/4" in first["data"]
    assert first["percent"] == 50
    assert first["cursor"] == len(first["data"])

    second = client.get(
        f"/api/v1/challenges/{challenge['id']}/build/progress?cursor={first['cursor']}",
        headers=admin_headers,
    ).json()
    assert second["data"] == ""

    registry.append(challenge["id"], "Step 3/4 : RUN true\n")
    registry.finish(challenge["id"], "failed", "Step 3/4 : RUN true\nboom")
    final = client.get(
        f"/api/v1/challenges/{challenge['id']}/build/progress?cursor=0", headers=admin_headers
    ).json()
    assert final["finished"] is True and final["status"] == "failed"
    assert "boom" in final["data"]


def test_player_cannot_read_build_progress(client, admin_headers, player_headers):
    challenge = client.post(
        "/api/v1/challenges", headers=admin_headers, json=_challenge_payload(slug="progress-denied")
    ).json()
    assert client.get(
        f"/api/v1/challenges/{challenge['id']}/build/progress", headers=player_headers
    ).status_code == 403


def test_docker_build_adapts_to_the_available_builder(monkeypatch, tmp_path):
    import asyncio

    from app.services.docker import DockerService

    context = tmp_path / "ctx"
    context.mkdir()
    (context / "Dockerfile").write_text("FROM alpine:3.20\n")

    async def scenario(buildx_available: bool):
        service = DockerService(mode="cli")
        service._buildx = buildx_available
        captured: list[list[str]] = []

        async def fake_run_streaming(command, timeout, on_output=None):
            captured.append(command)
            return "ok"

        monkeypatch.setattr(service, "_run_streaming", fake_run_streaming)
        await service.build(context=context, image="demo:1")
        return captured[0]

    with_buildx = asyncio.run(scenario(True))
    assert "--progress" in with_buildx and with_buildx[with_buildx.index("--progress") + 1] == "plain"
    without_buildx = asyncio.run(scenario(False))
    assert "--progress" not in without_buildx
    assert without_buildx[:2] == ["docker", "build"]
    # cached base images must be reusable when the registry is unreachable
    assert "--pull" not in with_buildx and "--pull" not in without_buildx


def test_script_interpreter_follows_the_shebang(tmp_path):
    from app.services.assets import script_interpreter
    from app.services.docker import DockerService

    shell = tmp_path / "check.sh"
    shell.write_text("#!/bin/sh\necho ok\n")
    python = tmp_path / "check.py"
    python.write_text("#!/usr/bin/env python3\nprint('ok')\n")

    assert DockerService._script_command(shell, "/tmp/x") == ["/bin/sh", "/tmp/x"]
    assert DockerService._script_command(python, "/tmp/y") == ["python3", "/tmp/y"]
    assert script_interpreter(shell) == ["/bin/sh", "-n"]
    assert script_interpreter(python) == ["python3", "-m", "py_compile"]


def test_start_does_not_widen_the_configured_bind(monkeypatch):
    """The published address must not be broader than SYCL_INSTANCE_BIND_ADDRESS."""
    from app.services.docker import DockerService

    docker = DockerService(mode="cli")
    commands: list[list[str]] = []
    monkeypatch.setattr("app.services.docker.time.sleep", lambda _: None)

    def fake_run(command, timeout):
        commands.append(command)
        if command[1] == "run":
            return "cid123"
        if command[1] == "inspect":
            return '{"Status":"running","Running":true,"Restarting":false,"ExitCode":0}'
        return "127.0.0.1:40000\n"

    monkeypatch.setattr(docker, "_run", fake_run)
    docker.start(
        image="calc:1", internal_port=9999, name="sycl-test", user_id="u1", challenge_id="c1",
        bind_address="10.0.0.5",
    )
    assert "10.0.0.5::9999" in commands[0]


def test_instance_reports_the_address_it_is_published_on(client, player_headers):
    """The reported host must match the bind address, otherwise the UI lies."""
    from dataclasses import replace

    from app.api.routes.instances import _effective_public_host

    request = type("R", (), {"headers": {"host": "192.168.1.50:8080"}})()

    class FakeSettings:
        instance_public_host = "localhost"

    loopback = replace(client.app.state.settings, instance_bind_address="127.0.0.1")
    assert _effective_public_host(request, loopback) == "127.0.0.1"

    wildcard = replace(
        client.app.state.settings,
        instance_bind_address="0.0.0.0",
        instance_public_host="localhost",
    )
    assert _effective_public_host(request, wildcard) == "192.168.1.50"

    challenge_domain = replace(wildcard, instance_public_host="challenge.sycsec.com")
    assert _effective_public_host(request, challenge_domain) == "challenge.sycsec.com"

    concrete = replace(client.app.state.settings, instance_bind_address="10.0.0.5")
    assert _effective_public_host(request, concrete) == "10.0.0.5"


def test_build_registry_keeps_progress_and_final_output():
    registry = BuildRegistry()
    registry.start("challenge-1")
    registry.append("challenge-1", "Step 1/3 : FROM alpine\n")
    registry.append("challenge-1", "Step 2/3 : COPY . .\n")

    running = registry.snapshot("challenge-1")
    assert running is not None and not running.finished
    assert "Step 2/3" in running.log

    registry.finish("challenge-1", "failed", "boom")
    finished = registry.snapshot("challenge-1")
    assert finished is not None and finished.finished
    assert finished.status == "failed"
    assert finished.log.strip() == "boom"

    registry.append("challenge-1", "late line that must be ignored\n")
    assert "late line" not in (registry.snapshot("challenge-1").log)


def test_build_registry_truncates_very_long_logs():
    registry = BuildRegistry()
    registry.start("challenge-2")
    for _ in range(400):
        registry.append("challenge-2", "x" * 2_000 + "\n")
    snapshot = registry.snapshot("challenge-2")
    assert snapshot is not None and snapshot.truncated
    assert len(snapshot.log) < 500_000


def test_slugify_tag_normalizes_input():
    assert slugify_tag("  SQL Injection ") == "sql-injection"
    assert slugify_tag("Web/API") == "web-api"
    assert slugify_tag("---") == ""
