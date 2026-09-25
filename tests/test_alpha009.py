from app.core.database import Database


def test_announcements_are_managed_by_admins_and_drafts_are_private(client, admin_headers, player_headers):
    base = "/api/v1/announcements"
    assert client.post(base, headers=player_headers, json={
        "title": "Denied", "content": "No permission", "status": "published",
    }).status_code == 403
    created = client.post(base, headers=admin_headers, json={
        "title": "Maintenance", "content": "Scheduled for Friday.", "status": "draft",
    })
    assert created.status_code == 201
    item_id = created.json()["id"]
    assert client.get(base, headers=player_headers).json() == []
    assert len(client.get(base, headers=admin_headers).json()) == 1
    assert client.patch(f"{base}/{item_id}", headers=player_headers, json={"status": "published"}).status_code == 403
    published = client.patch(f"{base}/{item_id}", headers=admin_headers, json={
        "title": "New schedule", "status": "published",
    })
    assert published.status_code == 200
    assert client.get(base, headers=player_headers).json()[0]["title"] == "New schedule"
    assert client.delete(f"{base}/{item_id}", headers=player_headers).status_code == 403
    assert client.delete(f"{base}/{item_id}", headers=admin_headers).status_code == 200
    assert client.get(base, headers=player_headers).json() == []


def test_collections_hide_drafts_and_unpublished_members_and_keep_order(client, admin_headers, player_headers):
    challenges = client.get("/api/v1/challenges", headers=admin_headers).json()
    first, second = challenges[:2]
    base = "/api/v1/collections"
    payload = {
        "title": "Web Basics", "slug": "web-basics", "description": "Start with the basics.",
        "status": "draft", "challenge_ids": [second["id"], first["id"]],
    }
    assert client.post(base, headers=player_headers, json=payload).status_code == 403
    created = client.post(base, headers=admin_headers, json=payload)
    assert created.status_code == 201
    collection_id = created.json()["id"]
    assert created.json()["challenge_ids"] == payload["challenge_ids"]
    assert client.get(base, headers=player_headers).json() == []
    assert client.get(f"{base}/{collection_id}", headers=player_headers).status_code == 404
    assert client.post(base, headers=admin_headers, json={**payload, "slug": "duplicate-members",
                                                         "challenge_ids": [first["id"], first["id"]]}).status_code == 422
    assert client.patch(f"{base}/{collection_id}", headers=admin_headers, json={"status": "published"}).status_code == 200
    assert client.get(f"{base}/{collection_id}", headers=player_headers).json()["challenge_ids"] == payload["challenge_ids"]
    assert client.patch(f"/api/v1/challenges/{second['id']}", headers=admin_headers,
                        json={"status": "draft"}).status_code == 200
    assert client.get(f"{base}/{collection_id}", headers=player_headers).json()["challenge_ids"] == [first["id"]]
    assert client.patch(f"{base}/{collection_id}", headers=player_headers,
                        json={"title": "No"}).status_code == 403
    assert client.delete(f"/api/v1/challenges/{second['id']}", headers=admin_headers).status_code == 200
    assert client.get(f"{base}/{collection_id}", headers=admin_headers).json()["challenge_ids"] == [first["id"]]
    assert client.delete(f"{base}/{collection_id}", headers=admin_headers).status_code == 200


def test_custom_achievement_lifecycle_and_builtin_protection(client, admin_headers, player_headers, settings):
    base = "/api/v1/achievements"
    payload = {
        "slug": "night_owl", "name": "Night Owl", "description": "Training after dark",
        "acquisition": "Administrator award", "icon": "core",
    }
    assert client.post(base, headers=player_headers, json=payload).status_code == 403
    created = client.post(base, headers=admin_headers, json=payload)
    assert created.status_code == 201
    assert created.json()["is_builtin"] is False
    assert client.patch(f"{base}/night_owl", headers=admin_headers, json={"name": "夜猫子"}).json()["name"] == "夜猫子"
    assert client.patch(f"{base}/first_solve", headers=admin_headers, json={
        "description": "管理员自定义的说明",
    }).status_code == 200
    database = Database(settings.database_path)
    database.initialize()
    assert next(item for item in client.get(base, headers=admin_headers).json()
                if item["slug"] == "night_owl")["name"] == "夜猫子"
    assert next(item for item in client.get(base, headers=admin_headers).json()
                if item["slug"] == "first_solve")["description"] == "管理员自定义的说明"
    assert client.delete(f"{base}/first_solve", headers=admin_headers).status_code == 409
    user_id = client.get("/api/v1/users/me/profile", headers=player_headers).json()["id"]
    path = f"/api/v1/users/{user_id}/achievements/night_owl"
    assert client.post(path, headers=admin_headers).status_code == 200
    assert client.delete(f"{base}/night_owl", headers=admin_headers).status_code == 409
    assert client.delete(path, headers=admin_headers).status_code == 200
    assert client.delete(f"{base}/night_owl", headers=admin_headers).status_code == 200


def test_tag_order_and_deleting_an_attached_tag(client, admin_headers, player_headers):
    tag = client.post("/api/v1/challenges/tags", headers=admin_headers, json={
        "name": "heap", "description": "Heap exploitation", "sort_order": 5,
    }).json()
    assert tag["sort_order"] == 5
    challenge = client.get("/api/v1/challenges", headers=admin_headers).json()[0]
    updated = client.patch(f"/api/v1/challenges/{challenge['id']}", headers=admin_headers,
                           json={"tags": ["heap"]})
    assert updated.status_code == 200
    assert client.get("/api/v1/challenges/tags/catalog", headers=player_headers).status_code == 200
    assert client.patch(f"/api/v1/challenges/tags/{tag['id']}", headers=admin_headers,
                        json={"sort_order": 3}).json()["sort_order"] == 3
    assert client.delete(f"/api/v1/challenges/tags/{tag['id']}", headers=admin_headers).status_code == 200
    assert "heap" not in client.get(f"/api/v1/challenges/{challenge['id']}", headers=admin_headers).json()["tags"]
    draft = client.post("/api/v1/challenges", headers=admin_headers, json={
        "title": "Private Tag Target", "slug": "private-tag-target",
        "description": "A draft challenge with a secret tag.", "category": "Web",
        "mode": "ctf", "difficulty": "easy", "points": 100, "flag": "SYC{private}",
        "status": "draft", "tags": ["future-topic"],
    })
    assert draft.status_code == 201
    assert "future-topic" in {
        item["name"] for item in client.get("/api/v1/challenges/tags/catalog", headers=admin_headers).json()
    }
    assert "future-topic" not in {
        item["name"] for item in client.get("/api/v1/challenges/tags/catalog", headers=player_headers).json()
    }
