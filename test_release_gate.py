from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

GOOD_SHA = "a" * 40

SAFE_PAYLOAD = {
    "target": "preview",
    "event": "pull_request",
    "ref": "refs/heads/feature-x",
    "workflow": {
        "trigger": "pull_request",
        "permissions": {"contents": "read", "packages": "write", "id-token": "none"},
        "testsPassed": True,
        "matrixComplete": True,
        "failFast": False,
        "actions": [
            {"owner": "actions", "name": "checkout", "ref": "v4"},
            {"owner": "docker", "name": "build-push-action", "ref": GOOD_SHA},
        ],
    },
    "image": {
        "multiStage": True,
        "runsAsRoot": False,
        "secretMode": "buildkit",
        "criticalVulnerabilities": 0,
        "digestPinned": True,
    },
}


def test_safe_preview_promotes():
    r = client.post("/release-gate", json=SAFE_PAYLOAD)
    assert r.status_code == 200
    body = r.json()
    assert body["decision"] == "promote"
    assert body["violations"] == []


def test_safe_production_needs_ref_and_approval():
    payload = {
        **SAFE_PAYLOAD,
        "target": "production",
        "event": "push",
        "ref": "refs/heads/main",
        "workflow": {**SAFE_PAYLOAD["workflow"], "environmentApproval": True},
    }
    r = client.post("/release-gate", json=payload)
    body = r.json()
    assert body["decision"] == "promote"
    assert body["violations"] == []


def test_production_missing_approval_blocks():
    payload = {
        **SAFE_PAYLOAD,
        "target": "production",
        "event": "push",
        "ref": "refs/heads/main",
    }
    r = client.post("/release-gate", json=payload)
    body = r.json()
    assert body["decision"] == "block"
    assert "APPROVAL_REQUIRED" in body["violations"]


def test_multi_failure_payload():
    payload = {
        "target": "production",
        "event": "pull_request",
        "ref": "refs/heads/feature-x",
        "workflow": {
            "trigger": "pull_request_target",
            "permissions": {"contents": "read", "packages": "write", "id-token": "write"},
            "testsPassed": False,
            "matrixComplete": False,
            "failFast": True,
            "actions": [
                {"owner": "actions", "name": "checkout", "ref": "v4"},
                {"owner": "someorg", "name": "some-action", "ref": "main"},
            ],
        },
        "image": {
            "multiStage": False,
            "runsAsRoot": True,
            "secretMode": "arg",
            "criticalVulnerabilities": 2,
            "digestPinned": False,
        },
    }
    r = client.post("/release-gate", json=payload)
    body = r.json()
    assert body["decision"] == "block"
    expected = {
        "EXCESS_PERMISSION",
        "UNSAFE_PR_TRIGGER",
        "TESTS_INCOMPLETE",
        "MUTABLE_ACTION",
        "SINGLE_STAGE_IMAGE",
        "ROOT_RUNTIME",
        "SECRET_IN_LAYER",
        "CRITICAL_CVE",
        "UNPINNED_IMAGE",
        "INVALID_PRODUCTION_REF",
        "APPROVAL_REQUIRED",
    }
    assert set(body["violations"]) == expected


def test_first_party_action_tag_is_fine():
    payload = SAFE_PAYLOAD
    r = client.post("/release-gate", json=payload)
    assert "MUTABLE_ACTION" not in r.json()["violations"]


def test_third_party_uppercase_sha_rejected():
    payload = {
        **SAFE_PAYLOAD,
        "workflow": {
            **SAFE_PAYLOAD["workflow"],
            "actions": [
                {"owner": "actions", "name": "checkout", "ref": "v4"},
                {"owner": "docker", "name": "build-push-action", "ref": "A" * 40},
            ],
        },
    }
    r = client.post("/release-gate", json=payload)
    assert "MUTABLE_ACTION" in r.json()["violations"]
