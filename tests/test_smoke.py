"""Smoke tests for the ButtrBase SDK."""
from __future__ import annotations

import hmac
import hashlib
import os
import time
import uuid

import pytest

from buttrbase import ButtrbaseClient, ButtrbaseError, webhooks

SMOKE_BASE = os.environ.get("BUTTRBASE_SMOKE_API", "https://stagingapi.buttrbase.com")
RUN_SMOKE = os.environ.get("BUTTRBASE_SMOKE", "1") != "0"

skip_if_no_net = pytest.mark.skipif(
    not RUN_SMOKE, reason="set BUTTRBASE_SMOKE=1 to run live smoke tests"
)


@pytest.fixture
def client() -> ButtrbaseClient:
    return ButtrbaseClient(api_key="", base_url=SMOKE_BASE, timeout=10.0)


@skip_if_no_net
def test_validate_coupon_nonexistent(client: ButtrbaseClient) -> None:
    try:
        result = client.validate_coupon("NONEXISTENT")
    except ButtrbaseError as e:
        assert e.status_code is not None
        return
    assert isinstance(result, dict)
    assert result.get("valid") is False
    assert "error" in result or "message" in result or "reason" in result


@skip_if_no_net
def test_validate_gift_card_nonexistent(client: ButtrbaseClient) -> None:
    try:
        result = client.validate_gift_card("NONEXISTENT")
    except ButtrbaseError as e:
        assert e.status_code is not None
        return
    assert isinstance(result, dict)
    assert result.get("valid") is False


@skip_if_no_net
def test_org_jwks(client: ButtrbaseClient) -> None:
    fake_uuid = str(uuid.uuid4())
    try:
        result = client.org_jwks(fake_uuid)
    except ButtrbaseError as e:
        assert e.status_code in (404, 400)
        return
    assert isinstance(result, dict)
    assert "keys" in result


@skip_if_no_net
def test_get_tenant_home_nonexistent(client: ButtrbaseClient) -> None:
    fake_uuid = str(uuid.uuid4())
    try:
        result = client.get_tenant_home(fake_uuid)
    except ButtrbaseError as e:
        # Unknown / non-active tenant -> 404.
        assert e.status_code in (404, 400)
        return
    assert isinstance(result, dict)
    assert "tenancy_mode" in result


# ---------------------------------------------------------------------------
# Offline tests for the zero-trust client methods. These stub the HTTP layer
# so we can assert request shaping (path / body / params / envelope unwrap)
# without a live backend.
# ---------------------------------------------------------------------------


class _FakeResp:
    def __init__(self, status_code: int, payload: object) -> None:
        self.status_code = status_code
        self._payload = payload
        self.content = b"x"

    def json(self) -> object:
        return self._payload


def _stub_session(client: ButtrbaseClient, captured: dict, payload: object,
                  status: int = 200) -> None:
    def _request(method, url, json=None, params=None, headers=None, timeout=None):
        captured["method"] = method
        captured["url"] = url
        captured["json"] = json
        captured["params"] = params
        captured["headers"] = headers
        return _FakeResp(status, payload)

    client._session.request = _request  # type: ignore[assignment]


def test_scope_context_request_and_token_stash() -> None:
    client = ButtrbaseClient(api_key="old-token", base_url="https://x")
    captured: dict = {}
    _stub_session(
        client, captured, {"token": "new-token", "scopes": ["a", "b"]}
    )
    resp = client.scope_context(["b", "a"])
    assert captured["method"] == "POST"
    assert captured["url"].endswith("/api/app/auth/scope-context")
    assert captured["json"] == {"requested_scopes": ["b", "a"]}
    assert captured["headers"]["Authorization"] == "Bearer old-token"
    assert resp == {"token": "new-token", "scopes": ["a", "b"]}
    # New windowed token is stashed back onto the client.
    assert client.api_key == "new-token"


def test_list_devices_unwraps_data_envelope() -> None:
    client = ButtrbaseClient(api_key="t", base_url="https://x")
    captured: dict = {}
    rows = [
        {
            "device_uuid": "d1",
            "jkt": "thumb",
            "label": "laptop",
            "created_at": "2026-01-01T00:00:00Z",
            "last_seen_at": None,
        }
    ]
    _stub_session(client, captured, {"data": rows})
    result = client.list_devices()
    assert captured["method"] == "GET"
    assert captured["url"].endswith("/api/app/devices")
    assert result == rows


def test_revoke_device_path_and_unwrap() -> None:
    client = ButtrbaseClient(api_key="t", base_url="https://x")
    captured: dict = {}
    _stub_session(
        client, captured, {"data": {"device_uuid": "d1", "revoked": True}}
    )
    result = client.revoke_device("d1")
    assert captured["method"] == "POST"
    assert captured["url"].endswith("/api/app/devices/d1/revoke")
    assert result == {"device_uuid": "d1", "revoked": True}


def test_get_tenant_home_params_and_anonymous() -> None:
    client = ButtrbaseClient(api_key="t", base_url="https://x")
    captured: dict = {}
    _stub_session(
        client,
        captured,
        {"data": {"tenancy_mode": "shared", "home_region": None,
                  "home_base_url": None}},
    )
    result = client.get_tenant_home("org-1", app_id=7)
    assert captured["method"] == "GET"
    assert captured["url"].endswith("/api/tenant/home")
    assert captured["params"] == {"org_uuid": "org-1", "app_id": 7}
    # Public endpoint: no Authorization header is sent.
    assert "Authorization" not in captured["headers"]
    assert result["tenancy_mode"] == "shared"


def test_webhook_round_trip() -> None:
    body = b'{"event":"ping","data":{"x":1}}'
    secret = "shh-it-is-a-secret"
    ts = str(int(time.time()))
    expected = hmac.new(
        secret.encode(), f"{ts}.".encode() + body, hashlib.sha256
    ).hexdigest()
    assert webhooks.verify_signature(body, expected, ts, secret) is True
    assert webhooks.verify_signature(body, "sha256=" + expected, ts, secret) is True
    assert webhooks.verify_signature(body, expected, ts, "wrong-secret") is False
    old_ts = str(int(time.time()) - 10_000)
    old_sig = hmac.new(
        secret.encode(), f"{old_ts}.".encode() + body, hashlib.sha256
    ).hexdigest()
    assert webhooks.verify_signature(body, old_sig, old_ts, secret) is False
