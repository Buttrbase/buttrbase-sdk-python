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
        assert e.status_code in (400, 403, 404)
        return
    assert isinstance(result, dict)
    assert "keys" in result


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
