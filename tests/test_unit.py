"""Unit tests for ButtrBase SDK — client, webhooks, types, errors."""
from __future__ import annotations

import time
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from buttrbase import ButtrbaseClient, ButtrbaseError
from buttrbase import webhooks
from buttrbase.types import (
    Credential,
    CreateCredentialResponse,
    RotateSecretResponse,
    SandboxResetResponse,
    InviteAcceptResponse,
    OrgCheckResponse,
    SuperuserResponse,
    ContactSubmitResponse,
    GeoResponse,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_response(status_code: int, body: Any = None, content: bytes = b"{}") -> MagicMock:
    """Return a mock requests.Response-like object."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.content = content if content is not None else b""
    resp.json.return_value = body
    return resp


def _make_client(api_key: str = "test-key") -> ButtrbaseClient:
    return ButtrbaseClient(api_key=api_key, base_url="https://example.com", timeout=5.0)


# ---------------------------------------------------------------------------
# ButtrbaseError
# ---------------------------------------------------------------------------

class TestButtrbaseError:
    def test_default_attrs(self):
        err = ButtrbaseError("bad")
        assert str(err) == "bad"
        assert err.status_code is None
        assert err.code is None
        assert err.detail is None

    def test_all_attrs(self):
        err = ButtrbaseError("oops", status_code=422, code="VALIDATION", detail={"field": "email"})
        assert err.status_code == 422
        assert err.code == "VALIDATION"
        assert err.detail == {"field": "email"}

    def test_repr(self):
        err = ButtrbaseError("oops", status_code=500, code="SERVER_ERROR", detail="boom")
        r = repr(err)
        assert "500" in r
        assert "SERVER_ERROR" in r
        assert "boom" in r


# ---------------------------------------------------------------------------
# ButtrbaseClient — _handle
# ---------------------------------------------------------------------------

class TestHandle:
    """Unit-test the static _handle method directly."""

    def test_200_returns_body(self):
        resp = _make_response(200, {"ok": True})
        assert ButtrbaseClient._handle(resp) == {"ok": True}

    def test_204_no_content_returns_empty_dict(self):
        resp = _make_response(204, None, content=b"")
        assert ButtrbaseClient._handle(resp) == {}

    def test_201_returns_body(self):
        resp = _make_response(201, {"id": "abc"})
        assert ButtrbaseClient._handle(resp) == {"id": "abc"}

    def test_200_with_none_body_returns_empty_dict(self):
        # content is truthy but json() returns None
        resp = _make_response(200, None, content=b"null")
        assert ButtrbaseClient._handle(resp) == {}

    def test_invalid_json_gives_none_body_and_raises_on_error(self):
        resp = _make_response(200, None, content=b"not-json")
        resp.json.side_effect = ValueError("No JSON")
        # 200 with None body → returns {}
        assert ButtrbaseClient._handle(resp) == {}

    def test_4xx_plain_raises(self):
        resp = _make_response(400, None, content=b"")
        with pytest.raises(ButtrbaseError) as exc_info:
            ButtrbaseClient._handle(resp)
        assert exc_info.value.status_code == 400

    def test_4xx_json_dict_raises_with_parsed_fields(self):
        body = {"message": "not found", "code": "NOT_FOUND", "detail": "item missing"}
        resp = _make_response(404, body)
        with pytest.raises(ButtrbaseError) as exc_info:
            ButtrbaseClient._handle(resp)
        err = exc_info.value
        assert err.status_code == 404
        assert err.code == "NOT_FOUND"
        assert err.detail == "item missing"

    def test_4xx_json_with_error_field(self):
        body = {"error": "bad_request"}
        resp = _make_response(400, body)
        with pytest.raises(ButtrbaseError) as exc_info:
            ButtrbaseClient._handle(resp)
        err = exc_info.value
        assert err.code == "bad_request"

    def test_5xx_raises(self):
        resp = _make_response(500, {"message": "internal server error"})
        with pytest.raises(ButtrbaseError) as exc_info:
            ButtrbaseClient._handle(resp)
        assert exc_info.value.status_code == 500

    def test_invalid_json_on_error_raises_with_status(self):
        resp = _make_response(503, None, content=b"not-json")
        resp.json.side_effect = ValueError("bad json")
        with pytest.raises(ButtrbaseError) as exc_info:
            ButtrbaseClient._handle(resp)
        assert exc_info.value.status_code == 503

    def test_4xx_body_is_list_not_dict(self):
        """Non-dict JSON body on error path."""
        resp = _make_response(422, ["err1", "err2"])
        with pytest.raises(ButtrbaseError) as exc_info:
            ButtrbaseClient._handle(resp)
        err = exc_info.value
        assert err.status_code == 422
        assert err.detail == ["err1", "err2"]


# ---------------------------------------------------------------------------
# ButtrbaseClient — _headers
# ---------------------------------------------------------------------------

class TestHeaders:
    def test_with_auth(self):
        client = _make_client("my-key")
        h = client._headers(auth=True)
        assert h["Authorization"] == "Bearer my-key"
        assert h["Accept"] == "application/json"

    def test_without_auth(self):
        client = _make_client("my-key")
        h = client._headers(auth=False)
        assert "Authorization" not in h

    def test_empty_api_key_no_auth_header(self):
        client = _make_client("")
        h = client._headers(auth=True)
        assert "Authorization" not in h

    def test_base_url_trailing_slash_stripped(self):
        client = ButtrbaseClient(api_key="k", base_url="https://example.com/")
        assert client.base_url == "https://example.com"


# ---------------------------------------------------------------------------
# Coupon endpoints
# ---------------------------------------------------------------------------

class TestCouponEndpoints:
    def setup_method(self):
        self.client = _make_client()

    def _patch(self):
        return patch.object(self.client._session, "request")

    def test_validate_coupon_minimal(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, {"valid": True})
            result = self.client.validate_coupon("PROMO10")
        assert result == {"valid": True}
        call_kwargs = mock_req.call_args
        assert call_kwargs[1]["json"] == {"code": "PROMO10"}

    def test_validate_coupon_with_cart_labels_and_product_id(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, {"valid": True})
            self.client.validate_coupon("PROMO10", cart_labels=["label1"], product_id=42)
        sent = mock_req.call_args[1]["json"]
        assert sent["cart_labels"] == ["label1"]
        assert sent["product_id"] == 42

    def test_validate_coupon_4xx(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(400, {"message": "invalid code"})
            with pytest.raises(ButtrbaseError) as exc_info:
                self.client.validate_coupon("BAD")
        assert exc_info.value.status_code == 400

    def test_validate_coupon_5xx(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(500, {"message": "server error"})
            with pytest.raises(ButtrbaseError):
                self.client.validate_coupon("X")


# ---------------------------------------------------------------------------
# Gift card endpoints
# ---------------------------------------------------------------------------

class TestGiftCardEndpoints:
    def setup_method(self):
        self.client = _make_client()

    def _patch(self):
        return patch.object(self.client._session, "request")

    def test_validate_gift_card_ok(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, {"valid": True, "balance_cents": 5000})
            result = self.client.validate_gift_card("GC-123")
        assert result["balance_cents"] == 5000

    def test_validate_gift_card_error(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(404, {"message": "not found"})
            with pytest.raises(ButtrbaseError):
                self.client.validate_gift_card("NOPE")

    def test_redeem_gift_card_minimal(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, {"redeemed": True})
            result = self.client.redeem_gift_card("GC-123", amount_cents=1000)
        assert result == {"redeemed": True}
        sent = mock_req.call_args[1]["json"]
        assert sent == {"code": "GC-123", "amount_cents": 1000}

    def test_redeem_gift_card_with_user_id(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, {"redeemed": True})
            self.client.redeem_gift_card("GC-123", amount_cents=500, user_id=7)
        sent = mock_req.call_args[1]["json"]
        assert sent["user_id"] == 7

    def test_redeem_gift_card_error(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(422, {"message": "insufficient balance"})
            with pytest.raises(ButtrbaseError):
                self.client.redeem_gift_card("GC-123", amount_cents=9999999)


# ---------------------------------------------------------------------------
# Magic link endpoints
# ---------------------------------------------------------------------------

class TestMagicLinkEndpoints:
    def setup_method(self):
        self.client = _make_client()

    def _patch(self):
        return patch.object(self.client._session, "request")

    def test_send_magic_link_minimal(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, {"sent": True})
            result = self.client.send_magic_link("user@example.com")
        assert result == {"sent": True}
        sent = mock_req.call_args[1]["json"]
        assert sent == {"email": "user@example.com"}

    def test_send_magic_link_with_org_and_redirect(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, {"sent": True})
            self.client.send_magic_link(
                "user@example.com",
                org_uuid="org-uuid-123",
                redirect_to="https://example.com/dashboard",
            )
        sent = mock_req.call_args[1]["json"]
        assert sent["org_uuid"] == "org-uuid-123"
        assert sent["redirect_to"] == "https://example.com/dashboard"

    def test_send_magic_link_error(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(400, {"message": "bad email"})
            with pytest.raises(ButtrbaseError):
                self.client.send_magic_link("not-an-email")

    def test_verify_magic_link_ok(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, {"user_id": 1})
            result = self.client.verify_magic_link("tok-abc")
        assert result == {"user_id": 1}

    def test_verify_magic_link_error(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(401, {"message": "invalid token"})
            with pytest.raises(ButtrbaseError):
                self.client.verify_magic_link("bad-tok")


# ---------------------------------------------------------------------------
# MFA endpoints
# ---------------------------------------------------------------------------

class TestMFAEndpoints:
    def setup_method(self):
        self.client = _make_client()

    def _patch(self):
        return patch.object(self.client._session, "request")

    def test_mfa_status_ok(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, {"enabled": False})
            result = self.client.mfa_status()
        assert result == {"enabled": False}

    def test_mfa_status_error(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(401, {"message": "unauthorized"})
            with pytest.raises(ButtrbaseError):
                self.client.mfa_status()

    def test_mfa_enroll_no_label(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, {"qr_code": "data:image/png;base64,..."})
            result = self.client.mfa_enroll()
        sent = mock_req.call_args[1]["json"]
        assert sent == {}

    def test_mfa_enroll_with_label(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, {"qr_code": "..."})
            self.client.mfa_enroll(label="My Phone")
        sent = mock_req.call_args[1]["json"]
        assert sent["label"] == "My Phone"

    def test_mfa_enroll_error(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(409, {"message": "already enrolled"})
            with pytest.raises(ButtrbaseError):
                self.client.mfa_enroll()

    def test_mfa_activate_ok(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, {"activated": True})
            result = self.client.mfa_activate("123456")
        assert result == {"activated": True}

    def test_mfa_activate_error(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(400, {"message": "invalid code"})
            with pytest.raises(ButtrbaseError):
                self.client.mfa_activate("000000")


# ---------------------------------------------------------------------------
# Org signing endpoints
# ---------------------------------------------------------------------------

class TestOrgSigningEndpoints:
    def setup_method(self):
        self.client = _make_client()

    def _patch(self):
        return patch.object(self.client._session, "request")

    def test_org_sign_minimal(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, {"token": "signed-jwt"})
            result = self.client.org_sign("org-uuid", {"sub": "user-1"})
        assert result == {"token": "signed-jwt"}
        sent = mock_req.call_args[1]["json"]
        assert sent == {"claims": {"sub": "user-1"}}

    def test_org_sign_with_ttl(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, {"token": "jwt"})
            self.client.org_sign("org-uuid", {"sub": "user-1"}, ttl_seconds=3600)
        sent = mock_req.call_args[1]["json"]
        assert sent["ttl_seconds"] == 3600

    def test_org_sign_error(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(403, {"message": "forbidden"})
            with pytest.raises(ButtrbaseError):
                self.client.org_sign("org-uuid", {})

    def test_org_jwks_ok(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, {"keys": []})
            result = self.client.org_jwks("org-uuid")
        assert result == {"keys": []}

    def test_org_jwks_error(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(404, {"message": "not found"})
            with pytest.raises(ButtrbaseError):
                self.client.org_jwks("no-such-org")


# ---------------------------------------------------------------------------
# Secrets endpoints
# ---------------------------------------------------------------------------

class TestSecretsEndpoints:
    def setup_method(self):
        self.client = _make_client()

    def _patch(self):
        return patch.object(self.client._session, "request")

    def test_get_secret_ok(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, {"name": "DB_PASS", "value": "secret"})
            result = self.client.get_secret("org-uuid", "DB_PASS")
        assert result["value"] == "secret"

    def test_get_secret_error(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(404, {"message": "not found"})
            with pytest.raises(ButtrbaseError):
                self.client.get_secret("org-uuid", "MISSING")

    def test_put_secret_minimal(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, {"name": "KEY", "value": "val"})
            self.client.put_secret("org-uuid", "KEY", "val")
        sent = mock_req.call_args[1]["json"]
        assert sent == {"value": "val"}

    def test_put_secret_with_description(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, {"name": "KEY", "value": "val"})
            self.client.put_secret("org-uuid", "KEY", "val", description="my secret")
        sent = mock_req.call_args[1]["json"]
        assert sent["description"] == "my secret"

    def test_put_secret_error(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(422, {"message": "validation error"})
            with pytest.raises(ButtrbaseError):
                self.client.put_secret("org-uuid", "KEY", "val")


# ---------------------------------------------------------------------------
# Step-up auth
# ---------------------------------------------------------------------------

class TestStepUpAuth:
    def setup_method(self):
        self.client = _make_client("original-key")

    def _patch(self):
        return patch.object(self.client._session, "request")

    def test_step_up_replaces_api_key(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, {"access_token": "elevated-key"})
            result = self.client.auth_step_up("123456")
        assert result["access_token"] == "elevated-key"
        # api_key should be replaced
        assert self.client.api_key == "elevated-key"

    def test_step_up_no_access_token_does_not_replace_key(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, {"status": "ok"})
            self.client.auth_step_up("123456")
        assert self.client.api_key == "original-key"

    def test_step_up_with_recovery(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, {"access_token": "new-key"})
            self.client.auth_step_up("recovery-code", recovery=True)
        sent = mock_req.call_args[1]["json"]
        assert sent["recovery"] is True

    def test_step_up_error(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(401, {"message": "invalid code"})
            with pytest.raises(ButtrbaseError):
                self.client.auth_step_up("wrong")


# ---------------------------------------------------------------------------
# Elevation endpoints
# ---------------------------------------------------------------------------

class TestElevationEndpoints:
    def setup_method(self):
        self.client = _make_client()

    def _patch(self):
        return patch.object(self.client._session, "request")

    def test_elevation_request_minimal(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, {"grant_uuid": "g-123"})
            result = self.client.elevation_request("org-uuid", "admin:read")
        assert result["grant_uuid"] == "g-123"
        sent = mock_req.call_args[1]["json"]
        assert sent == {"scope": "admin:read"}

    def test_elevation_request_with_reason_and_ttl(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, {"grant_uuid": "g-456"})
            self.client.elevation_request(
                "org-uuid", "admin:write", reason="emergency", ttl_seconds=600
            )
        sent = mock_req.call_args[1]["json"]
        assert sent["reason"] == "emergency"
        assert sent["ttl_seconds"] == 600

    def test_elevation_request_error(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(403, {"message": "forbidden"})
            with pytest.raises(ButtrbaseError):
                self.client.elevation_request("org-uuid", "admin:delete")

    def test_elevation_approve_ok(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, {"status": "approved"})
            result = self.client.elevation_approve("org-uuid", "g-123")
        assert result == {"status": "approved"}

    def test_elevation_approve_403_self_approve(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(403, {"message": "cannot self-approve"})
            with pytest.raises(ButtrbaseError) as exc_info:
                self.client.elevation_approve("org-uuid", "g-123")
        assert exc_info.value.status_code == 403

    def test_elevation_list_no_status(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, [{"grant_uuid": "g-1"}])
            result = self.client.elevation_list("org-uuid")
        assert result == [{"grant_uuid": "g-1"}]
        call_kwargs = mock_req.call_args[1]
        # no status filter → params should be None or empty
        assert call_kwargs.get("params") is None

    def test_elevation_list_with_status(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, [])
            self.client.elevation_list("org-uuid", status="pending")
        call_kwargs = mock_req.call_args[1]
        assert call_kwargs["params"] == {"status": "pending"}

    def test_elevation_list_error(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(401, {"message": "unauthorized"})
            with pytest.raises(ButtrbaseError):
                self.client.elevation_list("org-uuid")


# ---------------------------------------------------------------------------
# SPIFFE endpoints
# ---------------------------------------------------------------------------

class TestSpiffeEndpoints:
    def setup_method(self):
        self.client = _make_client()

    def _patch(self):
        return patch.object(self.client._session, "request")

    def test_spiffe_issue_svid_minimal(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, {"svid": "cert-data"})
            result = self.client.spiffe_issue_svid("org-uuid", "/ns/default/sa/worker")
        assert result == {"svid": "cert-data"}
        sent = mock_req.call_args[1]["json"]
        assert sent == {"workload_path": "/ns/default/sa/worker"}

    def test_spiffe_issue_svid_with_ttl(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, {"svid": "cert-data"})
            self.client.spiffe_issue_svid("org-uuid", "/ns/default/sa/worker", ttl_seconds=3600)
        sent = mock_req.call_args[1]["json"]
        assert sent["ttl_seconds"] == 3600

    def test_spiffe_issue_svid_error(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(403, {"message": "not allowed"})
            with pytest.raises(ButtrbaseError):
                self.client.spiffe_issue_svid("org-uuid", "/bad/path")


# ---------------------------------------------------------------------------
# Auth events
# ---------------------------------------------------------------------------

class TestAuthEventsEndpoints:
    def setup_method(self):
        self.client = _make_client()

    def _patch(self):
        return patch.object(self.client._session, "request")

    def test_list_auth_events_default(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, [{"event": "login"}])
            result = self.client.list_auth_events("org-uuid")
        assert result == [{"event": "login"}]
        call_kwargs = mock_req.call_args[1]
        assert call_kwargs["params"]["limit"] == 50

    def test_list_auth_events_with_user_uuid(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, [])
            self.client.list_auth_events("org-uuid", user_uuid="user-1", limit=10)
        call_kwargs = mock_req.call_args[1]
        assert call_kwargs["params"]["user_uuid"] == "user-1"
        assert call_kwargs["params"]["limit"] == 10

    def test_list_auth_events_error(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(403, {"message": "forbidden"})
            with pytest.raises(ButtrbaseError):
                self.client.list_auth_events("org-uuid")


# ---------------------------------------------------------------------------
# Re-encrypt endpoints
# ---------------------------------------------------------------------------

class TestReencryptEndpoints:
    def setup_method(self):
        self.client = _make_client()

    def _patch(self):
        return patch.object(self.client._session, "request")

    def test_reencrypt_secrets_ok(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, {"status": "done"})
            result = self.client.reencrypt_secrets("org-uuid")
        assert result == {"status": "done"}

    def test_reencrypt_secrets_error(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(500, {"message": "internal error"})
            with pytest.raises(ButtrbaseError):
                self.client.reencrypt_secrets("org-uuid")

    def test_reencrypt_signing_keys_ok(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, {"status": "done"})
            result = self.client.reencrypt_signing_keys("org-uuid")
        assert result == {"status": "done"}

    def test_reencrypt_signing_keys_error(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(500, {"message": "internal error"})
            with pytest.raises(ButtrbaseError):
                self.client.reencrypt_signing_keys("org-uuid")

    def test_reencrypt_mtls_ca_ok(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, {"status": "done"})
            result = self.client.reencrypt_mtls_ca("org-uuid")
        assert result == {"status": "done"}

    def test_reencrypt_mtls_ca_error(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(500, {"message": "internal error"})
            with pytest.raises(ButtrbaseError):
                self.client.reencrypt_mtls_ca("org-uuid")


# ---------------------------------------------------------------------------
# Session revocation
# ---------------------------------------------------------------------------

class TestSessionRevocation:
    def setup_method(self):
        self.client = _make_client()

    def _patch(self):
        return patch.object(self.client._session, "request")

    def test_revoke_session_minimal(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, {"revoked": True})
            result = self.client.revoke_session("jti-abc")
        assert result == {"revoked": True}
        sent = mock_req.call_args[1]["json"]
        assert sent == {"jti": "jti-abc"}

    def test_revoke_session_with_ttl(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, {"revoked": True})
            self.client.revoke_session("jti-abc", ttl_seconds=86400)
        sent = mock_req.call_args[1]["json"]
        assert sent["ttl_seconds"] == 86400

    def test_revoke_session_error(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(404, {"message": "not found"})
            with pytest.raises(ButtrbaseError):
                self.client.revoke_session("no-such-jti")


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

class TestMetricsEndpoints:
    def setup_method(self):
        self.client = _make_client()

    def _patch(self):
        return patch.object(self.client._session, "request")

    def test_get_org_metrics_ok(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, {"users": 100, "requests": 50000})
            result = self.client.get_org_metrics("org-uuid")
        assert result["users"] == 100

    def test_get_org_metrics_error(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(403, {"message": "forbidden"})
            with pytest.raises(ButtrbaseError):
                self.client.get_org_metrics("org-uuid")


# ---------------------------------------------------------------------------
# Credentials endpoints
# ---------------------------------------------------------------------------

class TestCredentialEndpoints:
    def setup_method(self):
        self.client = _make_client()

    def _patch(self):
        return patch.object(self.client._session, "request")

    def test_list_credentials_ok(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, {"data": []})
            result = self.client.list_credentials()
        assert result == {"data": []}

    def test_list_credentials_error(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(401, {"message": "unauthorized"})
            with pytest.raises(ButtrbaseError):
                self.client.list_credentials()

    def test_create_credential_minimal(self):
        resp_body = {
            "credentials_id": "cred-1",
            "client_id": "client-1",
            "client_secret": "sec-1",
            "name": "My Cred",
            "description": None,
            "created_at": "2024-01-01T00:00:00Z",
        }
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(201, resp_body)
            result = self.client.create_credential("My Cred")
        assert result["credentials_id"] == "cred-1"
        sent = mock_req.call_args[1]["json"]
        assert sent == {"name": "My Cred"}

    def test_create_credential_with_description(self):
        resp_body = {
            "credentials_id": "cred-2",
            "client_id": "client-2",
            "client_secret": "sec-2",
            "name": "Cred2",
            "description": "A description",
            "created_at": "2024-01-01T00:00:00Z",
        }
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(201, resp_body)
            self.client.create_credential("Cred2", description="A description")
        sent = mock_req.call_args[1]["json"]
        assert sent["description"] == "A description"

    def test_create_credential_error(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(422, {"message": "name required"})
            with pytest.raises(ButtrbaseError):
                self.client.create_credential("")

    def test_get_credential_ok(self):
        resp_body = {
            "credentials_id": "cred-1",
            "client_id": "client-1",
            "name": "My Cred",
            "description": None,
            "created_at": "2024-01-01T00:00:00Z",
        }
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, resp_body)
            result = self.client.get_credential("cred-1")
        assert result["credentials_id"] == "cred-1"

    def test_get_credential_error(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(404, {"message": "not found"})
            with pytest.raises(ButtrbaseError):
                self.client.get_credential("no-such-cred")

    def test_delete_credential_ok(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(204, None, content=b"")
            # Should not raise
            self.client.delete_credential("cred-1")

    def test_delete_credential_error(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(404, {"message": "not found"})
            with pytest.raises(ButtrbaseError):
                self.client.delete_credential("no-such-cred")

    def test_rotate_credential_secret_ok(self):
        resp_body = {
            "credentials_id": "cred-1",
            "client_id": "client-1",
            "client_secret": "new-secret",
        }
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, resp_body)
            result = self.client.rotate_credential_secret("cred-1")
        assert result["client_secret"] == "new-secret"

    def test_rotate_credential_secret_error(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(404, {"message": "not found"})
            with pytest.raises(ButtrbaseError):
                self.client.rotate_credential_secret("no-such-cred")


# ---------------------------------------------------------------------------
# Invite-based registration endpoints
# ---------------------------------------------------------------------------

class TestInviteEndpoints:
    def setup_method(self):
        self.client = _make_client()

    def _patch(self):
        return patch.object(self.client._session, "request")

    def test_invite_accept_minimal(self):
        resp_body = {
            "user_uuid": "u-1",
            "org_uuid": "org-1",
            "role": "member",
            "access_token": "tok",
            "refresh_token": "refresh",
            "token_type": "bearer",
            "expires_in": 3600,
            "message": "Welcome",
        }
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, resp_body)
            result = self.client.invite_accept(
                token="invite-tok",
                first_name="Alice",
                last_name="Smith",
                username="alice",
                password="s3cr3t",
            )
        assert result["user_uuid"] == "u-1"
        sent = mock_req.call_args[1]["json"]
        assert "phone" not in sent

    def test_invite_accept_with_phone(self):
        resp_body = {
            "user_uuid": "u-2",
            "org_uuid": "org-1",
            "role": "member",
            "access_token": "tok",
            "refresh_token": "refresh",
            "token_type": "bearer",
            "expires_in": 3600,
            "message": "Welcome",
        }
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, resp_body)
            self.client.invite_accept(
                token="invite-tok",
                first_name="Alice",
                last_name="Smith",
                username="alice",
                password="s3cr3t",
                phone="+1-555-0100",
            )
        sent = mock_req.call_args[1]["json"]
        assert sent["phone"] == "+1-555-0100"

    def test_invite_accept_error(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(400, {"message": "invalid token"})
            with pytest.raises(ButtrbaseError):
                self.client.invite_accept(
                    token="bad", first_name="X", last_name="Y", username="xy", password="pw"
                )

    def test_check_org_name_ok(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, {"name": "acme", "available": True})
            result = self.client.check_org_name("acme")
        assert result["available"] is True

    def test_check_org_name_error(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(422, {"message": "name too short"})
            with pytest.raises(ButtrbaseError):
                self.client.check_org_name("x")

    def test_get_superuser_flag_ok(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(
                200, {"email": "admin@example.com", "is_superuser": True}
            )
            result = self.client.get_superuser_flag("admin@example.com")
        assert result["is_superuser"] is True

    def test_get_superuser_flag_error(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(403, {"message": "forbidden"})
            with pytest.raises(ButtrbaseError):
                self.client.get_superuser_flag("user@example.com")


# ---------------------------------------------------------------------------
# Contact form endpoints
# ---------------------------------------------------------------------------

class TestContactEndpoints:
    def setup_method(self):
        self.client = _make_client()

    def _patch(self):
        return patch.object(self.client._session, "request")

    def test_post_contact_minimal(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(
                200, {"message": "received", "reference_id": "ref-1"}
            )
            result = self.client.post_contact("Alice", "alice@example.com", "Hello")
        assert result["reference_id"] == "ref-1"
        sent = mock_req.call_args[1]["json"]
        assert "company" not in sent
        assert "app_id" not in sent

    def test_post_contact_full(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(
                200, {"message": "received", "reference_id": "ref-2"}
            )
            self.client.post_contact(
                "Alice", "alice@example.com", "Hello",
                company="Acme", app_id="app-123"
            )
        sent = mock_req.call_args[1]["json"]
        assert sent["company"] == "Acme"
        assert sent["app_id"] == "app-123"

    def test_post_contact_error(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(400, {"message": "bad request"})
            with pytest.raises(ButtrbaseError):
                self.client.post_contact("", "", "")

    def test_post_contact_us_ok(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(
                200, {"message": "received", "reference_id": "ref-3"}
            )
            result = self.client.post_contact_us(
                "Alice", "alice@example.com", "Feedback", "Great product!"
            )
        assert result["reference_id"] == "ref-3"
        sent = mock_req.call_args[1]["json"]
        assert sent["subject"] == "Feedback"

    def test_post_contact_us_error(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(500, {"message": "server error"})
            with pytest.raises(ButtrbaseError):
                self.client.post_contact_us("A", "a@b.com", "Sub", "Msg")


# ---------------------------------------------------------------------------
# Geo / IP endpoint
# ---------------------------------------------------------------------------

class TestGeoEndpoints:
    def setup_method(self):
        self.client = _make_client()

    def _patch(self):
        return patch.object(self.client._session, "request")

    def test_get_client_ip_ok(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(
                200, {"ip": "1.2.3.4", "country": "US", "timezone": "America/New_York"}
            )
            result = self.client.get_client_ip()
        assert result["ip"] == "1.2.3.4"
        assert result["country"] == "US"

    def test_get_client_ip_error(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(503, {"message": "service unavailable"})
            with pytest.raises(ButtrbaseError):
                self.client.get_client_ip()


# ---------------------------------------------------------------------------
# Sandbox endpoints
# ---------------------------------------------------------------------------

class TestSandboxEndpoints:
    def setup_method(self):
        self.client = _make_client()

    def _patch(self):
        return patch.object(self.client._session, "request")

    def test_reset_sandbox_no_org(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, {"status": "reset"})
            result = self.client.reset_sandbox()
        assert result == {"status": "reset"}
        call_kwargs = mock_req.call_args[1]
        # empty payload → None
        assert call_kwargs.get("json") is None

    def test_reset_sandbox_with_org_uuid(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, {"status": "reset"})
            self.client.reset_sandbox(org_uuid="org-uuid")
        call_kwargs = mock_req.call_args[1]
        assert call_kwargs["json"] == {"org_uuid": "org-uuid"}

    def test_reset_sandbox_error(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(403, {"message": "forbidden"})
            with pytest.raises(ButtrbaseError):
                self.client.reset_sandbox()


# ---------------------------------------------------------------------------
# Webhooks — additional branch coverage
# ---------------------------------------------------------------------------

class TestWebhooksBranchCoverage:
    def _valid_ts(self) -> str:
        return str(int(time.time()))

    def _make_sig(self, body: bytes, ts: str, secret: str) -> str:
        return webhooks.compute_signature(body, ts, secret)

    # Line 36: missing/empty inputs return False
    def test_empty_signature_returns_false(self):
        assert webhooks.verify_signature(b"body", "", self._valid_ts(), "secret") is False

    def test_empty_timestamp_returns_false(self):
        ts = self._valid_ts()
        sig = self._make_sig(b"body", ts, "secret")
        assert webhooks.verify_signature(b"body", sig, "", "secret") is False

    def test_empty_secret_returns_false(self):
        ts = self._valid_ts()
        sig = self._make_sig(b"body", ts, "secret")
        assert webhooks.verify_signature(b"body", sig, ts, "") is False

    # Lines 39-40: invalid timestamp format → ValueError → False
    def test_non_numeric_timestamp_returns_false(self):
        ts = self._valid_ts()
        sig = self._make_sig(b"body", ts, "secret")
        assert webhooks.verify_signature(b"body", sig, "not-a-number", "secret") is False

    def test_none_timestamp_returns_false(self):
        ts = self._valid_ts()
        sig = self._make_sig(b"body", ts, "secret")
        # passing None as timestamp_header triggers TypeError inside int()
        assert webhooks.verify_signature(b"body", sig, None, "secret") is False  # type: ignore

    # Line 41: timestamp too old (tested in smoke but re-cover here explicitly)
    def test_stale_timestamp_returns_false(self):
        old_ts = str(int(time.time()) - 1000)
        sig = self._make_sig(b"body", old_ts, "secret")
        assert webhooks.verify_signature(b"body", sig, old_ts, "secret", tolerance_seconds=60) is False

    # Line 44-46: sha256= prefix stripping
    def test_sha256_prefix_stripped(self):
        ts = self._valid_ts()
        body = b"hello"
        sig = self._make_sig(body, ts, "mysecret")
        assert webhooks.verify_signature(body, "sha256=" + sig, ts, "mysecret") is True

    # Correct bare signature
    def test_correct_bare_signature(self):
        ts = self._valid_ts()
        body = b'{"event":"test"}'
        sig = self._make_sig(body, ts, "mysecret")
        assert webhooks.verify_signature(body, sig, ts, "mysecret") is True

    # Wrong signature value → False
    def test_wrong_signature_returns_false(self):
        ts = self._valid_ts()
        assert webhooks.verify_signature(b"body", "deadbeef" * 8, ts, "secret") is False


# ---------------------------------------------------------------------------
# Types — TypedDict import fallback (lines 8-9)
# Coverage note: lines 8-9 are the try/except ImportError for typing_extensions.
# We can verify the classes are properly importable and usable.
# ---------------------------------------------------------------------------

class TestTypes:
    def test_credential_typed_dict(self):
        cred: Credential = {
            "credentials_id": "c1",
            "client_id": "cli-1",
            "name": "Test",
            "description": None,
            "created_at": "2024-01-01T00:00:00Z",
        }
        assert cred["name"] == "Test"

    def test_create_credential_response(self):
        resp: CreateCredentialResponse = {
            "credentials_id": "c1",
            "client_id": "cli-1",
            "client_secret": "sec",
            "name": "Test",
            "description": "desc",
            "created_at": "2024-01-01T00:00:00Z",
        }
        assert resp["client_secret"] == "sec"

    def test_rotate_secret_response(self):
        resp: RotateSecretResponse = {
            "credentials_id": "c1",
            "client_id": "cli-1",
            "client_secret": "new-sec",
        }
        assert resp["client_secret"] == "new-sec"

    def test_sandbox_reset_response(self):
        resp: SandboxResetResponse = {"status": "done"}
        assert resp["status"] == "done"

    def test_invite_accept_response(self):
        resp: InviteAcceptResponse = {
            "user_uuid": "u-1",
            "org_uuid": "org-1",
            "role": "member",
            "access_token": "tok",
            "refresh_token": "refresh",
            "token_type": "bearer",
            "expires_in": 3600,
            "message": "ok",
        }
        assert resp["role"] == "member"

    def test_org_check_response(self):
        resp: OrgCheckResponse = {"name": "acme", "available": True}
        assert resp["available"] is True

    def test_superuser_response(self):
        resp: SuperuserResponse = {"email": "admin@example.com", "is_superuser": True}
        assert resp["is_superuser"] is True

    def test_contact_submit_response(self):
        resp: ContactSubmitResponse = {"message": "ok", "reference_id": "r-1"}
        assert resp["reference_id"] == "r-1"

    def test_geo_response(self):
        resp: GeoResponse = {"ip": "1.2.3.4", "country": "US", "timezone": "UTC"}
        assert resp["ip"] == "1.2.3.4"
