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


def _make_client(access_token: str = "test-key") -> ButtrbaseClient:
    return ButtrbaseClient(access_token=access_token, base_url="https://example.com", timeout=5.0)


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

    def test_empty_access_token_no_auth_header(self):
        client = _make_client("")
        h = client._headers(auth=True)
        assert "Authorization" not in h

    def test_base_url_trailing_slash_stripped(self):
        client = ButtrbaseClient(access_token="k", base_url="https://example.com/")
        assert client.base_url == "https://example.com"


# ---------------------------------------------------------------------------
# Client-credentials token grant (authenticate / lazy fetch / refresh)
# ---------------------------------------------------------------------------

class TestClientCredentialsGrant:
    def _client(self) -> ButtrbaseClient:
        return ButtrbaseClient(
            base_url="https://example.com",
            timeout=5.0,
            client_id="cid",
            client_secret="csecret",
        )

    def test_authenticate_sets_bearer(self):
        client = self._client()
        with patch.object(client._session, "post") as mock_post:
            mock_post.return_value = _make_response(
                200,
                {"access_token": "jwt-1", "token_type": "Bearer", "expires_in": 3600},
            )
            body = client.authenticate()
        # Hits the token endpoint with the client-credentials grant body.
        assert mock_post.call_args[0][0] == "https://example.com/api/v1/auth/token"
        assert mock_post.call_args[1]["json"] == {
            "grant_type": "client_credentials",
            "client_id": "cid",
            "client_secret": "csecret",
        }
        assert body["access_token"] == "jwt-1"
        # Bearer is stored for subsequent requests.
        assert client.access_token == "jwt-1"
        assert client._headers(auth=True)["Authorization"] == "Bearer jwt-1"

    def test_authenticate_bad_credentials_raises(self):
        client = self._client()
        with patch.object(client._session, "post") as mock_post:
            mock_post.return_value = _make_response(
                401, {"error": "invalid client credentials"}
            )
            with pytest.raises(ButtrbaseError) as exc_info:
                client.authenticate()
        assert exc_info.value.status_code == 401
        assert exc_info.value.code == "invalid client credentials"
        assert client.access_token == ""

    def test_authenticate_requires_credentials(self):
        client = ButtrbaseClient(base_url="https://example.com")
        with pytest.raises(ValueError):
            client.authenticate()

    def test_lazy_fetch_before_first_authed_request(self):
        client = self._client()
        with patch.object(client._session, "post") as mock_post, \
                patch.object(client._session, "request") as mock_req:
            mock_post.return_value = _make_response(
                200,
                {"access_token": "jwt-1", "token_type": "Bearer", "expires_in": 3600},
            )
            mock_req.return_value = _make_response(200, {"ok": True})
            # No token set yet — the authed call should trigger a token fetch.
            result = client.get_profile()
        assert result == {"ok": True}
        assert mock_post.call_count == 1
        # The authed request carried the freshly-minted bearer.
        sent_headers = mock_req.call_args[1]["headers"]
        assert sent_headers["Authorization"] == "Bearer jwt-1"

    def test_token_reused_across_requests(self):
        client = self._client()
        with patch.object(client._session, "post") as mock_post, \
                patch.object(client._session, "request") as mock_req:
            mock_post.return_value = _make_response(
                200,
                {"access_token": "jwt-1", "token_type": "Bearer", "expires_in": 3600},
            )
            mock_req.return_value = _make_response(200, {"ok": True})
            client.get_profile()
            client.get_profile()
            client.list_users()
        # Token fetched once, reused for all three authed calls.
        assert mock_post.call_count == 1
        assert mock_req.call_count == 3

    def test_token_refreshed_on_expiry(self):
        client = self._client()
        with patch.object(client._session, "post") as mock_post, \
                patch.object(client._session, "request") as mock_req:
            mock_post.side_effect = [
                _make_response(
                    200,
                    {"access_token": "jwt-1", "token_type": "Bearer", "expires_in": 3600},
                ),
                _make_response(
                    200,
                    {"access_token": "jwt-2", "token_type": "Bearer", "expires_in": 3600},
                ),
            ]
            mock_req.return_value = _make_response(200, {"ok": True})
            client.get_profile()
            assert client.access_token == "jwt-1"
            # Force the cached token past its (early) expiry mark.
            client._token_expires_at = time.time() - 1
            client.get_profile()
        # A second token was minted and is now in use.
        assert mock_post.call_count == 2
        assert client.access_token == "jwt-2"
        last_headers = mock_req.call_args[1]["headers"]
        assert last_headers["Authorization"] == "Bearer jwt-2"

    def test_explicit_access_token_skips_grant(self):
        client = ButtrbaseClient(
            access_token="preset",
            base_url="https://example.com",
            client_id="cid",
            client_secret="csecret",
        )
        with patch.object(client._session, "post") as mock_post, \
                patch.object(client._session, "request") as mock_req:
            mock_req.return_value = _make_response(200, {"ok": True})
            client.get_profile()
        # A preset token (no tracked expiry) is used as-is; no grant call.
        mock_post.assert_not_called()
        assert mock_req.call_args[1]["headers"]["Authorization"] == "Bearer preset"

    def test_no_credentials_no_lazy_fetch(self):
        client = ButtrbaseClient(base_url="https://example.com")
        with patch.object(client._session, "post") as mock_post, \
                patch.object(client._session, "request") as mock_req:
            mock_req.return_value = _make_response(200, {"ok": True})
            client.get_profile()
        # Anonymous client with no credentials: no grant, no auth header.
        mock_post.assert_not_called()
        assert "Authorization" not in mock_req.call_args[1]["headers"]


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

    def test_step_up_replaces_access_token(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, {"access_token": "elevated-key"})
            result = self.client.auth_step_up("123456")
        assert result["access_token"] == "elevated-key"
        # access_token should be replaced
        assert self.client.access_token == "elevated-key"

    def test_step_up_no_access_token_does_not_replace_key(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, {"status": "ok"})
            self.client.auth_step_up("123456")
        assert self.client.access_token == "original-key"

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
        # 503 is retryable; patch sleep so the retries don't slow the suite.
        with self._patch() as mock_req, patch("buttrbase.client.time.sleep"):
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
# Retry strategy
# ---------------------------------------------------------------------------

class TestRetryStrategy:
    def setup_method(self):
        self.client = _make_client()

    def _patch(self):
        return patch.object(self.client._session, "request")

    def test_503_then_200_succeeds_after_retry(self):
        with self._patch() as mock_req, patch("buttrbase.client.time.sleep") as sleep:
            mock_req.side_effect = [
                _make_response(503, {"message": "cold start"}),
                _make_response(200, {"ok": True}),
            ]
            result = self.client.validate_coupon("PROMO10")
        assert result == {"ok": True}
        assert mock_req.call_count == 2
        # Backoff slept once between the two attempts.
        assert sleep.call_count == 1

    def test_400_does_not_retry(self):
        with self._patch() as mock_req, patch("buttrbase.client.time.sleep") as sleep:
            mock_req.return_value = _make_response(400, {"message": "bad"})
            with pytest.raises(ButtrbaseError) as exc_info:
                self.client.validate_coupon("BAD")
        assert exc_info.value.status_code == 400
        assert mock_req.call_count == 1
        sleep.assert_not_called()

    def test_connection_error_retries_then_succeeds(self):
        import requests as _requests

        with self._patch() as mock_req, patch("buttrbase.client.time.sleep"):
            mock_req.side_effect = [
                _requests.exceptions.ConnectionError("boom"),
                _make_response(200, {"ok": True}),
            ]
            result = self.client.validate_coupon("X")
        assert result == {"ok": True}
        assert mock_req.call_count == 2

    def test_exhausts_retries_and_raises(self):
        with self._patch() as mock_req, patch("buttrbase.client.time.sleep"):
            mock_req.return_value = _make_response(502, {"message": "gateway"})
            with pytest.raises(ButtrbaseError) as exc_info:
                self.client.validate_coupon("X")
        assert exc_info.value.status_code == 502
        # 1 initial + 3 retries (default max_retries=3) = 4 attempts.
        assert mock_req.call_count == 4

    def test_max_retries_zero_disables(self):
        client = ButtrbaseClient(
            access_token="k", base_url="https://example.com", max_retries=0
        )
        with patch.object(client._session, "request") as mock_req, \
                patch("buttrbase.client.time.sleep") as sleep:
            mock_req.return_value = _make_response(503, {"message": "down"})
            with pytest.raises(ButtrbaseError):
                client.validate_coupon("X")
        assert mock_req.call_count == 1
        sleep.assert_not_called()

    def test_retry_after_header_honored(self):
        with self._patch() as mock_req, patch("buttrbase.client.time.sleep") as sleep:
            resp_503 = _make_response(503, {"message": "wait"})
            resp_503.headers = {"Retry-After": "2"}
            mock_req.side_effect = [resp_503, _make_response(200, {"ok": True})]
            result = self.client.validate_coupon("X")
        assert result == {"ok": True}
        # Retry-After: 2 seconds should be slept exactly.
        sleep.assert_called_once_with(2.0)


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


# ---------------------------------------------------------------------------
# Token claims enrichment (verify module) — data-envelope: roles / email
# ---------------------------------------------------------------------------

import json
import os
import pathlib

from buttrbase.verify import (
    Claims,
    ClaimsData,
    TokenPrincipal,
    principal_from_payload,
)

# Resolve the fixture relative to the Rust SDK repo alongside this one.
_FIXTURE_PATH = pathlib.Path(__file__).parent.parent.parent / (
    "buttrbase-sdk-rust/tests/fixtures/access_token_claims.json"
)


def _load_fixture() -> dict:
    """Load access_token_claims.json; skip gracefully if the path is absent."""
    if _FIXTURE_PATH.exists():
        return json.loads(_FIXTURE_PATH.read_text())
    # Inline minimal fixture so tests are self-contained in any checkout.
    return {
        "sub": "11111111-1111-1111-1111-111111111111",
        "org": "22222222-2222-2222-2222-222222222222",
        "exp": 1750003600,
        "iat": 1750000000,
        "scope": ["read:messages", "write:messages"],
        "data": {
            "email": "test@example.com",
            "roles": "owner",
            "org_uuid": "22222222-2222-2222-2222-222222222222",
            "user_uuid": "11111111-1111-1111-1111-111111111111",
        },
    }


class TestClaimsDataEnrichment:
    """Unit tests for ClaimsData — additive data-envelope parsing."""

    def test_claims_data_from_full_dict(self):
        raw = {
            "roles": "owner",
            "email": "test@example.com",
            "org_uuid": "22222222-2222-2222-2222-222222222222",
            "user_uuid": "11111111-1111-1111-1111-111111111111",
        }
        cd = ClaimsData.from_dict(raw)
        assert cd.roles == "owner"
        assert cd.email == "test@example.com"
        assert cd.org_uuid == "22222222-2222-2222-2222-222222222222"
        assert cd.user_uuid == "11111111-1111-1111-1111-111111111111"

    def test_claims_data_missing_fields_are_none(self):
        cd = ClaimsData.from_dict({})
        assert cd.roles is None
        assert cd.email is None
        assert cd.org_uuid is None
        assert cd.user_uuid is None

    def test_claims_data_partial(self):
        cd = ClaimsData.from_dict({"email": "a@b.com"})
        assert cd.email == "a@b.com"
        assert cd.roles is None


class TestClaimsFromDict:
    """Unit tests for Claims.from_dict — JWT payload parsing."""

    def test_minimal_payload(self):
        payload = {
            "sub": "00000000-0000-0000-0000-000000000000",
            "org": "00000000-0000-0000-0000-000000000001",
            "exp": 9999999999,
            "iat": 0,
        }
        claims = Claims.from_dict(payload)
        assert claims.sub == "00000000-0000-0000-0000-000000000000"
        assert claims.org == "00000000-0000-0000-0000-000000000001"
        assert claims.scope == []
        assert claims.data is None

    def test_scope_populated(self):
        payload = {
            "sub": "aaa",
            "org": "bbb",
            "exp": 1,
            "iat": 0,
            "scope": ["read:users", "write:users"],
        }
        claims = Claims.from_dict(payload)
        assert claims.scope == ["read:users", "write:users"]

    def test_data_envelope_parsed(self):
        payload = {
            "sub": "aaa",
            "org": "bbb",
            "exp": 1,
            "iat": 0,
            "data": {"roles": "owner", "email": "test@example.com"},
        }
        claims = Claims.from_dict(payload)
        assert claims.data is not None
        assert claims.data.roles == "owner"
        assert claims.data.email == "test@example.com"

    def test_non_dict_data_envelope_ignored(self):
        """A data field that is not a dict should not crash; data should be None."""
        payload = {"sub": "a", "org": "b", "exp": 1, "iat": 0, "data": "not-a-dict"}
        claims = Claims.from_dict(payload)
        assert claims.data is None

    def test_fixture_claims(self):
        """Round-trip the shared access_token_claims.json fixture."""
        fixture = _load_fixture()
        claims = Claims.from_dict(fixture)
        assert claims.data is not None
        assert claims.data.roles == "owner"
        assert claims.data.email == "test@example.com"


class TestTokenPrincipal:
    """Unit tests for TokenPrincipal — auth-context from claims."""

    def test_principal_roles_split_single(self):
        claims = Claims(
            sub="u1", org="o1", exp=1, iat=0,
            data=ClaimsData(roles="owner", email="x@y.com"),
        )
        p = TokenPrincipal.from_claims(claims)
        assert p.roles == ["owner"]
        assert p.email == "x@y.com"

    def test_principal_roles_split_comma_delimited(self):
        claims = Claims(
            sub="u1", org="o1", exp=1, iat=0,
            data=ClaimsData(roles="org_admin,leadership"),
        )
        p = TokenPrincipal.from_claims(claims)
        assert p.roles == ["org_admin", "leadership"]

    def test_principal_roles_split_space_delimited(self):
        claims = Claims(
            sub="u1", org="o1", exp=1, iat=0,
            data=ClaimsData(roles="a b c"),
        )
        p = TokenPrincipal.from_claims(claims)
        assert p.roles == ["a", "b", "c"]

    def test_principal_roles_split_mixed_delimiter(self):
        claims = Claims(
            sub="u1", org="o1", exp=1, iat=0,
            data=ClaimsData(roles="owner, org_admin,  leadership"),
        )
        p = TokenPrincipal.from_claims(claims)
        assert p.roles == ["owner", "org_admin", "leadership"]

    def test_principal_no_data_gives_empty_roles_and_no_email(self):
        claims = Claims(sub="u1", org="o1", exp=1, iat=0, data=None)
        p = TokenPrincipal.from_claims(claims)
        assert p.roles == []
        assert p.email is None

    def test_principal_data_no_roles(self):
        claims = Claims(
            sub="u1", org="o1", exp=1, iat=0,
            data=ClaimsData(roles=None, email="a@b.com"),
        )
        p = TokenPrincipal.from_claims(claims)
        assert p.roles == []
        assert p.email == "a@b.com"

    def test_principal_copies_scopes(self):
        claims = Claims(
            sub="u1", org="o1", exp=1, iat=0,
            scope=["read:pages", "write:pages"],
            data=None,
        )
        p = TokenPrincipal.from_claims(claims)
        assert p.scopes == ["read:pages", "write:pages"]

    def test_principal_from_payload_one_shot(self):
        payload = {
            "sub": "u1",
            "org": "o1",
            "exp": 1,
            "iat": 0,
            "data": {"roles": "owner", "email": "test@example.com"},
        }
        p = principal_from_payload(payload)
        assert "owner" in p.roles
        assert p.email == "test@example.com"

    def test_fixture_principal_roles_and_email(self):
        """Core assertion: fixture token yields roles list + email on principal.

        This is the Python mirror of the Rust SDK test
        ``claims_expose_roles_and_email_from_data_envelope``.
        """
        fixture = _load_fixture()
        p = principal_from_payload(fixture)
        assert "owner" in p.roles, f"expected 'owner' in roles, got {p.roles!r}"
        assert p.email == "test@example.com", f"unexpected email: {p.email!r}"


# ---------------------------------------------------------------------------
# Parity methods — refresh_token
# ---------------------------------------------------------------------------

class TestRefreshToken:
    def setup_method(self):
        self.client = _make_client()

    def _patch(self):
        return patch.object(self.client._session, "request")

    def test_refresh_token_ok(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(
                200,
                {"access_token": "new-jwt", "token_type": "Bearer", "expires_in": 3600},
            )
            result = self.client.refresh_token("old-refresh-tok")
        assert result["access_token"] == "new-jwt"
        assert result["token_type"] == "Bearer"
        # Verify endpoint and body.
        url, = (mock_req.call_args[0][1],)
        assert "/api/app/auth/refresh" in url
        sent = mock_req.call_args[1]["json"]
        assert sent == {"refresh": "old-refresh-tok"}

    def test_refresh_token_http_method_is_post(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(
                200, {"access_token": "x", "token_type": "Bearer", "expires_in": 3600}
            )
            self.client.refresh_token("tok")
        assert mock_req.call_args[0][0] == "POST"

    def test_refresh_token_401_raises(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(401, {"message": "invalid refresh token"})
            with pytest.raises(ButtrbaseError) as exc_info:
                self.client.refresh_token("bad-tok")
        assert exc_info.value.status_code == 401


# ---------------------------------------------------------------------------
# Parity methods — wallet_transactions
# ---------------------------------------------------------------------------

class TestWalletTransactions:
    def setup_method(self):
        self.client = _make_client()

    def _patch(self):
        return patch.object(self.client._session, "request")

    def test_wallet_transactions_default_params(self):
        txns = [
            {"id": 1, "type": "credit", "amount_cents": 500, "currency": "USD",
             "description": "deposit", "created_at": "2026-01-01T00:00:00Z"},
        ]
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, txns)
            result = self.client.wallet_transactions()
        assert len(result) == 1
        assert result[0]["type"] == "credit"
        params = mock_req.call_args[1]["params"]
        assert params["limit"] == 50
        assert params["offset"] == 0

    def test_wallet_transactions_custom_params(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, [])
            self.client.wallet_transactions(limit=10, offset=20)
        params = mock_req.call_args[1]["params"]
        assert params["limit"] == 10
        assert params["offset"] == 20

    def test_wallet_transactions_url(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, [])
            self.client.wallet_transactions()
        url = mock_req.call_args[0][1]
        assert "/api/wallet/transactions" in url

    def test_wallet_transactions_http_get(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, [])
            self.client.wallet_transactions()
        assert mock_req.call_args[0][0] == "GET"

    def test_wallet_transactions_error(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(401, {"message": "unauthorized"})
            with pytest.raises(ButtrbaseError):
                self.client.wallet_transactions()


# ---------------------------------------------------------------------------
# Parity methods — subscriptions
# ---------------------------------------------------------------------------

class TestSubscriptions:
    def setup_method(self):
        self.client = _make_client()

    def _patch(self):
        return patch.object(self.client._session, "request")

    def test_subscriptions_ok(self):
        items = [
            {"id": 1, "price_id": "price_basic", "status": "active",
             "current_period_start": "2026-01-01T00:00:00Z",
             "current_period_end": "2026-02-01T00:00:00Z",
             "created_at": "2026-01-01T00:00:00Z"},
        ]
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, items)
            result = self.client.subscriptions()
        assert len(result) == 1
        assert result[0]["status"] == "active"

    def test_subscriptions_http_get(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, [])
            self.client.subscriptions()
        assert mock_req.call_args[0][0] == "GET"
        assert "/api/subscriptions" in mock_req.call_args[0][1]

    def test_subscriptions_error(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(401, {"message": "unauthorized"})
            with pytest.raises(ButtrbaseError):
                self.client.subscriptions()

    def test_create_subscription_ok(self):
        created = {"id": 42, "price_id": "price_pro", "status": "active",
                   "current_period_start": None, "current_period_end": None,
                   "created_at": "2026-06-01T00:00:00Z"}
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, created)
            result = self.client.create_subscription({"price_id": "price_pro"})
        assert result["id"] == 42
        assert result["price_id"] == "price_pro"

    def test_create_subscription_http_post(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(
                200, {"id": 1, "price_id": "x", "status": "active",
                      "current_period_start": None, "current_period_end": None,
                      "created_at": "2026-01-01T00:00:00Z"}
            )
            self.client.create_subscription({"price_id": "x"})
        assert mock_req.call_args[0][0] == "POST"
        assert "/api/subscriptions" in mock_req.call_args[0][1]
        assert mock_req.call_args[1]["json"] == {"price_id": "x"}

    def test_create_subscription_error(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(400, {"message": "invalid price_id"})
            with pytest.raises(ButtrbaseError):
                self.client.create_subscription({"price_id": "bad"})

    def test_cancel_subscription_ok(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(204, None, content=b"")
            # Should not raise; returns None
            result = self.client.cancel_subscription(42)
        assert result is None or result == {}

    def test_cancel_subscription_http_delete(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(204, None, content=b"")
            self.client.cancel_subscription(99)
        assert mock_req.call_args[0][0] == "DELETE"
        assert "/api/subscriptions/99" in mock_req.call_args[0][1]

    def test_cancel_subscription_error(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(404, {"message": "not found"})
            with pytest.raises(ButtrbaseError):
                self.client.cancel_subscription(9999)


# ---------------------------------------------------------------------------
# Parity methods — app management
# ---------------------------------------------------------------------------

class TestAppManagement:
    def setup_method(self):
        self.client = _make_client()

    def _patch(self):
        return patch.object(self.client._session, "request")

    def test_my_apps_ok(self):
        apps = [
            {"app_uuid": "app-1", "name": "My App", "role": "admin",
             "created_at": "2026-01-01T00:00:00Z"},
        ]
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, apps)
            result = self.client.my_apps()
        assert len(result) == 1
        assert result[0]["app_uuid"] == "app-1"

    def test_my_apps_http_get(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, [])
            self.client.my_apps()
        assert mock_req.call_args[0][0] == "GET"
        assert "/api/me/apps" in mock_req.call_args[0][1]

    def test_my_apps_error(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(401, {"message": "unauthorized"})
            with pytest.raises(ButtrbaseError):
                self.client.my_apps()

    def test_app_orgs_ok(self):
        orgs = [
            {"org_uuid": "org-1", "name": "Acme Inc", "role": "member"},
        ]
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, orgs)
            result = self.client.app_orgs("app-uuid-123")
        assert len(result) == 1
        assert result[0]["org_uuid"] == "org-1"

    def test_app_orgs_url(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, [])
            self.client.app_orgs("app-uuid-123")
        url = mock_req.call_args[0][1]
        assert "/api/apps/app-uuid-123/organizations" in url

    def test_app_orgs_error(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(403, {"message": "forbidden"})
            with pytest.raises(ButtrbaseError):
                self.client.app_orgs("app-uuid-123")

    def test_app_credentials_ok(self):
        creds = {
            "live": {"client_id": "bb_live_cid_xyz", "environment": "live"},
            "sandbox": {"client_id": "bb_test_cid_xyz", "environment": "sandbox"},
        }
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, creds)
            result = self.client.app_credentials("app-uuid-123")
        assert result["live"]["client_id"] == "bb_live_cid_xyz"
        assert result["sandbox"]["client_id"] == "bb_test_cid_xyz"

    def test_app_credentials_url(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(
                200, {"live": None, "sandbox": None}
            )
            self.client.app_credentials("app-uuid-xyz")
        url = mock_req.call_args[0][1]
        assert "/api/apps/app-uuid-xyz/credentials" in url

    def test_app_credentials_error(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(403, {"message": "admin only"})
            with pytest.raises(ButtrbaseError):
                self.client.app_credentials("app-uuid-123")

    def test_enable_sandbox_ok(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, {"sandbox_enabled": True})
            self.client.enable_sandbox("app-uuid-123")
        assert mock_req.call_args[0][0] == "PATCH"
        url = mock_req.call_args[0][1]
        assert "/api/apps/app-uuid-123" in url
        sent = mock_req.call_args[1]["json"]
        assert sent == {"sandbox_enabled": True}

    def test_enable_sandbox_error(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(403, {"message": "forbidden"})
            with pytest.raises(ButtrbaseError):
                self.client.enable_sandbox("app-uuid-123")

    def test_rotate_credentials_live(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(
                200, {"client_id": "new-cid", "client_secret": "new-sk"}
            )
            result = self.client.rotate_credentials("app-uuid-123", "live")
        assert result["client_id"] == "new-cid"
        assert mock_req.call_args[0][0] == "POST"
        url = mock_req.call_args[0][1]
        assert "/api/apps/app-uuid-123/credentials/live/rotate" in url

    def test_rotate_credentials_sandbox(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(
                200, {"client_id": "new-test-cid", "client_secret": "new-test-sk"}
            )
            self.client.rotate_credentials("app-uuid-123", "sandbox")
        url = mock_req.call_args[0][1]
        assert "/api/apps/app-uuid-123/credentials/sandbox/rotate" in url

    def test_rotate_credentials_error(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(403, {"message": "forbidden"})
            with pytest.raises(ButtrbaseError):
                self.client.rotate_credentials("app-uuid-123", "live")


# ---------------------------------------------------------------------------
# Parity methods — canonical entitlement shapes
# ---------------------------------------------------------------------------

class TestCanonicalEntitlements:
    def setup_method(self):
        self.client = _make_client()

    def _patch(self):
        return patch.object(self.client._session, "request")

    def test_check_entitlement_uses_feature_key_field(self):
        """Canonical Rust shape uses 'feature_key' not 'feature'."""
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(
                200, {"granted": True, "reason": None}
            )
            result = self.client.check_entitlement("user-bearer", "advanced_analytics")
        assert result["granted"] is True
        sent = mock_req.call_args[1]["json"]
        assert "feature_key" in sent
        assert sent["feature_key"] == "advanced_analytics"
        assert "feature" not in sent  # NOT the old divergent field

    def test_check_entitlement_not_granted(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(
                200, {"granted": False, "reason": "subscription_required"}
            )
            result = self.client.check_entitlement("tok", "premium_feature")
        assert result["granted"] is False
        assert result["reason"] == "subscription_required"

    def test_check_entitlement_http_post(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, {"granted": True, "reason": None})
            self.client.check_entitlement("tok", "feat")
        assert mock_req.call_args[0][0] == "POST"
        assert "/api/entitlements/check" in mock_req.call_args[0][1]

    def test_check_entitlement_error(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(401, {"message": "unauthorized"})
            with pytest.raises(ButtrbaseError):
                self.client.check_entitlement("bad-tok", "feat")

    def test_check_entitlements_uses_feature_keys_field(self):
        """Canonical Rust shape uses 'feature_keys' not 'checks'."""
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(
                200,
                {
                    "advanced_analytics": {"granted": True, "reason": None},
                    "premium_export": {"granted": False, "reason": "subscription_required"},
                },
            )
            result = self.client.check_entitlements(
                "user-bearer", ["advanced_analytics", "premium_export"]
            )
        assert result["advanced_analytics"]["granted"] is True
        assert result["premium_export"]["granted"] is False
        sent = mock_req.call_args[1]["json"]
        assert "feature_keys" in sent
        assert sent["feature_keys"] == ["advanced_analytics", "premium_export"]
        assert "checks" not in sent  # NOT the old divergent field

    def test_check_entitlements_http_post(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, {})
            self.client.check_entitlements("tok", ["a", "b"])
        assert mock_req.call_args[0][0] == "POST"
        assert "/api/entitlements/check/batch" in mock_req.call_args[0][1]

    def test_check_entitlements_error(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(401, {"message": "unauthorized"})
            with pytest.raises(ButtrbaseError):
                self.client.check_entitlements("bad", ["feat"])

    def test_effective_entitlements_ok(self):
        items = [{"feature_key": "basic_access", "granted": True}]
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, items)
            result = self.client.effective_entitlements("user-bearer")
        assert result == items

    def test_effective_entitlements_http_get(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, [])
            self.client.effective_entitlements("tok")
        assert mock_req.call_args[0][0] == "GET"
        assert "/api/entitlements/effective" in mock_req.call_args[0][1]


# ---------------------------------------------------------------------------
# Parity methods — report_usage (canonical, app-level Basic auth)
# ---------------------------------------------------------------------------

class TestReportUsage:
    def setup_method(self):
        self.client = ButtrbaseClient(
            base_url="https://example.com",
            client_id="bb_test_cid_test",
            client_secret="bb_test_sk_test",
            timeout=5.0,
        )

    def _patch(self):
        return patch.object(self.client._session, "request")

    def test_report_usage_sends_basic_auth(self):
        import base64
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, {})
            self.client.report_usage({"metric": "api_calls", "quantity": 1.0})
        headers = mock_req.call_args[1]["headers"]
        assert "Authorization" in headers
        auth = headers["Authorization"]
        assert auth.startswith("Basic ")
        # Decode and verify it contains client_id:client_secret
        decoded = base64.b64decode(auth[6:]).decode()
        assert "bb_test_cid_test" in decoded
        assert "bb_test_sk_test" in decoded

    def test_report_usage_posts_to_correct_url(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, {})
            self.client.report_usage({"metric": "api_calls", "quantity": 1.0})
        assert mock_req.call_args[0][0] == "POST"
        url = mock_req.call_args[0][1]
        assert "/api/usage/report" in url

    def test_report_usage_sends_event_body(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, {})
            self.client.report_usage({"metric": "storage_gb", "quantity": 50.5, "org_uuid": "org-1"})
        sent = mock_req.call_args[1]["json"]
        assert sent["metric"] == "storage_gb"
        assert sent["quantity"] == 50.5
        assert sent["org_uuid"] == "org-1"

    def test_report_usage_error(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(400, {"message": "invalid metric"})
            with pytest.raises(ButtrbaseError):
                self.client.report_usage({"metric": "", "quantity": 0})

    def test_report_usage_fallback_bearer_when_no_creds(self):
        client = _make_client("bearer-tok")
        with patch.object(client._session, "request") as mock_req:
            mock_req.return_value = _make_response(200, {})
            client.report_usage({"metric": "api_calls", "quantity": 1.0})
        headers = mock_req.call_args[1]["headers"]
        assert headers["Authorization"] == "Bearer bearer-tok"


# ---------------------------------------------------------------------------
# Parity methods — analytics with period param
# ---------------------------------------------------------------------------

class TestAnalyticsPeriodParam:
    def setup_method(self):
        self.client = _make_client()

    def _patch(self):
        return patch.object(self.client._session, "request")

    def test_analytics_app_overview_no_period(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, {"users": 100})
            self.client.analytics_app_overview("app-uuid-1")
        params = mock_req.call_args[1].get("params")
        assert params is None  # no period → no params

    def test_analytics_app_overview_with_period(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, {"users": 200})
            result = self.client.analytics_app_overview("app-uuid-1", period="7d")
        assert result["users"] == 200
        params = mock_req.call_args[1]["params"]
        assert params["period"] == "7d"

    def test_analytics_org_overview_no_period(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, {"events": 50})
            self.client.analytics_org_overview("org-uuid-1")
        params = mock_req.call_args[1].get("params")
        assert params is None

    def test_analytics_org_overview_with_period(self):
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, {"events": 75})
            self.client.analytics_org_overview("org-uuid-1", period="30d")
        params = mock_req.call_args[1]["params"]
        assert params["period"] == "30d"

    def test_ingest_event_alias(self):
        """ingest_event(bearer, event) is the canonical alias for ingest_analytics_event."""
        with self._patch() as mock_req:
            mock_req.return_value = _make_response(200, {})
            self.client.ingest_event("user-bearer", {"event_type": "click", "payload": {}})
        assert mock_req.call_args[0][0] == "POST"
        assert "/api/analytics/events" in mock_req.call_args[0][1]
        sent = mock_req.call_args[1]["json"]
        assert sent["event_type"] == "click"
