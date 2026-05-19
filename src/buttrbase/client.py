"""ButtrBase API client."""
from __future__ import annotations

from typing import Any, Optional

import requests

from .errors import ButtrbaseError
from .types import (
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

DEFAULT_BASE_URL = "https://stagingapi.buttrbase.com"


class ButtrbaseClient:
    """Small synchronous client for the ButtrBase API."""

    def __init__(
        self,
        api_key: str,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 10.0,
    ) -> None:
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._session = requests.Session()

    # ----- internal -----
    def _headers(self, auth: bool = True) -> dict:
        h = {"Accept": "application/json", "Content-Type": "application/json"}
        if auth and self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        return h

    def _request(
        self,
        method: str,
        path: str,
        *,
        json: Optional[dict] = None,
        params: Optional[dict] = None,
        auth: bool = True,
    ) -> Any:
        url = f"{self.base_url}{path}"
        resp = self._session.request(
            method,
            url,
            json=json,
            params=params,
            headers=self._headers(auth=auth),
            timeout=self.timeout,
        )
        return self._handle(resp)

    @staticmethod
    def _handle(resp: requests.Response) -> Any:
        try:
            body = resp.json() if resp.content else None
        except ValueError:
            body = None
        if 200 <= resp.status_code < 300:
            return body if body is not None else {}
        code = None
        detail: Any = body
        message = f"HTTP {resp.status_code}"
        if isinstance(body, dict):
            code = body.get("code") or body.get("error")
            detail = body.get("detail", body.get("message", body))
            message = str(body.get("message") or body.get("error") or message)
        raise ButtrbaseError(
            message, status_code=resp.status_code, code=code, detail=detail
        )

    # ----- Coupons -----
    def validate_coupon(
        self,
        code: str,
        cart_labels: Optional[list[str]] = None,
        product_id: Optional[int] = None,
    ) -> dict:
        payload: dict = {"code": code}
        if cart_labels is not None:
            payload["cart_labels"] = cart_labels
        if product_id is not None:
            payload["product_id"] = product_id
        return self._request("POST", "/api/v1/coupons/validate", json=payload, auth=False)

    # ----- Gift cards -----
    def validate_gift_card(self, code: str) -> dict:
        return self._request(
            "POST", "/api/v1/gift-cards/validate", json={"code": code}, auth=False
        )

    def redeem_gift_card(
        self, code: str, amount_cents: int, user_id: Optional[int] = None
    ) -> dict:
        payload: dict = {"code": code, "amount_cents": amount_cents}
        if user_id is not None:
            payload["user_id"] = user_id
        return self._request("POST", "/api/v1/gift-cards/redeem", json=payload)

    # ----- Magic link -----
    def send_magic_link(
        self,
        email: str,
        org_uuid: Optional[str] = None,
        redirect_to: Optional[str] = None,
    ) -> dict:
        payload: dict = {"email": email}
        if org_uuid is not None:
            payload["org_uuid"] = org_uuid
        if redirect_to is not None:
            payload["redirect_to"] = redirect_to
        return self._request("POST", "/api/v1/auth/magic-link/send", json=payload, auth=False)

    def verify_magic_link(self, token: str) -> dict:
        return self._request(
            "POST", "/api/v1/auth/magic-link/verify", json={"token": token}, auth=False
        )

    # ----- MFA -----
    def mfa_status(self) -> dict:
        return self._request("GET", "/api/v1/auth/mfa/status")

    def mfa_enroll(self, label: Optional[str] = None) -> dict:
        payload: dict = {}
        if label is not None:
            payload["label"] = label
        return self._request("POST", "/api/v1/auth/mfa/enroll", json=payload)

    def mfa_activate(self, code: str) -> dict:
        return self._request("POST", "/api/v1/auth/mfa/activate", json={"code": code})

    # ----- Org signing -----
    def org_sign(
        self, org_uuid: str, claims: dict, ttl_seconds: Optional[int] = None
    ) -> dict:
        payload: dict = {"claims": claims}
        if ttl_seconds is not None:
            payload["ttl_seconds"] = ttl_seconds
        return self._request("POST", f"/api/v1/orgs/{org_uuid}/sign", json=payload)

    def org_jwks(self, org_uuid: str) -> dict:
        return self._request(
            "GET", f"/api/v1/orgs/{org_uuid}/.well-known/jwks.json", auth=False
        )

    # ----- Secrets -----
    def get_secret(self, org_uuid: str, name: str) -> dict:
        return self._request("GET", f"/api/v1/orgs/{org_uuid}/secrets/{name}")

    def put_secret(
        self,
        org_uuid: str,
        name: str,
        value: str,
        description: Optional[str] = None,
    ) -> dict:
        payload: dict = {"value": value}
        if description is not None:
            payload["description"] = description
        return self._request(
            "PUT", f"/api/v1/orgs/{org_uuid}/secrets/{name}", json=payload
        )

    # ----- Step-up auth -----
    def auth_step_up(self, code: str, recovery: bool = False) -> dict:
        """POST /api/auth/step-up.

        Exchange an MFA TOTP (or recovery) code for a short-lived
        elevated access token (~5 min). On success the SDK's bearer
        token is REPLACED with the returned ``access_token`` so the
        next admin / JIT call carries the elevated session.
        """
        payload = {"code": code, "recovery": recovery}
        body = self._request("POST", "/api/auth/step-up", json=payload)
        if isinstance(body, dict) and body.get("access_token"):
            self.api_key = body["access_token"]
        return body

    # ----- JIT elevation (admin) -----
    # All elevation endpoints require an active step-up session.
    def elevation_request(
        self,
        org_uuid: str,
        scope: str,
        reason: Optional[str] = None,
        ttl_seconds: Optional[int] = None,
    ) -> dict:
        """POST /api/admin/orgs/{org_uuid}/elevation/request — returns a grant view."""
        payload: dict = {"scope": scope}
        if reason is not None:
            payload["reason"] = reason
        if ttl_seconds is not None:
            payload["ttl_seconds"] = ttl_seconds
        return self._request(
            "POST", f"/api/admin/orgs/{org_uuid}/elevation/request", json=payload
        )

    def elevation_approve(self, org_uuid: str, grant_uuid: str) -> dict:
        """POST /api/admin/orgs/{org_uuid}/elevation/{grant_uuid}/approve.

        Server returns 403 if the approver is the same admin as the requester.
        """
        return self._request(
            "POST",
            f"/api/admin/orgs/{org_uuid}/elevation/{grant_uuid}/approve",
        )

    def elevation_list(self, org_uuid: str, status: Optional[str] = None) -> list:
        """GET /api/admin/orgs/{org_uuid}/elevation — list grant views."""
        params: dict = {}
        if status is not None:
            params["status"] = status
        return self._request(
            "GET",
            f"/api/admin/orgs/{org_uuid}/elevation",
            params=params or None,
        )

    # ----- SPIFFE -----
    def spiffe_issue_svid(
        self,
        org_uuid: str,
        workload_path: str,
        ttl_seconds: Optional[int] = None,
    ) -> dict:
        """POST /api/admin/orgs/{org_uuid}/spiffe/svid — issue an X.509 SVID."""
        payload: dict = {"workload_path": workload_path}
        if ttl_seconds is not None:
            payload["ttl_seconds"] = ttl_seconds
        return self._request(
            "POST", f"/api/admin/orgs/{org_uuid}/spiffe/svid", json=payload
        )

    # ----- Context-aware auth events -----
    def list_auth_events(
        self,
        org_uuid: str,
        user_uuid: Optional[str] = None,
        limit: int = 50,
    ) -> list:
        """GET /api/admin/orgs/{org_uuid}/auth-events."""
        params: dict = {"limit": limit}
        if user_uuid is not None:
            params["user_uuid"] = user_uuid
        return self._request(
            "GET", f"/api/admin/orgs/{org_uuid}/auth-events", params=params
        )

    # ----- Re-encrypt (key rotation) -----
    def reencrypt_secrets(self, org_uuid: str) -> dict:
        """POST /api/admin/orgs/{org_uuid}/reencrypt/secrets."""
        return self._request(
            "POST", f"/api/admin/orgs/{org_uuid}/reencrypt/secrets"
        )

    def reencrypt_signing_keys(self, org_uuid: str) -> dict:
        """POST /api/admin/orgs/{org_uuid}/reencrypt/signing-keys."""
        return self._request(
            "POST", f"/api/admin/orgs/{org_uuid}/reencrypt/signing-keys"
        )

    def reencrypt_mtls_ca(self, org_uuid: str) -> dict:
        """POST /api/admin/orgs/{org_uuid}/reencrypt/mtls-ca."""
        return self._request(
            "POST", f"/api/admin/orgs/{org_uuid}/reencrypt/mtls-ca"
        )

    # ----- Sessions -----
    def revoke_session(self, jti: str, ttl_seconds: Optional[int] = None) -> dict:
        """POST /api/admin/sessions/revoke — add ``jti`` to the revocation list."""
        payload: dict = {"jti": jti}
        if ttl_seconds is not None:
            payload["ttl_seconds"] = ttl_seconds
        return self._request("POST", "/api/admin/sessions/revoke", json=payload)

    # ----- Metrics -----
    def get_org_metrics(self, org_uuid: str) -> dict:
        """GET /api/admin/orgs/{org_uuid}/metrics."""
        return self._request("GET", f"/api/admin/orgs/{org_uuid}/metrics")

    # ----- Credentials -----
    def list_credentials(self) -> dict:
        """GET /credentials — returns ``{"data": [Credential, ...]}``."""
        return self._request("GET", "/credentials")

    def create_credential(self, name: str, description: Optional[str] = None) -> CreateCredentialResponse:
        """POST /credentials — create a new credential (returns HTTP 201).

        Args:
            name: Human-readable name for the credential.
            description: Optional description for the credential.

        Returns:
            A ``CreateCredentialResponse`` dict containing ``credentials_id``,
            ``client_id``, ``client_secret``, ``name``, ``description``, and
            ``created_at``.
        """
        payload: dict = {"name": name}
        if description is not None:
            payload["description"] = description
        return self._request("POST", "/credentials", json=payload)

    def get_credential(self, credential_id: str) -> Credential:
        """GET /credentials/{credential_id} — fetch a single credential.

        Note: the response does **not** include ``client_secret``.
        """
        return self._request("GET", f"/credentials/{credential_id}")

    def delete_credential(self, credential_id: str) -> None:
        """DELETE /credentials/{credential_id} — delete a credential (HTTP 204)."""
        self._request("DELETE", f"/credentials/{credential_id}")

    def rotate_credential_secret(self, credential_id: str) -> RotateSecretResponse:
        """POST /credentials/{credential_id}/rotate-secret — generate a new client secret.

        Returns:
            A ``RotateSecretResponse`` dict containing ``credentials_id``,
            ``client_id``, and the new ``client_secret``.
        """
        return self._request("POST", f"/credentials/{credential_id}/rotate-secret")

    # ----- Invite-based registration -----
    def invite_accept(
        self,
        token: str,
        first_name: str,
        last_name: str,
        username: str,
        password: str,
        phone: Optional[str] = None,
    ) -> InviteAcceptResponse:
        """POST /api/auth/invite/accept — accept an invitation and create a user account.

        No authentication required; the ``token`` argument acts as the credential.

        Returns:
            An ``InviteAcceptResponse`` dict containing ``user_uuid``, ``org_uuid``,
            ``role``, ``access_token``, ``refresh_token``, ``token_type``,
            ``expires_in``, and ``message``.
        """
        payload: dict = {
            "token": token,
            "first_name": first_name,
            "last_name": last_name,
            "username": username,
            "password": password,
        }
        if phone is not None:
            payload["phone"] = phone
        return self._request("POST", "/api/auth/invite/accept", json=payload, auth=False)

    def check_org_name(self, name: str) -> OrgCheckResponse:
        """GET /api/auth/orgs/check — check whether an organisation name is available.

        Returns:
            An ``OrgCheckResponse`` dict with ``name`` and ``available``.
        """
        return self._request(
            "GET", "/api/auth/orgs/check", params={"name": name}, auth=False
        )

    def get_superuser_flag(self, email: str) -> SuperuserResponse:
        """GET /api/auth/superuser — look up the superuser flag for an email address.

        Requires platform-admin authentication.

        Returns:
            A ``SuperuserResponse`` dict with ``email`` and ``is_superuser``.
        """
        return self._request("GET", "/api/auth/superuser", params={"email": email})

    # ----- Contact forms -----
    def post_contact(
        self,
        name: str,
        email: str,
        message: str,
        company: Optional[str] = None,
        app_id: Optional[str] = None,
    ) -> ContactSubmitResponse:
        """POST /api/contact — submit an account / sales enquiry form.

        Returns:
            A ``ContactSubmitResponse`` dict with ``message`` and ``reference_id``.
        """
        payload: dict = {"name": name, "email": email, "message": message}
        if company is not None:
            payload["company"] = company
        if app_id is not None:
            payload["app_id"] = app_id
        return self._request("POST", "/api/contact", json=payload, auth=False)

    def post_contact_us(
        self,
        name: str,
        email: str,
        subject: str,
        message: str,
    ) -> ContactSubmitResponse:
        """POST /api/contact-us — submit a general contact-us form.

        Returns:
            A ``ContactSubmitResponse`` dict with ``message`` and ``reference_id``.
        """
        payload = {"name": name, "email": email, "subject": subject, "message": message}
        return self._request("POST", "/api/contact-us", json=payload, auth=False)

    # ----- Geo / IP -----
    def get_client_ip(self) -> GeoResponse:
        """GET /api/geo/ip — return the caller's IP address and basic geo context.

        Useful during registration for timezone / country pre-fill.

        Returns:
            A ``GeoResponse`` dict with ``ip``, ``country``, and ``timezone``.
        """
        return self._request("GET", "/api/geo/ip", auth=False)

    # ----- Sandbox -----
    def reset_sandbox(self, org_uuid: Optional[str] = None) -> SandboxResetResponse:
        """POST /api/sandbox/reset — reset the sandbox environment.

        Args:
            org_uuid: Optional organisation UUID to scope the reset to a
                specific organisation's sandbox data.

        Returns:
            A ``SandboxResetResponse`` dict (shape may vary; typically
            contains a ``status`` field).
        """
        payload: dict = {}
        if org_uuid is not None:
            payload["org_uuid"] = org_uuid
        return self._request("POST", "/api/sandbox/reset", json=payload or None)
