"""ButtrBase API client."""
from __future__ import annotations

from typing import Any, List, Optional

import requests

from urllib.parse import urlencode

from .errors import ButtrbaseError
from .types import (
    ApiKeySummary,
    AuditRow,
    ContactSubmitResponse,
    CreateApiKeyInput,
    CreateCredentialResponse,
    CreateOAuthConfigInput,
    CreatedKeyResponse,
    Credential,
    ExchangeResponse,
    GeoResponse,
    InviteAcceptResponse,
    OAuthConfigSummary,
    OrgCheckResponse,
    PasskeyAuthChallenge,
    PasskeyAuthComplete,
    PasskeyListItem,
    PasskeyRegistrationChallenge,
    PasskeyRegistrationComplete,
    PasskeyRegistrationResult,
    RotateSecretResponse,
    SandboxResetResponse,
    SuperuserResponse,
    UpdateOAuthConfigInput,
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
        app_uuid: str,
        org_uuid: Optional[str] = None,
        redirect_to: Optional[str] = None,
    ) -> dict:
        """POST /api/auth/magic-link/send.

        Args:
            email: The recipient's email address.
            app_uuid: UUID of the target app (string-formatted UUID). This
                replaced the legacy ``app`` slug parameter. Example:
                ``"018f1234-5678-7000-8000-000000000001"``.
            org_uuid: Optional org scope.
            redirect_to: Optional URL the user lands on after clicking.
        """
        payload: dict = {"email": email, "app_uuid": app_uuid}
        if org_uuid is not None:
            payload["org_uuid"] = org_uuid
        if redirect_to is not None:
            payload["redirect_to"] = redirect_to
        return self._request("POST", "/api/auth/magic-link/send", json=payload, auth=False)

    def verify_magic_link(self, token: str, app_uuid: str) -> dict:
        """POST /api/v1/auth/magic-link/verify.

        Args:
            token: The single-use token from the magic-link email.
            app_uuid: UUID of the target app (string-formatted UUID).
                Replaced the legacy ``app`` slug parameter.
        """
        return self._request(
            "POST",
            "/api/v1/auth/magic-link/verify",
            json={"token": token, "app_uuid": app_uuid},
            auth=False,
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
        """POST /api/auth/step-up."""
        payload = {"code": code, "recovery": recovery}
        body = self._request("POST", "/api/auth/step-up", json=payload)
        if isinstance(body, dict) and body.get("access_token"):
            self.api_key = body["access_token"]
        return body

    # ----- JIT elevation (admin) -----
    def elevation_request(
        self,
        org_uuid: str,
        scope: str,
        reason: Optional[str] = None,
        ttl_seconds: Optional[int] = None,
    ) -> dict:
        """POST /api/admin/orgs/{org_uuid}/elevation/request."""
        payload: dict = {"scope": scope}
        if reason is not None:
            payload["reason"] = reason
        if ttl_seconds is not None:
            payload["ttl_seconds"] = ttl_seconds
        return self._request(
            "POST", f"/api/admin/orgs/{org_uuid}/elevation/request", json=payload
        )

    def elevation_approve(self, org_uuid: str, grant_uuid: str) -> dict:
        """POST /api/admin/orgs/{org_uuid}/elevation/{grant_uuid}/approve."""
        return self._request(
            "POST",
            f"/api/admin/orgs/{org_uuid}/elevation/{grant_uuid}/approve",
        )

    def elevation_list(self, org_uuid: str, status: Optional[str] = None) -> list:
        """GET /api/admin/orgs/{org_uuid}/elevation."""
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
        """POST /api/admin/orgs/{org_uuid}/spiffe/svid."""
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
        """POST /api/admin/sessions/revoke."""
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
        """GET /credentials."""
        return self._request("GET", "/credentials")

    def create_credential(self, name: str, description: Optional[str] = None) -> CreateCredentialResponse:
        """POST /credentials."""
        payload: dict = {"name": name}
        if description is not None:
            payload["description"] = description
        return self._request("POST", "/credentials", json=payload)

    def get_credential(self, credential_id: str) -> Credential:
        """GET /credentials/{credential_id}."""
        return self._request("GET", f"/credentials/{credential_id}")

    def delete_credential(self, credential_id: str) -> None:
        """DELETE /credentials/{credential_id}."""
        self._request("DELETE", f"/credentials/{credential_id}")

    def rotate_credential_secret(self, credential_id: str) -> RotateSecretResponse:
        """POST /credentials/{credential_id}/rotate-secret."""
        return self._request("POST", f"/credentials/{credential_id}/rotate-secret")

    # ----- Sandbox -----
    def reset_sandbox(self, org_uuid: Optional[str] = None) -> SandboxResetResponse:
        """POST /api/sandbox/reset."""
        payload: dict = {}
        if org_uuid is not None:
            payload["org_uuid"] = org_uuid
        return self._request("POST", "/api/sandbox/reset", json=payload or None)

    # ----- Auth -----
    def register(
        self,
        email: str,
        password: str,
        org_name: str,
        app_uuid: str,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
    ) -> dict:
        """POST /api/auth/register.

        Args:
            email: The new user's email address.
            password: The new user's password.
            org_name: The organisation name (a different concept from app —
                an org owns users, an app routes auth).
            app_uuid: UUID of the target app (string-formatted UUID). This
                replaced the legacy ``app`` slug parameter. Example:
                ``"018f1234-5678-7000-8000-000000000001"``.
            first_name: Optional given name.
            last_name: Optional family name.
        """
        payload: dict = {
            "email": email,
            "password": password,
            "org_name": org_name,
            "app_uuid": app_uuid,
        }
        if first_name is not None:
            payload["first_name"] = first_name
        if last_name is not None:
            payload["last_name"] = last_name
        return self._request("POST", "/api/auth/register", json=payload, auth=False)

    def login(self, email: str, password: str, org_name: str, app_uuid: str) -> dict:
        """POST /api/auth/login.

        Args:
            email: The user's email address.
            password: The user's password.
            org_name: The organisation name.
            app_uuid: UUID of the target app (string-formatted UUID).
                Replaced the legacy ``app`` slug parameter.
        """
        payload = {
            "email": email,
            "password": password,
            "org_name": org_name,
            "app_uuid": app_uuid,
        }
        body = self._request("POST", "/api/auth/login", json=payload, auth=False)
        if isinstance(body, dict) and body.get("access_token"):
            self.api_key = body["access_token"]
        return body

    def lookup_organizations(self, email: str, app_uuid: str) -> dict:
        """POST /api/auth/organizations/lookup.

        Args:
            email: The email to look up.
            app_uuid: UUID of the target app (string-formatted UUID).
                Replaced the legacy ``app`` slug parameter.
        """
        payload = {"email": email, "app_uuid": app_uuid}
        return self._request(
            "POST", "/api/auth/organizations/lookup", json=payload, auth=False
        )

    def get_login_options(self, org_uuid: str) -> dict:
        """GET /api/auth/organizations/{org_uuid}/login-options."""
        return self._request("GET", f"/api/auth/organizations/{org_uuid}/login-options", auth=False)

    def get_status(self) -> dict:
        """GET /api/auth/status."""
        return self._request("GET", "/api/auth/status")

    def get_profile(self) -> dict:
        """GET /api/profile."""
        return self._request("GET", "/api/profile")

    def update_profile(self, **kwargs: Any) -> dict:
        """PUT /api/profile."""
        return self._request("PUT", "/api/profile", json=kwargs)

    def get_org_by_domain(self, domain: str) -> dict:
        """GET /api/auth/orgs-by-domain/{domain}."""
        return self._request("GET", f"/api/auth/orgs-by-domain/{domain}", auth=False)

    # ----- OTP -----
    def send_otp(self, phone: str, app_uuid: str) -> dict:
        """POST /api/auth/otp.

        Args:
            phone: The destination phone number in E.164 format.
            app_uuid: UUID of the target app (string-formatted UUID).
                Replaced the legacy ``app`` slug parameter.
        """
        return self._request(
            "POST",
            "/api/auth/otp",
            json={"phone": phone, "app_uuid": app_uuid},
            auth=False,
        )

    def verify_otp(self, phone: str, code: str, app_uuid: str) -> dict:
        """POST /api/auth/otp/verify.

        Args:
            phone: The phone number the OTP was sent to.
            code: The OTP code the user provided.
            app_uuid: UUID of the target app (string-formatted UUID).
                Replaced the legacy ``app`` slug parameter.
        """
        return self._request(
            "POST",
            "/api/auth/otp/verify",
            json={"phone": phone, "code": code, "app_uuid": app_uuid},
            auth=False,
        )


    # ----- MFA (extended) -----
    def mfa_verify(self, code: str) -> dict:
        """POST /api/auth/mfa/totp/verify."""
        return self._request("POST", "/api/auth/mfa/totp/verify", json={"code": code})

    def mfa_challenge(self) -> dict:
        """POST /api/auth/mfa/totp/challenge."""
        return self._request("POST", "/api/auth/mfa/totp/challenge")

    def mfa_disable(self) -> dict:
        """DELETE /api/auth/mfa/totp."""
        return self._request("DELETE", "/api/auth/mfa/totp")

    def mfa_generate_recovery_codes(self) -> dict:
        """POST /api/auth/mfa/recovery-codes."""
        return self._request("POST", "/api/auth/mfa/recovery-codes")

    def mfa_redeem_recovery_code(self, code: str) -> dict:
        """POST /api/auth/mfa/recovery-codes/redeem."""
        return self._request("POST", "/api/auth/mfa/recovery-codes/redeem", json={"code": code})

    # ----- Passkeys (WebAuthn) -----
    #
    # Thin HTTP wrappers around the four passkey ceremony endpoints. The
    # WebAuthn challenge / credential blobs are pass-through ``Any`` JSON —
    # the browser's ``navigator.credentials.create / .get`` APIs consume and
    # produce them directly. Begin endpoints unwrap the backend's
    # ``{"data": ...}`` envelope for ergonomics.

    def passkey_register_begin(self) -> PasskeyRegistrationChallenge:
        """POST /api/passkeys/register/begin.

        Start passkey registration. Requires an authenticated caller (the
        passkey is added to the user's existing account). Pass the returned
        ``challenge`` to ``navigator.credentials.create({publicKey: ...})``
        in the browser.
        """
        resp = self._request("POST", "/api/passkeys/register/begin")
        return resp.get("data", resp) if isinstance(resp, dict) else resp

    def passkey_register_complete(
        self, body: PasskeyRegistrationComplete
    ) -> PasskeyRegistrationResult:
        """POST /api/passkeys/register/complete.

        Finish passkey registration. ``body['credential']`` is the WebAuthn
        ``RegisterPublicKeyCredential`` returned by the browser.
        """
        resp = self._request(
            "POST", "/api/passkeys/register/complete", json=dict(body)
        )
        return resp.get("data", resp) if isinstance(resp, dict) else resp

    def passkey_authenticate_begin(self) -> PasskeyAuthChallenge:
        """POST /api/passkeys/authenticate/begin.

        Anonymous; no Authorization header required. Pass the returned
        ``challenge`` to ``navigator.credentials.get({publicKey: ...})``.
        """
        resp = self._request(
            "POST", "/api/passkeys/authenticate/begin", auth=False
        )
        return resp.get("data", resp) if isinstance(resp, dict) else resp

    def passkey_authenticate_complete(self, body: PasskeyAuthComplete) -> dict:
        """POST /api/passkeys/authenticate/complete.

        Returns the session payload (shape currently unstable on the
        backend).
        """
        return self._request(
            "POST",
            "/api/passkeys/authenticate/complete",
            json=dict(body),
            auth=False,
        )

    def list_my_passkeys(self) -> List[PasskeyListItem]:
        """GET /api/v1/me/passkeys.

        List the signed-in user's enrolled passkeys, in descending
        ``created_at`` order. Each row carries ``credential_uuid`` (for
        revocation) and ``credential_id_prefix`` (a 12-char display fragment
        of the full WebAuthn credential ID).
        """
        resp = self._request("GET", "/api/v1/me/passkeys")
        # Backend returns the list directly; tolerate a {"data": [...]}
        # envelope in case a proxy layer wraps it.
        if isinstance(resp, dict) and isinstance(resp.get("data"), list):
            return resp["data"]
        return resp if isinstance(resp, list) else []

    def delete_my_passkey(self, credential_uuid: str) -> dict:
        """DELETE /api/v1/me/passkeys/{credential_uuid}.

        Revoke one of the signed-in user's passkeys. The owner check is
        enforced on the backend; UUIDs owned by other users return 404.
        """
        return self._request(
            "DELETE", f"/api/v1/me/passkeys/{credential_uuid}"
        )

    # ----- SSO -----
    def oidc_authorize_url(self, connection_uuid: str) -> dict:
        """GET /api/auth/oidc/{connection_uuid}/authorize."""
        return self._request("GET", f"/api/auth/oidc/{connection_uuid}/authorize")

    def saml_authorize_url(self, connection_uuid: str) -> dict:
        """GET /api/auth/saml/{connection_uuid}/authorize."""
        return self._request("GET", f"/api/auth/saml/{connection_uuid}/authorize")

    # ----- Users -----
    def list_users(self, **filters: Any) -> list:
        """GET /api/users."""
        return self._request("GET", "/api/users", params=filters or None)

    def get_user_level(self, user_uuid: str) -> dict:
        """GET /api/users/{user_uuid}/level."""
        return self._request("GET", f"/api/users/{user_uuid}/level")

    def set_user_level(self, user_uuid: str, user_type: str) -> dict:
        """POST /api/users/{user_uuid}/level."""
        return self._request("POST", f"/api/users/{user_uuid}/level", json={"user_type": user_type})

    def update_user_status(self, user_uuid: str, active: bool) -> dict:
        """PUT /api/users/{user_uuid}/status."""
        return self._request("PUT", f"/api/users/{user_uuid}/status", json={"active": active})

    def update_user_role(self, user_uuid: str, role: str) -> dict:
        """PUT /api/users/{user_uuid}/role."""
        return self._request("PUT", f"/api/users/{user_uuid}/role", json={"role": role})

    # ----- Org Security -----
    def get_security_settings(self, org_uuid: str) -> dict:
        """GET /api/organizations/{org_uuid}/security-settings."""
        return self._request("GET", f"/api/organizations/{org_uuid}/security-settings")

    def update_security_settings(self, org_uuid: str, settings: dict) -> dict:
        """PUT /api/organizations/{org_uuid}/security-settings."""
        return self._request("PUT", f"/api/organizations/{org_uuid}/security-settings", json=settings)

    def list_sso_connections(self, org_uuid: str) -> list:
        """GET /api/organizations/{org_uuid}/sso-connections."""
        return self._request("GET", f"/api/organizations/{org_uuid}/sso-connections")

    def create_sso_connection(self, org_uuid: str, provider: str, name: str, config: dict) -> dict:
        """POST /api/organizations/{org_uuid}/sso-connections."""
        payload = {"provider": provider, "name": name, "config": config}
        return self._request("POST", f"/api/organizations/{org_uuid}/sso-connections", json=payload)

    def update_sso_connection(self, org_uuid: str, connection_uuid: str, data: dict) -> dict:
        """PUT /api/organizations/{org_uuid}/sso-connections/{connection_uuid}."""
        return self._request("PUT", f"/api/organizations/{org_uuid}/sso-connections/{connection_uuid}", json=data)

    def delete_sso_connection(self, org_uuid: str, connection_uuid: str) -> dict:
        """DELETE /api/organizations/{org_uuid}/sso-connections/{connection_uuid}."""
        return self._request("DELETE", f"/api/organizations/{org_uuid}/sso-connections/{connection_uuid}")

    def list_audit_events(self, org_uuid: str) -> list:
        """GET /api/organizations/{org_uuid}/audit-events."""
        return self._request("GET", f"/api/organizations/{org_uuid}/audit-events")

    def export_audit_events(self, org_uuid: str) -> dict:
        """GET /api/organizations/{org_uuid}/audit-events/export."""
        return self._request("GET", f"/api/organizations/{org_uuid}/audit-events/export")

    # ----- Branding -----
    def get_branding(self, org_uuid: str) -> dict:
        """GET /api/organizations/{org_uuid}/branding."""
        return self._request("GET", f"/api/organizations/{org_uuid}/branding")

    def update_branding(self, org_uuid: str, branding: dict) -> dict:
        """PUT /api/organizations/{org_uuid}/branding."""
        return self._request("PUT", f"/api/organizations/{org_uuid}/branding", json=branding)

    # ----- Sessions (extended) -----
    def org_session_inventory(self, org_uuid: str) -> dict:
        """GET /api/organizations/{org_uuid}/session-inventory."""
        return self._request("GET", f"/api/organizations/{org_uuid}/session-inventory")

    def org_revoke_all_sessions(self, org_uuid: str) -> dict:
        """POST /api/organizations/{org_uuid}/revoke-all-sessions."""
        return self._request("POST", f"/api/organizations/{org_uuid}/revoke-all-sessions")

    def list_device_accounts(self, device_uuid: str) -> list:
        """GET /api/devices/{device_uuid}/accounts."""
        return self._request("GET", f"/api/devices/{device_uuid}/accounts")

    def add_device_account(self, device_uuid: str, email: str, org_name: str, org_uuid: str) -> dict:
        """POST /api/devices/{device_uuid}/accounts."""
        payload = {"email": email, "org_name": org_name, "org_uuid": org_uuid}
        return self._request("POST", f"/api/devices/{device_uuid}/accounts", json=payload)

    def delete_device_accounts(self, device_uuid: str) -> dict:
        """DELETE /api/devices/{device_uuid}/accounts."""
        return self._request("DELETE", f"/api/devices/{device_uuid}/accounts")

    def delete_device_account(self, device_uuid: str, account_uuid: str) -> dict:
        """DELETE /api/devices/{device_uuid}/accounts/{account_uuid}."""
        return self._request("DELETE", f"/api/devices/{device_uuid}/accounts/{account_uuid}")

    def switch_device_active_account(self, device_uuid: str, account_uuid: str) -> dict:
        """POST /api/devices/{device_uuid}/active-account."""
        return self._request("POST", f"/api/devices/{device_uuid}/active-account", json={"account_uuid": account_uuid})

    def device_session_inventory(self, device_uuid: str) -> dict:
        """GET /api/devices/{device_uuid}/session-inventory."""
        return self._request("GET", f"/api/devices/{device_uuid}/session-inventory")

    def revoke_all_device_sessions(self, device_uuid: str) -> dict:
        """POST /api/devices/{device_uuid}/revoke-all."""
        return self._request("POST", f"/api/devices/{device_uuid}/revoke-all")

    # ----- API Keys v2 -----
    def list_api_keys_v2(self, org_uuid: str) -> list:
        """GET /api/v2/organizations/{org_uuid}/api-keys."""
        return self._request("GET", f"/api/v2/organizations/{org_uuid}/api-keys")

    def create_api_key_v2(self, org_uuid: str, name: str) -> dict:
        """POST /api/v2/organizations/{org_uuid}/api-keys."""
        return self._request("POST", f"/api/v2/organizations/{org_uuid}/api-keys", json={"name": name})

    def delete_api_key_v2(self, org_uuid: str, key_uuid: str) -> dict:
        """DELETE /api/v2/organizations/{org_uuid}/api-keys/{key_uuid}."""
        return self._request("DELETE", f"/api/v2/organizations/{org_uuid}/api-keys/{key_uuid}")

    # ----- Service Identities -----
    def list_service_identities(self, org_uuid: str) -> list:
        """GET /api/organizations/{org_uuid}/service-identities."""
        return self._request("GET", f"/api/organizations/{org_uuid}/service-identities")

    def create_service_identity(self, org_uuid: str, payload: dict) -> dict:
        """POST /api/organizations/{org_uuid}/service-identities."""
        return self._request("POST", f"/api/organizations/{org_uuid}/service-identities", json=payload)

    def delete_service_identity(self, org_uuid: str, key_uuid: str) -> dict:
        """DELETE /api/organizations/{org_uuid}/service-identities/{key_uuid}."""
        return self._request("DELETE", f"/api/organizations/{org_uuid}/service-identities/{key_uuid}")

    def create_service_identity_automation_token(self, org_uuid: str, payload: dict) -> dict:
        """POST /api/organizations/{org_uuid}/service-identities/automation-token."""
        return self._request("POST", f"/api/organizations/{org_uuid}/service-identities/automation-token", json=payload)

    # ----- Entitlements -----
    def entitlements_check(self, feature: str, org_uuid: Optional[str] = None) -> dict:
        """POST /api/entitlements/check."""
        payload: dict = {"feature": feature}
        if org_uuid is not None:
            payload["org_uuid"] = org_uuid
        return self._request("POST", "/api/entitlements/check", json=payload)

    def entitlements_check_batch(self, checks: list) -> dict:
        """POST /api/entitlements/check/batch."""
        return self._request("POST", "/api/entitlements/check/batch", json={"checks": checks})

    def entitlements_effective(self) -> dict:
        """GET /api/entitlements/effective."""
        return self._request("GET", "/api/entitlements/effective")

    def admin_entitlements_explain(self, payload: dict) -> dict:
        """POST /api/admin/entitlements/explain."""
        return self._request("POST", "/api/admin/entitlements/explain", json=payload)

    # ----- Pricing -----
    def pricing_preview(self, payload: dict) -> dict:
        """POST /api/pricing/preview."""
        return self._request("POST", "/api/pricing/preview", json=payload)

    def pricing_quote(self, payload: dict) -> dict:
        """POST /api/pricing/quote."""
        return self._request("POST", "/api/pricing/quote", json=payload)

    def pricing_checkout_session(self, payload: dict) -> dict:
        """POST /api/pricing/checkout-session."""
        return self._request("POST", "/api/pricing/checkout-session", json=payload)

    def admin_pricing_explain(self, payload: dict) -> dict:
        """POST /api/admin/pricing/explain."""
        return self._request("POST", "/api/admin/pricing/explain", json=payload)

    def catalog_pricing_preview(self, payload: dict) -> dict:
        """POST /api/catalog/pricing/preview."""
        return self._request("POST", "/api/catalog/pricing/preview", json=payload)

    # ----- Coupons Admin -----
    def admin_list_product_coupons(self, product_id: str) -> list:
        """GET /api/admin/products/{product_id}/coupons."""
        return self._request("GET", f"/api/admin/products/{product_id}/coupons")

    def admin_create_product_coupon(self, product_id: str, coupon: dict) -> dict:
        """POST /api/admin/products/{product_id}/coupons."""
        return self._request("POST", f"/api/admin/products/{product_id}/coupons", json=coupon)

    def admin_update_product_coupon(self, product_id: str, coupon_id: str, coupon: dict) -> dict:
        """PUT /api/admin/products/{product_id}/coupons/{coupon_id}."""
        return self._request("PUT", f"/api/admin/products/{product_id}/coupons/{coupon_id}", json=coupon)

    def admin_delete_product_coupon(self, product_id: str, coupon_id: str) -> dict:
        """DELETE /api/admin/products/{product_id}/coupons/{coupon_id}."""
        return self._request("DELETE", f"/api/admin/products/{product_id}/coupons/{coupon_id}")

    # ----- Labels -----
    def set_coupon_labels(self, coupon_id: str, labels: list) -> dict:
        """PUT /api/admin/coupons/{id}/labels."""
        return self._request("PUT", f"/api/admin/coupons/{coupon_id}/labels", json={"labels": labels})

    def add_coupon_label(self, coupon_id: str, label: str) -> dict:
        """POST /api/admin/coupons/{id}/labels."""
        return self._request("POST", f"/api/admin/coupons/{coupon_id}/labels", json={"label": label})

    def remove_coupon_label(self, coupon_id: str, label: str) -> dict:
        """DELETE /api/admin/coupons/{id}/labels/{label}."""
        return self._request("DELETE", f"/api/admin/coupons/{coupon_id}/labels/{label}")

    def set_product_tags(self, product_id: str, tags: list) -> dict:
        """PUT /api/admin/products/{id}/tags."""
        return self._request("PUT", f"/api/admin/products/{product_id}/tags", json={"tags": tags})

    def add_product_tag(self, product_id: str, tag: str) -> dict:
        """POST /api/admin/products/{id}/tags."""
        return self._request("POST", f"/api/admin/products/{product_id}/tags", json={"tag": tag})

    def remove_product_tag(self, product_id: str, tag: str) -> dict:
        """DELETE /api/admin/products/{id}/tags/{tag}."""
        return self._request("DELETE", f"/api/admin/products/{product_id}/tags/{tag}")

    # ----- Analytics -----
    def ingest_analytics_event(self, event: dict) -> dict:
        """POST /api/analytics/events."""
        return self._request("POST", "/api/analytics/events", json=event)

    def analytics_app_overview(self, app_uuid: str) -> dict:
        """GET /api/analytics/apps/{app_uuid}/overview."""
        return self._request("GET", f"/api/analytics/apps/{app_uuid}/overview")

    def analytics_org_overview(self, org_uuid: str) -> dict:
        """GET /api/analytics/organizations/{org_uuid}/overview."""
        return self._request("GET", f"/api/analytics/organizations/{org_uuid}/overview")

    # ----- Teams -----
    def create_team(self, payload: dict) -> dict:
        """POST /api/teams."""
        return self._request("POST", "/api/teams", json=payload)

    def list_org_teams(self, org_uuid: str) -> list:
        """GET /api/organizations/{org_uuid}/teams."""
        return self._request("GET", f"/api/organizations/{org_uuid}/teams")

    def list_inactive_teams(self, org_uuid: str) -> list:
        """GET /api/teams/org/{org_uuid}/inactive."""
        return self._request("GET", f"/api/teams/org/{org_uuid}/inactive")

    def reactivate_team(self, team_uuid: str) -> dict:
        """POST /api/teams/lifecycle/{team_uuid}/reactivate."""
        return self._request("POST", f"/api/teams/lifecycle/{team_uuid}/reactivate")

    def archive_team(self, team_uuid: str) -> dict:
        """DELETE /api/teams/lifecycle/{team_uuid}."""
        return self._request("DELETE", f"/api/teams/lifecycle/{team_uuid}")

    def list_team_members(self, team_uuid: str) -> list:
        """GET /api/teams/{team_uuid}/members."""
        return self._request("GET", f"/api/teams/{team_uuid}/members")

    def add_team_member(self, team_uuid: str, user_uuid: str) -> dict:
        """POST /api/teams/{team_uuid}/members."""
        return self._request("POST", f"/api/teams/{team_uuid}/members", json={"user_uuid": user_uuid})

    def remove_team_member(self, team_uuid: str, user_uuid: str) -> dict:
        """DELETE /api/teams/{team_uuid}/members/{user_uuid}."""
        return self._request("DELETE", f"/api/teams/{team_uuid}/members/{user_uuid}")

    def list_team_observers(self, team_uuid: str) -> list:
        """GET /api/teams/{team_uuid}/observers."""
        return self._request("GET", f"/api/teams/{team_uuid}/observers")

    def add_team_observer(self, team_uuid: str, user_uuid: str) -> dict:
        """POST /api/teams/{team_uuid}/observers."""
        return self._request("POST", f"/api/teams/{team_uuid}/observers", json={"user_uuid": user_uuid})

    def remove_team_observer(self, team_uuid: str, user_uuid: str) -> dict:
        """DELETE /api/teams/{team_uuid}/observers/{user_uuid}."""
        return self._request("DELETE", f"/api/teams/{team_uuid}/observers/{user_uuid}")

    def get_user_teams(self, user_uuid: str) -> list:
        """GET /api/users/{user_uuid}/teams."""
        return self._request("GET", f"/api/users/{user_uuid}/teams")

    def get_user_observed_teams(self, user_uuid: str) -> list:
        """GET /api/users/{user_uuid}/observed-teams."""
        return self._request("GET", f"/api/users/{user_uuid}/observed-teams")

    # ----- Org Features -----
    def list_org_features(self, org_uuid: str) -> list:
        """GET /api/organizations/{org_uuid}/features."""
        return self._request("GET", f"/api/organizations/{org_uuid}/features")

    def set_org_feature(self, org_uuid: str, feature: dict) -> dict:
        """POST /api/organizations/{org_uuid}/features."""
        return self._request("POST", f"/api/organizations/{org_uuid}/features", json=feature)

    def remove_org_feature(self, org_uuid: str, feature_id: str) -> dict:
        """DELETE /api/organizations/{org_uuid}/features/{feature_id}."""
        return self._request("DELETE", f"/api/organizations/{org_uuid}/features/{feature_id}")

    # ----- Roles -----
    def list_roles(self) -> list:
        """GET /api/roles."""
        return self._request("GET", "/api/roles")

    def list_all_permissions(self) -> list:
        """GET /api/roles/permissions."""
        return self._request("GET", "/api/roles/permissions")

    def get_role_permissions(self, role_id: str) -> dict:
        """GET /api/roles/{role_id}/permissions."""
        return self._request("GET", f"/api/roles/{role_id}/permissions")

    def update_role_permissions(self, role_id: str, permissions: list) -> dict:
        """PUT /api/roles/{role_id}/permissions."""
        return self._request("PUT", f"/api/roles/{role_id}/permissions", json={"permissions": permissions})

    # ----- RBAC -----
    def get_product_permissions(self, product_id: str) -> dict:
        """GET /api/v2/products/{product_id}/permissions."""
        return self._request("GET", f"/api/v2/products/{product_id}/permissions")

    def create_product_role(self, product_id: str, role_data: dict) -> dict:
        """POST /api/v2/products/{product_id}/roles."""
        return self._request("POST", f"/api/v2/products/{product_id}/roles", json=role_data)

    def get_assignable_roles(self, org_uuid: str, product_id: str) -> list:
        """GET /api/v2/organizations/{org_uuid}/products/{product_id}/roles."""
        return self._request("GET", f"/api/v2/organizations/{org_uuid}/products/{product_id}/roles")

    def assign_role_to_user(self, org_uuid: str, user_uuid: str, role_id: str) -> dict:
        """PUT /api/v2/organizations/{org_uuid}/users/{user_uuid}/role."""
        return self._request("PUT", f"/api/v2/organizations/{org_uuid}/users/{user_uuid}/role", json={"role_id": role_id})

    # ----- Billing -----
    def checkout(
        self,
        price_id: str,
        coupon_code: Optional[str] = None,
        add_ons: Optional[list] = None,
    ) -> dict:
        """POST /api/billing/checkout."""
        payload: dict = {"price_id": price_id}
        if coupon_code is not None:
            payload["coupon_code"] = coupon_code
        if add_ons is not None:
            payload["add_ons"] = add_ons
        return self._request("POST", "/api/billing/checkout", json=payload)

    def get_billing_history(self) -> list:
        """GET /api/billing/history."""
        return self._request("GET", "/api/billing/history")

    def list_invoices(self) -> list:
        """GET /api/billing/invoices."""
        return self._request("GET", "/api/billing/invoices")

    def get_provider_config(self, provider: str) -> dict:
        """GET /api/billing/config/{provider}."""
        return self._request("GET", f"/api/billing/config/{provider}")

    def add_add_on(self, add_on: dict) -> dict:
        """POST /api/billing/subscriptions/add-on."""
        return self._request("POST", "/api/billing/subscriptions/add-on", json=add_on)

    def wallet(self) -> dict:
        """GET /api/wallet."""
        return self._request("GET", "/api/wallet")

    # ----- Environments -----
    def list_environments(self) -> list:
        """GET /api/environments."""
        return self._request("GET", "/api/environments")

    # ----- Plaid -----
    def plaid_create_link_token(self, payload: dict) -> dict:
        """POST /api/plaid/create-link-token."""
        return self._request("POST", "/api/plaid/create-link-token", json=payload)

    def plaid_exchange_public_token(self, public_token: str) -> dict:
        """POST /api/plaid/exchange-public-token."""
        return self._request("POST", "/api/plaid/exchange-public-token", json={"public_token": public_token})

    def plaid_accounts(self) -> list:
        """GET /api/plaid/accounts."""
        return self._request("GET", "/api/plaid/accounts")

    # ----- Usage -----
    def usage_report(self, payload: dict) -> dict:
        """POST /api/usage/report."""
        return self._request("POST", "/api/usage/report", json=payload)

    # ----- Help -----
    def help_root(self) -> dict:
        """GET /api/help."""
        return self._request("GET", "/api/help", auth=False)

    def help_search(self, query: str) -> dict:
        """GET /api/help/search?q={query}."""
        return self._request("GET", "/api/help/search", params={"q": query}, auth=False)

    def help_category(self, slug: str) -> dict:
        """GET /api/help/categories/{slug}."""
        return self._request("GET", f"/api/help/categories/{slug}", auth=False)

    def help_article(self, slug: str) -> dict:
        """GET /api/help/articles/{slug}."""
        return self._request("GET", f"/api/help/articles/{slug}", auth=False)

    # ----- Search -----
    def search_index(self, payload: dict) -> dict:
        """POST /api/v2/search/index."""
        return self._request("POST", "/api/v2/search/index", json=payload)

    def search_query(self, q: str, filters: Optional[dict] = None) -> dict:
        """POST /api/v2/search/query."""
        payload: dict = {"q": q}
        if filters is not None:
            payload["filters"] = filters
        return self._request("POST", "/api/v2/search/query", json=payload)

    def search_chat(self, q: str, options: Optional[dict] = None) -> dict:
        """POST /api/v2/search/chat."""
        payload: dict = {"q": q}
        if options is not None:
            payload["options"] = options
        return self._request("POST", "/api/v2/search/chat", json=payload)

    # ----- AI Gateway -----
    def ai_chat_completions(self, org_uuid: str, provider: str, payload: dict) -> dict:
        """POST gateway.buttrbase.com/v1/chat/completions."""
        headers = self._headers(auth=True)
        headers["x-buttrbase-target-org"] = org_uuid
        headers["x-buttrbase-provider"] = provider
        resp = self._session.post(
            "https://gateway.buttrbase.com/v1/chat/completions",
            json=payload,
            headers=headers,
            timeout=self.timeout,
        )
        return self._handle(resp)

    # ----- Signing Keys (extended) -----
    def list_signing_keys(self, org_uuid: str) -> list:
        """GET /api/admin/organizations/{org_uuid}/signing-keys."""
        return self._request("GET", f"/api/admin/organizations/{org_uuid}/signing-keys")

    def rotate_signing_keys(self, org_uuid: str) -> dict:
        """POST /api/admin/organizations/{org_uuid}/signing-keys/rotate."""
        return self._request("POST", f"/api/admin/organizations/{org_uuid}/signing-keys/rotate")

    def list_signing_audit(self, org_uuid: str) -> list:
        """GET /api/admin/organizations/{org_uuid}/signing-audit."""
        return self._request("GET", f"/api/admin/organizations/{org_uuid}/signing-audit")

    def sign_document(self, org_uuid: str, document: dict) -> dict:
        """POST /api/orgs/{org_uuid}/sign-document."""
        return self._request("POST", f"/api/orgs/{org_uuid}/sign-document", json=document)

    # ----- mTLS CA -----
    def get_ca(self, org_uuid: str) -> dict:
        """GET /api/admin/organizations/{org_uuid}/certificate-authority."""
        return self._request("GET", f"/api/admin/organizations/{org_uuid}/certificate-authority")

    def init_ca(self, org_uuid: str, config: dict) -> dict:
        """POST /api/admin/organizations/{org_uuid}/certificate-authority/init."""
        return self._request("POST", f"/api/admin/organizations/{org_uuid}/certificate-authority/init", json=config)

    def list_certificates(self, org_uuid: str) -> list:
        """GET /api/admin/organizations/{org_uuid}/certificates."""
        return self._request("GET", f"/api/admin/organizations/{org_uuid}/certificates")

    def issue_certificate(self, org_uuid: str, csr: dict) -> dict:
        """POST /api/admin/organizations/{org_uuid}/certificates."""
        return self._request("POST", f"/api/admin/organizations/{org_uuid}/certificates", json=csr)

    def revoke_certificate(self, org_uuid: str, serial: str) -> dict:
        """POST /api/admin/organizations/{org_uuid}/certificates/{serial}/revoke."""
        return self._request("POST", f"/api/admin/organizations/{org_uuid}/certificates/{serial}/revoke")

    # ----- Zero Trust (extended) -----
    def purge_auth_events(self, org_uuid: str) -> dict:
        """POST /api/admin/organizations/{org_uuid}/auth-events/purge."""
        return self._request("POST", f"/api/admin/organizations/{org_uuid}/auth-events/purge")

    def kms_status(self, org_uuid: str) -> dict:
        """GET /api/admin/organizations/{org_uuid}/kms-status."""
        return self._request("GET", f"/api/admin/organizations/{org_uuid}/kms-status")

    def saml_cert_rollover(self, org_uuid: str, connection_uuid: str, payload: dict) -> dict:
        """PATCH /api/admin/organizations/{org_uuid}/sso/{connection_uuid}/saml-cert."""
        return self._request("PATCH", f"/api/admin/organizations/{org_uuid}/sso/{connection_uuid}/saml-cert", json=payload)

    def update_payment_settings(self, org_uuid: str, settings: dict) -> dict:
        """PATCH /api/admin/organizations/{org_uuid}/payment-settings."""
        return self._request("PATCH", f"/api/admin/organizations/{org_uuid}/payment-settings", json=settings)

    # ----- Secrets (extended) -----
    def list_secrets(self, org_uuid: str) -> list:
        """GET /api/admin/organizations/{org_uuid}/secrets."""
        return self._request("GET", f"/api/admin/organizations/{org_uuid}/secrets")

    def delete_secret(self, org_uuid: str, name: str) -> dict:
        """DELETE /api/admin/organizations/{org_uuid}/secrets/{name}."""
        return self._request("DELETE", f"/api/admin/organizations/{org_uuid}/secrets/{name}")

    # ----- Admin Portal -----
    def admin_portal_issue(self, org_uuid: str) -> dict:
        """POST /api/admin/organizations/{org_uuid}/admin-portal/issue."""
        return self._request("POST", f"/api/admin/organizations/{org_uuid}/admin-portal/issue")

    def admin_portal_exchange(self, token: str) -> dict:
        """POST /api/admin-portal/exchange."""
        return self._request("POST", "/api/admin-portal/exchange", json={"token": token})

    # ----- Domains -----
    def list_domains(self, org_uuid: str) -> list:
        """GET /api/admin/organizations/{org_uuid}/domains."""
        return self._request("GET", f"/api/admin/organizations/{org_uuid}/domains")

    def create_domain(self, org_uuid: str, domain: str) -> dict:
        """POST /api/admin/organizations/{org_uuid}/domains."""
        return self._request("POST", f"/api/admin/organizations/{org_uuid}/domains", json={"domain": domain})

    def verify_domain(self, org_uuid: str, domain_id: str) -> dict:
        """POST /api/admin/organizations/{org_uuid}/domains/{id}/verify."""
        return self._request("POST", f"/api/admin/organizations/{org_uuid}/domains/{domain_id}/verify")

    def delete_domain(self, org_uuid: str, domain_id: str) -> dict:
        """DELETE /api/admin/organizations/{org_uuid}/domains/{id}."""
        return self._request("DELETE", f"/api/admin/organizations/{org_uuid}/domains/{domain_id}")

    # ----- Webhooks Admin -----
    def list_webhook_endpoints(self, org_uuid: str) -> list:
        """GET /api/admin/organizations/{org_uuid}/webhook-endpoints."""
        return self._request("GET", f"/api/admin/organizations/{org_uuid}/webhook-endpoints")

    def create_webhook_endpoint(self, org_uuid: str, url: str, events: list) -> dict:
        """POST /api/admin/organizations/{org_uuid}/webhook-endpoints."""
        return self._request("POST", f"/api/admin/organizations/{org_uuid}/webhook-endpoints", json={"url": url, "events": events})

    def delete_webhook_endpoint(self, org_uuid: str, endpoint_id: str) -> dict:
        """DELETE /api/admin/organizations/{org_uuid}/webhook-endpoints/{id}."""
        return self._request("DELETE", f"/api/admin/organizations/{org_uuid}/webhook-endpoints/{endpoint_id}")

    def list_webhook_deliveries(self, org_uuid: str) -> list:
        """GET /api/admin/organizations/{org_uuid}/webhook-deliveries."""
        return self._request("GET", f"/api/admin/organizations/{org_uuid}/webhook-deliveries")

    # ----- SCIM -----
    def issue_scim_token(self, org_uuid: str) -> dict:
        """POST /api/admin/organizations/{org_uuid}/scim-tokens."""
        return self._request("POST", f"/api/admin/organizations/{org_uuid}/scim-tokens")

    # ----- Payments -----
    def create_payment_checkout(
        self,
        amount: int,
        currency: str,
        country: str,
        org_uuid: Optional[str] = None,
    ) -> dict:
        """POST /api/payments/checkout."""
        payload: dict = {"amount": amount, "currency": currency, "country": country}
        if org_uuid is not None:
            payload["org_uuid"] = org_uuid
        return self._request("POST", "/api/payments/checkout", json=payload)

    def send_invoice(
        self,
        amount: int,
        currency: str,
        app_uuid: str,
        customer_phone: Optional[str] = None,
        customer_email: Optional[str] = None,
    ) -> dict:
        """POST /api/payments/invoices/send."""
        payload: dict = {"amount": amount, "currency": currency, "app_uuid": app_uuid}
        if customer_phone is not None:
            payload["customer_phone"] = customer_phone
        if customer_email is not None:
            payload["customer_email"] = customer_email
        return self._request("POST", "/api/payments/invoices/send", json=payload)

    # ----- SMS -----
    def send_sms(
        self,
        phone: str,
        message: str,
        scheme: Optional[str] = None,
        app_uuid: Optional[str] = None,
    ) -> dict:
        """POST /api/sms/send_sms."""
        payload: dict = {"phone": phone, "message": message}
        if scheme is not None:
            payload["scheme"] = scheme
        if app_uuid is not None:
            payload["app_uuid"] = app_uuid
        return self._request("POST", "/api/sms/send_sms", json=payload)

    # ----- Email -----
    def verify_email_identity(
        self,
        email: str,
        aws_access_key_id: str,
        aws_secret_access_key: str,
        aws_region: Optional[str] = None,
    ) -> dict:
        """POST /api/email/verify-identity."""
        payload: dict = {
            "email": email,
            "aws_access_key_id": aws_access_key_id,
            "aws_secret_access_key": aws_secret_access_key,
        }
        if aws_region is not None:
            payload["aws_region"] = aws_region
        return self._request("POST", "/api/email/verify-identity", json=payload)

    # ----- Jobs & Notifications -----
    def enqueue_job(self, name: str, payload: dict) -> dict:
        """POST /api/v2/jobs/enqueue."""
        return self._request("POST", "/api/v2/jobs/enqueue", json={"name": name, "payload": payload})

    def send_notification(self, payload: dict) -> dict:
        """POST /api/v2/notifications/send."""
        return self._request("POST", "/api/v2/notifications/send", json=payload)

    def list_notifications(self) -> list:
        """GET /api/v2/notifications."""
        return self._request("GET", "/api/v2/notifications")

    # ----- Custom Variables -----
    def get_custom_variable(self, key: str) -> dict:
        """GET /api/v2/custom-variables/{key}."""
        return self._request("GET", f"/api/v2/custom-variables/{key}")

    def set_custom_variable(self, key: str, value: Any, scope: Optional[str] = None) -> dict:
        """POST /api/v2/custom-variables."""
        payload: dict = {"key": key, "value": value}
        if scope is not None:
            payload["scope"] = scope
        return self._request("POST", "/api/v2/custom-variables", json=payload)

    # ----- Webhooks (legacy) -----
    def register_webhook(self, url: str, events: list, org_uuid: Optional[str] = None) -> dict:
        """POST /api/v2/webhooks."""
        payload: dict = {"url": url, "events": events}
        if org_uuid is not None:
            payload["org_uuid"] = org_uuid
        return self._request("POST", "/api/v2/webhooks", json=payload or None)

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
        """POST /api/auth/invite/accept."""
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
        """GET /api/auth/orgs/check?name={name}."""
        return self._request("GET", "/api/auth/orgs/check", params={"name": name}, auth=False)

    def get_superuser_flag(self, email: str) -> SuperuserResponse:
        """GET /api/auth/superuser?email={email}."""
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
        """POST /api/contact."""
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
        """POST /api/contact-us."""
        payload: dict = {"name": name, "email": email, "subject": subject, "message": message}
        return self._request("POST", "/api/contact-us", json=payload, auth=False)

    # ----- Geo / IP -----
    def get_client_ip(self) -> GeoResponse:
        """GET /api/geo/ip."""
        return self._request("GET", "/api/geo/ip", auth=False)

    # ===== API key exchange (anonymous) =====
    def exchange_api_key(self, api_key: str) -> ExchangeResponse:
        """POST /api/v1/auth/api-key/exchange — initial exchange.

        Trade a long-lived ``short_lived`` raw key (``wb_<env>_<random>``)
        for a short-lived access JWT plus a 90-day rotating refresh
        token. The raw key is never sent on hot-path requests after this.

        Args:
            api_key: The raw key returned exactly once from
                ``create_app_api_key`` / ``rotate_app_api_key``.
        """
        return self._request(
            "POST",
            "/api/v1/auth/api-key/exchange",
            json={"api_key": api_key},
            auth=False,
        )

    def exchange_refresh_token(self, refresh_token: str) -> ExchangeResponse:
        """POST /api/v1/auth/api-key/exchange — refresh exchange.

        Trade an opaque refresh token from a previous exchange for a
        fresh access/refresh pair. The presented refresh token is
        immediately revoked — refresh is one-time-use.
        """
        return self._request(
            "POST",
            "/api/v1/auth/api-key/exchange",
            json={"refresh_token": refresh_token},
            auth=False,
        )

    # ===== OAuth start URL helper =====
    def oauth_start_url(self, provider: str, app_uuid: str, return_to: str) -> str:
        """Build the public OAuth ``/start`` URL.

        Returns the URL string only — no network call is made. Redirect
        the user-agent to it; the backend will 302 onward to the
        provider's authorize endpoint with a signed ``state``.

        Args:
            provider: ``google``, ``microsoft``, ``github``, or ``apple``.
                Only ``google``/``microsoft`` have authorize-URL builders
                wired today; the others 400 with ``unsupported provider``.
            app_uuid: UUID of the target app (string-formatted UUID).
            return_to: The post-callback URL — must exactly match one of
                the ``redirect_uris`` registered on the OAuth config.
        """
        query = urlencode({"app_uuid": app_uuid, "return_to": return_to})
        return f"{self.base_url}/api/v1/auth/oauth/{provider}/start?{query}"

    # ===== App-level API keys (admin) =====
    def list_app_api_keys(self, app_uuid: str) -> list:
        """GET /api/v1/apps/:app_uuid/api-keys.

        Returns every key for the app — including revoked ones —
        without ``raw_key``. Each row is an ``ApiKeySummary``.
        """
        return self._request("GET", f"/api/v1/apps/{app_uuid}/api-keys")

    def create_app_api_key(
        self, app_uuid: str, input: CreateApiKeyInput
    ) -> CreatedKeyResponse:
        """POST /api/v1/apps/:app_uuid/api-keys.

        ``raw_key`` is returned **exactly once** — the server stores
        only the SHA-256 hash and cannot recover it later. If you don't
        save it on this call, you'll need to rotate to get a new one.

        For ``key_type == "expiring"`` set ``expiry`` to either
        ``{"absolute": "<RFC3339>"}`` or ``{"in_days": N}``. Both
        resolve to a UTC timestamp at create time.
        """
        return self._request(
            "POST", f"/api/v1/apps/{app_uuid}/api-keys", json=dict(input)
        )

    def revoke_app_api_key(self, app_uuid: str, key_uuid: str) -> None:
        """DELETE /api/v1/apps/:app_uuid/api-keys/:key_uuid.

        Idempotent — revoking an already-revoked key is a no-op. Also
        invalidates every refresh token issued against this key.
        """
        self._request("DELETE", f"/api/v1/apps/{app_uuid}/api-keys/{key_uuid}")

    def rotate_app_api_key(
        self, app_uuid: str, key_uuid: str
    ) -> CreatedKeyResponse:
        """POST /api/v1/apps/:app_uuid/api-keys/:key_uuid/rotate.

        Issues a new key with the same name (suffixed ``(rotated)``),
        type, and env as the original, then revokes the old one.
        Returns the same shape as create — ``raw_key`` shown once.
        """
        return self._request(
            "POST", f"/api/v1/apps/{app_uuid}/api-keys/{key_uuid}/rotate"
        )

    # ===== OAuth configs (admin) =====
    def list_oauth_configs(self, app_uuid: str) -> list:
        """GET /api/v1/apps/:app_uuid/oauth-configs.

        Returns every configured provider for the app. ``client_secret``
        is **never** returned. Each row is an ``OAuthConfigSummary``.
        """
        return self._request("GET", f"/api/v1/apps/{app_uuid}/oauth-configs")

    def create_oauth_config(
        self, app_uuid: str, input: CreateOAuthConfigInput
    ) -> OAuthConfigSummary:
        """POST /api/v1/apps/:app_uuid/oauth-configs.

        Every ``redirect_uris`` entry must be ``https://…`` or
        ``http://localhost…`` — plain http to non-localhost is rejected.
        """
        return self._request(
            "POST", f"/api/v1/apps/{app_uuid}/oauth-configs", json=dict(input)
        )

    def update_oauth_config(
        self,
        app_uuid: str,
        provider: str,
        patch: UpdateOAuthConfigInput,
    ) -> OAuthConfigSummary:
        """PATCH /api/v1/apps/:app_uuid/oauth-configs/:provider.

        Every field is optional. ``client_secret`` only rotates when
        sent as a non-empty value — sending ``""`` or omitting it
        leaves the stored ciphertext untouched.
        """
        return self._request(
            "PATCH",
            f"/api/v1/apps/{app_uuid}/oauth-configs/{provider}",
            json=dict(patch),
        )

    def delete_oauth_config(self, app_uuid: str, provider: str) -> None:
        """DELETE /api/v1/apps/:app_uuid/oauth-configs/:provider."""
        self._request("DELETE", f"/api/v1/apps/{app_uuid}/oauth-configs/{provider}")

    # ===== Audit log =====
    def read_audit_log(
        self,
        app_uuid: str,
        limit: Optional[int] = None,
        action_prefix: Optional[str] = None,
    ) -> list:
        """GET /api/v1/apps/:app_uuid/audit-log.

        Args:
            app_uuid: UUID of the target app.
            limit: Cap on number of rows returned (server enforces an
                upper bound).
            action_prefix: Optional action-string prefix filter — e.g.
                ``"api_key."`` returns only key lifecycle events.
        """
        params: dict = {}
        if limit is not None:
            params["limit"] = limit
        if action_prefix is not None:
            params["action_prefix"] = action_prefix
        return self._request(
            "GET",
            f"/api/v1/apps/{app_uuid}/audit-log",
            params=params or None,
        )
