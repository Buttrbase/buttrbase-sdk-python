"""ButtrBase API client."""
from __future__ import annotations

import email.utils
import random
import time
import warnings
from typing import Any, List, Optional

import requests

from urllib.parse import urlencode

from .errors import ButtrbaseError
from .types import (
    AcceptInvitationResponse,
    AppRpConfig,
    AuditRow,
    CheckOrgNameResponse,
    ContactSubmitResponse,
    CreateCredentialResponse,
    CreateInvitationRequest,
    CreateOAuthConfigInput,
    Credential,
    DeviceItem,
    FinalizeRegistrationRequest,
    GeoResponse,
    InvitationListItem,
    InvitationPreview,
    InvitationResponse,
    InviteAcceptResponse,
    OAuthConfigSummary,
    OrgCheckResponse,
    PasskeyAuthChallenge,
    PasskeyAuthComplete,
    PasskeyListItem,
    PasskeyRegistrationChallenge,
    PasskeyRegistrationComplete,
    PasskeyRegistrationResult,
    RegistrationResult,
    RevokeDeviceResponse,
    RotateSecretResponse,
    SandboxResetResponse,
    ScopeContextResponse,
    SuperuserResponse,
    TenantHome,
    TokenPair,
    UpdateAppRpConfigRequest,
    UpdateOAuthConfigInput,
    PasswordResetRequestResponse,
    PasswordResetResponse,
    WebhookListResponse,
    Webhook,
    WebhookDelivery,
    WebhookDeliveryRetryResponse,
    OAuthRefreshResponse,
    EmailSendResponse,
)

DEFAULT_BASE_URL = "https://stagingapi.buttrbase.com"

# HTTP statuses that are safe to retry. 502/503/504 are emitted by the gateway
# when the backend (which can scale to zero) has not processed the request —
# safe to replay for any method, including POST. 429 is rate limiting.
RETRYABLE_STATUS_CODES = frozenset({429, 502, 503, 504})

# Network-level failures where the request likely never reached / was answered
# by the app, so a replay is safe.
RETRYABLE_EXCEPTIONS = (
    requests.exceptions.ConnectionError,
    requests.exceptions.Timeout,
)

# Hard ceiling on a single backoff sleep, regardless of base/attempt.
_MAX_BACKOFF = 4.0


class ButtrbaseClient:
    """Small synchronous client for the ButtrBase API."""

    def __init__(
        self,
        access_token: str = "",
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 10.0,
        max_retries: int = 3,
        retry_base_delay: float = 0.5,
        client_id: str = "",
        client_secret: str = "",
    ) -> None:
        """Create a client.

        Args:
            access_token: A bearer access token sent as
                ``Authorization: Bearer <token>``. For app-server callers
                this is an OAuth2 client-credentials access token; for
                end-user flows it is the JWT returned by ``login`` and
                friends (those methods stash the new token here
                automatically). Pass ``""`` (the default) for an anonymous
                client, or supply ``client_id`` / ``client_secret`` to have
                the SDK fetch one for you on first use.
            base_url: The API base URL.
            timeout: Per-request timeout in seconds.
            max_retries: Number of retries on retryable failures.
            retry_base_delay: Base delay for exponential backoff.
            client_id: OAuth2 client-credentials client id. With
                ``client_secret``, the SDK exchanges these for an access
                token via :meth:`authenticate` — lazily before the first
                authed request and again when the cached token nears expiry.
            client_secret: OAuth2 client-credentials secret. See
                ``client_id``.
        """
        self.access_token = access_token
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_base_delay = retry_base_delay
        self.client_id = client_id
        self.client_secret = client_secret
        # Expiry (epoch seconds) of a token obtained via the
        # client-credentials grant. ``None`` means the current token is not
        # managed by the SDK (passed in directly, or a user JWT stashed by
        # ``login``) and so is never proactively refreshed.
        self._token_expires_at: Optional[float] = None
        self._session = requests.Session()

    # ----- internal -----
    def _headers(self, auth: bool = True) -> dict:
        h = {"Accept": "application/json", "Content-Type": "application/json"}
        if auth and self.access_token:
            h["Authorization"] = f"Bearer {self.access_token}"
        return h

    def _ensure_token(self) -> None:
        """Lazily obtain / refresh a client-credentials access token.

        No-op unless both ``client_id`` and ``client_secret`` are set. A new
        token is fetched when none is cached or when the managed token is
        at/near expiry. Tokens not minted by this grant (passed in directly,
        or user JWTs from ``login``) carry no tracked expiry and are left
        untouched.
        """
        if not (self.client_id and self.client_secret):
            return
        if self.access_token and not self._token_expired():
            return
        self.authenticate()

    def _token_expired(self) -> bool:
        """True once the managed token has reached its (early) expiry mark."""
        if self._token_expires_at is None:
            return False
        return time.time() >= self._token_expires_at

    def _request(
        self,
        method: str,
        path: str,
        *,
        json: Optional[dict] = None,
        params: Optional[dict] = None,
        auth: bool = True,
    ) -> Any:
        if auth:
            # Lazily fetch / refresh a client-credentials token when one is
            # configured, before sending an authenticated request.
            self._ensure_token()
        url = f"{self.base_url}{path}"
        # Total attempts = 1 initial try + ``max_retries`` retries.
        # ``max_retries=0`` disables retrying entirely.
        attempts = max(0, self.max_retries) + 1
        last_exc: Optional[BaseException] = None
        for attempt in range(attempts):
            is_last = attempt == attempts - 1
            try:
                resp = self._session.request(
                    method,
                    url,
                    json=json,
                    params=params,
                    headers=self._headers(auth=auth),
                    timeout=self.timeout,
                )
            except RETRYABLE_EXCEPTIONS as exc:
                # Connection/timeout: app didn't answer, replay is safe.
                if is_last:
                    raise
                last_exc = exc
                self._sleep_before_retry(attempt, retry_after=None)
                continue

            if not is_last and resp.status_code in RETRYABLE_STATUS_CODES:
                self._sleep_before_retry(
                    attempt,
                    retry_after=resp.headers.get("Retry-After"),
                )
                continue

            return self._handle(resp)

        # Unreachable in practice: the loop either returns or re-raises on the
        # final attempt. Guard anyway for completeness.
        if last_exc is not None:
            raise last_exc
        raise RuntimeError("retry loop exited without a response")

    def _sleep_before_retry(
        self, attempt: int, retry_after: Optional[str]
    ) -> None:
        """Sleep before the next retry using exponential backoff with jitter.

        Honors a ``Retry-After`` header (delay-seconds or HTTP-date) when the
        server supplies one; otherwise uses ``retry_base_delay * 2**attempt``
        with full jitter, capped at ``_MAX_BACKOFF``.
        """
        delay = self._retry_after_seconds(retry_after)
        if delay is None:
            backoff = self.retry_base_delay * (2 ** attempt)
            backoff = min(backoff, _MAX_BACKOFF)
            delay = random.uniform(0, backoff)
        time.sleep(delay)

    @staticmethod
    def _retry_after_seconds(value: Optional[str]) -> Optional[float]:
        """Parse a ``Retry-After`` header into seconds, or None if absent/bad."""
        if not isinstance(value, str) or not value.strip():
            return None
        value = value.strip()
        try:
            return max(0.0, float(value))
        except ValueError:
            pass
        # HTTP-date form, e.g. "Wed, 21 Oct 2015 07:28:00 GMT".
        try:
            parsed = email.utils.parsedate_to_datetime(value)
        except (TypeError, ValueError):
            return None
        if parsed is None:
            return None
        delta = parsed.timestamp() - time.time()
        return max(0.0, delta)

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
        *,
        app_uuid: Optional[str] = None,
        redirect_to: Optional[str] = None,
        org_uuid: Optional[str] = None,
    ) -> dict:
        """Send a passwordless magic-link email (``POST /api/auth/magic-link/send``).

        Magic-link is the only browser flow that yields a JWKS-verifiable
        **RS256** access token. The generic email-OTP endpoints
        (:meth:`send_otp` / :meth:`verify_otp`) issue HS256 tokens signed with
        Buttrbase's server secret, which the public JWKS cannot verify, so
        third-party apps that validate tokens against the JWKS must use
        magic-link.

        Cross-app federation: if you pass ``app_uuid`` together with a
        ``redirect_to`` whose *origin* is registered on the Buttrbase
        application (its WebAuthn ``rp_origins`` or configured redirect URL),
        the email link points at the app's own callback
        (``{redirect_to}?token=...``) so the app verifies the RS256 token
        itself via :meth:`verify_magic_link`. Non-allowlisted or non-absolute
        ``redirect_to`` targets fall back to the Buttrbase-hosted sign-in page.
        Omit ``redirect_to`` for the first-party flow.

        Args:
            email: The recipient's email address. Required.
            app_uuid: Target-app UUID (string-formatted) for cross-app
                federation. Required to land on your own callback.
            redirect_to: Absolute URL the user lands on after clicking the
                link. Its origin must be allowlisted on the application (see
                cross-app federation above) or it is ignored.
            org_uuid: Optional org scope the magic link is issued for.

        Returns:
            dict: ``{"sent": bool, "dev_token": str | None,
            "expires_in_seconds": int}``. ``dev_token`` is the raw one-time
            token, returned only in non-prod dev-echo mode (``None`` in prod).
        """
        payload: dict = {"email": email}
        if app_uuid is not None:
            payload["app_uuid"] = app_uuid
        if redirect_to is not None:
            payload["redirect_to"] = redirect_to
        if org_uuid is not None:
            payload["org_uuid"] = org_uuid
        return self._request("POST", "/api/auth/magic-link/send", json=payload, auth=False)

    def verify_magic_link(self, token: str) -> dict:
        """Verify a magic-link token (``POST /api/auth/magic-link/verify``).

        Exchanges the single-use token (delivered in the email link as
        ``?token=...``, or returned as ``dev_token`` in dev-echo mode) for an
        RS256 access token verifiable against the public JWKS.

        Args:
            token: The single-use token from the magic-link email.

        Returns:
            dict: ``{"access_token": str, "token_type": str,
            "user": {"user_uuid": str, "email": str},
            "redirect_to": str | None}``.
        """
        return self._request(
            "POST",
            "/api/auth/magic-link/verify",
            json={"token": token},
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
            self.access_token = body["access_token"]
            # User/step-up token, not a client-credentials grant — don't
            # proactively refresh it.
            self._token_expires_at = None
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
        """POST /api/sandbox/reset."""
        payload: dict = {}
        if org_uuid is not None:
            payload["org_uuid"] = org_uuid
        return self._request("POST", "/api/sandbox/reset", json=payload or None)

    # ----- Auth -----
    # How early (in seconds) to refresh a client-credentials token before it
    # actually expires, so an in-flight request never races the boundary.
    _TOKEN_REFRESH_SKEW = 30.0

    def authenticate(self) -> dict:
        """POST /api/v1/auth/token — OAuth2 client-credentials grant.

        Exchanges the configured ``client_id`` / ``client_secret`` for an
        access token and stores it on ``self.access_token`` (and tracks its
        expiry) so subsequent authed requests carry the bearer. Normally you
        do not call this directly — authed methods fetch and refresh the
        token lazily — but it is exposed for eager warm-up / verification.

        Returns:
            The token response dict (``access_token``, ``token_type``,
            ``expires_in``).

        Raises:
            ButtrbaseError: On non-2xx (e.g. 401 ``invalid client
                credentials``).
            ValueError: If ``client_id`` / ``client_secret`` are not set.
        """
        if not (self.client_id and self.client_secret):
            raise ValueError(
                "authenticate() requires client_id and client_secret"
            )
        payload = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }
        # Use the raw session: this is an unauthenticated POST, and routing it
        # through _request would re-enter _ensure_token and recurse.
        requested_at = time.time()
        resp = self._session.post(
            f"{self.base_url}/api/v1/auth/token",
            json=payload,
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            timeout=self.timeout,
        )
        body = self._handle(resp)
        token = body.get("access_token") if isinstance(body, dict) else None
        if not token:
            raise ButtrbaseError(
                "token endpoint returned no access_token",
                status_code=resp.status_code,
                detail=body,
            )
        self.access_token = token
        expires_in = body.get("expires_in") if isinstance(body, dict) else None
        if isinstance(expires_in, (int, float)) and expires_in > 0:
            self._token_expires_at = (
                requested_at + float(expires_in) - self._TOKEN_REFRESH_SKEW
            )
        else:
            # No usable lifetime hint: keep the token but don't proactively
            # refresh it (treat as long-lived).
            self._token_expires_at = None
        return body

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

        .. deprecated::
            Use the 0.3.0 flow instead:
            ``send_otp_email`` → ``verify_otp_email`` → ``finalize_registration``.

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
        warnings.warn(
            "register() is deprecated since 0.3.0. Use send_otp_email() → "
            "verify_otp_email() → finalize_registration() instead.",
            DeprecationWarning,
            stacklevel=2,
        )
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
            self.access_token = body["access_token"]
            # User JWT, not a client-credentials grant — don't refresh it.
            self._token_expires_at = None
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

    # ----- OTP email (0.3.0 registration flow) -----

    def send_otp_email(self, email: str, app_uuid: str) -> None:
        """POST /api/v1/auth/otp/send — send email OTP for registration.

        Flow: send_otp_email → verify_otp_email → finalize_registration.
        """
        self._request("POST", "/api/v1/auth/otp/send",
                      json={"email": email, "app_uuid": app_uuid}, auth=False)

    def verify_otp_email(self, email: str, otp: str, app_uuid: str) -> TokenPair:
        """POST /api/v1/auth/otp/verify — verify email OTP.

        Returns a TokenPair; the ``token`` field is the signup_token for
        finalize_registration.
        """
        return self._request(
            "POST", "/api/v1/auth/otp/verify",
            json={"email": email, "otp": otp, "app_uuid": app_uuid}, auth=False
        )

    def check_org_name_v2(self, name: str) -> CheckOrgNameResponse:
        """POST /api/v1/auth/check-org-name — check org name availability.

        Returns available, normalized form, and reason if unavailable.
        """
        return self._request(
            "POST", "/api/v1/auth/check-org-name",
            json={"name": name}, auth=False
        )

    def finalize_registration(self, req: FinalizeRegistrationRequest) -> RegistrationResult:
        """POST /api/v1/auth/finalize-registration.

        Complete registration after OTP verification.
        req["signup_token"] must be the token from verify_otp_email.
        req["org_choice"] is either {"type": "create", "name": "..."}
        or {"type": "accept_invite", "invitation_token": "..."}.
        """
        return self._request(
            "POST", "/api/v1/auth/finalize-registration",
            json=dict(req), auth=False
        )

    # ----- Invitations (0.3.0+) -----

    def create_invitation(
        self, org_uuid: str, req: CreateInvitationRequest
    ) -> InvitationResponse:
        """POST /api/v1/organizations/{org_uuid}/invitations.

        The plaintext token in the response is shown once.
        """
        return self._request(
            "POST", f"/api/v1/organizations/{org_uuid}/invitations",
            json=dict(req), auth=True
        )

    def preview_invitation(self, token: str) -> InvitationPreview:
        """GET /api/v1/invitations/{token}/preview — public, no auth."""
        return self._request(
            "GET", f"/api/v1/invitations/{token}/preview",
            auth=False
        )

    def accept_invitation_v2(self, token: str) -> AcceptInvitationResponse:
        """POST /api/v1/invitations/{token}/accept — for already-authenticated users.

        New users should use finalize_registration with OrgChoice accept_invite.
        """
        return self._request(
            "POST", f"/api/v1/invitations/{token}/accept",
            auth=True
        )

    def list_invitations(self, org_uuid: str) -> List[InvitationListItem]:
        """GET /api/v1/organizations/{org_uuid}/invitations."""
        return self._request(
            "GET", f"/api/v1/organizations/{org_uuid}/invitations",
            auth=True
        )

    def revoke_invitation(self, org_uuid: str, invitation_id: int) -> None:
        """DELETE /api/v1/organizations/{org_uuid}/invitations/{invitation_id}."""
        self._request(
            "DELETE", f"/api/v1/organizations/{org_uuid}/invitations/{invitation_id}",
            auth=True
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

    # ===== WebAuthn relying-party config (admin) =====
    def get_app_rp_config(self, app_uuid: str) -> AppRpConfig:
        """GET /api/v1/apps/:app_uuid/rp-config.

        Returns the per-app WebAuthn RP config. ``rp_id`` is ``None``
        when the app has no override and falls back to the deployment
        ``BUTTRBASE_WEBAUTHN_RP_ID`` env var.
        """
        return self._request("GET", f"/api/v1/apps/{app_uuid}/rp-config")

    def update_app_rp_config(
        self, app_uuid: str, patch: UpdateAppRpConfigRequest
    ) -> AppRpConfig:
        """PATCH /api/v1/apps/:app_uuid/rp-config.

        Partial update — omit a field to leave it unchanged. Known
        limitation: this method cannot explicitly clear ``rp_id`` back
        to the env-var fallback; that requires raw-JSON access.
        """
        return self._request(
            "PATCH", f"/api/v1/apps/{app_uuid}/rp-config", json=dict(patch)
        )

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
                ``"oauth_config."`` returns only OAuth-config lifecycle
                events.
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

    # ===== Scope context (windowed / JIT scope re-mint) =====
    def scope_context(self, requested_scopes: List[str]) -> ScopeContextResponse:
        """POST /api/app/auth/scope-context.

        Re-mint the caller's access token windowed to an explicit,
        gate-checked scope subset (least-privilege "windowed" strategy).
        Requires an authenticated end user — the current access token is
        sent via the ``Authorization`` header. The granted set is always a
        subset of the caller's effective scopes, and each requested scope is
        run through the scope-gate (step-up) machinery.

        On success the new access token is stashed onto ``self.access_token`` so
        subsequent calls use the windowed token, mirroring ``login`` /
        ``auth_step_up``. Only the access token is re-minted; the refresh
        token is unchanged and not returned.

        Args:
            requested_scopes: The explicit scope list to window into a fresh
                access token. A requested scope the caller does not hold
                raises ``ButtrbaseError`` (HTTP 403); a scope behind an
                unsatisfied step-up gate raises ``ButtrbaseError`` (HTTP 401,
                ``code == "step_up_required"``).
        """
        body = self._request(
            "POST",
            "/api/app/auth/scope-context",
            json={"requested_scopes": requested_scopes},
        )
        if isinstance(body, dict) and body.get("token"):
            self.access_token = body["token"]
            # Windowed user token, not a client-credentials grant.
            self._token_expires_at = None
        return body

    # ===== Devices (end-user self-service device-key management) =====
    def list_devices(self) -> List[DeviceItem]:
        """GET /api/app/devices.

        List the authenticated caller's ACTIVE (non-revoked) device keys, in
        descending ``created_at`` order. Returns only public-safe fields — no
        private key material is ever returned. Unwraps the backend's
        ``{"data": [...]}`` envelope.
        """
        resp = self._request("GET", "/api/app/devices")
        if isinstance(resp, dict) and isinstance(resp.get("data"), list):
            return resp["data"]
        return resp if isinstance(resp, list) else []

    def revoke_device(self, device_uuid: str) -> RevokeDeviceResponse:
        """POST /api/app/devices/{device_uuid}/revoke.

        Soft-revoke a device the caller owns. Ownership is enforced on the
        backend; a device that does not exist, is already revoked, or belongs
        to another user yields 404 (raised as ``ButtrbaseError``). Unwraps
        the backend's ``{"data": {...}}`` envelope.
        """
        resp = self._request(
            "POST", f"/api/app/devices/{device_uuid}/revoke"
        )
        return resp.get("data", resp) if isinstance(resp, dict) else resp

    # ===== Tenant home (public discovery) =====
    def get_tenant_home(
        self, org_uuid: str, app_id: Optional[int] = None
    ) -> TenantHome:
        """GET /api/tenant/home?org_uuid=&app_id=.

        Public, pre-auth discovery: resolve an ACTIVE tenant's home so a
        client can target it directly. Keyed by ``(org_uuid, app_id)`` and
        gated on the tenant's lifecycle status — an unknown or non-active
        tenant yields 404 (raised as ``ButtrbaseError``). Carries public
        routing info only. Unwraps the backend's ``{"data": {...}}``
        envelope.
        """
        params: dict = {"org_uuid": org_uuid}
        if app_id is not None:
            params["app_id"] = app_id
        resp = self._request(
            "GET", "/api/tenant/home", params=params, auth=False
        )
        return resp.get("data", resp) if isinstance(resp, dict) else resp

    # ----- Password reset -----
    def request_password_reset(self, email: str) -> PasswordResetRequestResponse:
        """POST /api/auth/request-password-reset — send a password-reset email.

        No authentication required.

        Returns:
            A ``PasswordResetRequestResponse`` dict with a ``message`` field.
        """
        return self._request(
            "POST", "/api/auth/request-password-reset", json={"email": email}, auth=False
        )

    def reset_password(self, token: str, password: str) -> PasswordResetResponse:
        """POST /api/auth/reset-password — set a new password using a reset token.

        No authentication required; the ``token`` argument acts as the credential.

        Returns:
            A ``PasswordResetResponse`` dict with a ``message`` field.
        """
        return self._request(
            "POST",
            "/api/auth/reset-password",
            json={"token": token, "password": password},
            auth=False,
        )

    # ----- Webhooks -----
    def list_webhooks(self) -> WebhookListResponse:
        """GET /api/v1/webhooks — list all webhooks for the authenticated account.

        Returns:
            A ``WebhookListResponse`` dict containing ``data`` (list of webhooks).
        """
        return self._request("GET", "/api/v1/webhooks")

    def create_webhook(
        self,
        url: str,
        *,
        event_types: Optional[list] = None,
        signing_secret: Optional[str] = None,
        description: Optional[str] = None,
    ) -> Webhook:
        """POST /api/v1/webhooks — register a new webhook endpoint.

        Args:
            url: The HTTPS URL that will receive webhook POST requests.
            event_types: Optional list of event type strings to subscribe to.
            signing_secret: Optional secret used to sign webhook payloads.
            description: Optional human-readable description.

        Returns:
            A ``Webhook`` dict representing the created webhook.
        """
        payload: dict = {"url": url}
        if event_types is not None:
            payload["event_types"] = event_types
        if signing_secret is not None:
            payload["signing_secret"] = signing_secret
        if description is not None:
            payload["description"] = description
        return self._request("POST", "/api/v1/webhooks", json=payload)

    def delete_webhook(self, webhook_id: int) -> None:
        """DELETE /api/v1/webhooks/{id} — delete a webhook (HTTP 204, no body)."""
        self._request("DELETE", f"/api/v1/webhooks/{webhook_id}")

    def list_webhook_deliveries(self, webhook_id: int) -> list:
        """GET /api/v1/webhooks/{id}/deliveries — list delivery attempts for a webhook.

        Returns:
            A list of ``WebhookDelivery`` dicts.
        """
        return self._request("GET", f"/api/v1/webhooks/{webhook_id}/deliveries")

    def retry_webhook_delivery(
        self, webhook_id: int, delivery_id: int
    ) -> WebhookDeliveryRetryResponse:
        """POST /api/v1/webhooks/{id}/deliveries/{delivery_id}/retry — retry a delivery.

        Returns:
            A ``WebhookDeliveryRetryResponse`` dict with a ``message`` field.
        """
        return self._request(
            "POST",
            f"/api/v1/webhooks/{webhook_id}/deliveries/{delivery_id}/retry",
        )

    # ----- OAuth -----
    def refresh_oauth_connection(self, provider: str) -> OAuthRefreshResponse:
        """POST /v1/oauth/connections/{provider}/refresh — refresh an OAuth token.

        Args:
            provider: The OAuth provider slug (e.g. ``"google"``, ``"github"``).

        Returns:
            An ``OAuthRefreshResponse`` dict with ``provider``, ``access_token``,
            and ``expires_at``.
        """
        return self._request(
            "POST", f"/v1/oauth/connections/{provider}/refresh"
        )

    # ----- Email -----
    def send_email(
        self,
        to: str,
        subject: str,
        *,
        html_body: Optional[str] = None,
        text_body: Optional[str] = None,
        from_address: Optional[str] = None,
        reply_to: Optional[str] = None,
    ) -> EmailSendResponse:
        """POST /api/email/send — send a transactional email.

        Args:
            to: Recipient email address.
            subject: Email subject line.
            html_body: Optional HTML content for the email body.
            text_body: Optional plain-text content for the email body.
            from_address: Optional sender address (overrides account default).
            reply_to: Optional reply-to address.

        Returns:
            An ``EmailSendResponse`` dict with ``message`` and optionally
            ``message_id``.
        """
        payload: dict = {"to": to, "subject": subject}
        if html_body is not None:
            payload["html_body"] = html_body
        if text_body is not None:
            payload["text_body"] = text_body
        if from_address is not None:
            payload["from_address"] = from_address
        if reply_to is not None:
            payload["reply_to"] = reply_to
        return self._request("POST", "/api/email/send", json=payload)
