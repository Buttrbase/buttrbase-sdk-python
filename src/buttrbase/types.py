"""Type definitions for the ButtrBase SDK."""
from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional, Union

try:
    from typing import TypedDict
except ImportError:  # Python 3.7
    from typing_extensions import TypedDict


class Credential(TypedDict):
    """A credential object returned by the credentials endpoints.

    Note: ``client_secret`` is **not** present on GET responses; it is only
    included in the create (``CreateCredentialResponse``) and rotate-secret
    (``RotateSecretResponse``) responses.
    """

    credentials_id: str
    client_id: str
    name: str
    description: Optional[str]
    created_at: str


class CreateCredentialResponse(TypedDict):
    """Response from POST /credentials (HTTP 201)."""

    credentials_id: str
    client_id: str
    client_secret: str
    name: str
    description: Optional[str]
    created_at: str


class RotateSecretResponse(TypedDict):
    """Response from POST /credentials/:id/rotate-secret."""

    credentials_id: str
    client_id: str
    client_secret: str


class SandboxResetResponse(TypedDict):
    """Response from POST /api/sandbox/reset."""

    status: str


class AppTokenResponse(TypedDict):
    """Response from POST /api/v1/auth/token (OAuth2 client-credentials grant)."""

    access_token: str
    token_type: str
    expires_in: int


# ----- Invite-based registration -----

class InviteAcceptResponse(TypedDict):
    """Response from POST /api/auth/invite/accept."""

    user_uuid: str
    org_uuid: str
    role: str
    access_token: str
    refresh_token: str
    token_type: str
    expires_in: int
    message: str


class OrgCheckResponse(TypedDict):
    """Response from GET /api/auth/orgs/check."""

    name: str
    available: bool


class SuperuserResponse(TypedDict):
    """Response from GET /api/auth/superuser."""

    email: str
    is_superuser: bool


# ----- Contact forms -----

class ContactSubmitResponse(TypedDict):
    """Response from POST /api/contact and POST /api/contact-us."""

    message: str
    reference_id: str


# ----- Geo / IP -----

class GeoResponse(TypedDict):
    """Response from GET /api/geo/ip."""

    ip: str
    country: str
    timezone: str


# ---------------------------------------------------------------------------
# API key exchange (anonymous)
# ---------------------------------------------------------------------------


class ExchangeResponse(TypedDict):
    """Response from POST /api/v1/auth/api-key/exchange.

    Returned by both the initial (``api_key``) and refresh
    (``refresh_token``) modes.
    """

    access_token: str
    refresh_token: str
    token_type: str
    access_expires_at: str
    refresh_expires_at: str


# ---------------------------------------------------------------------------
# App-level API keys (admin)
# ---------------------------------------------------------------------------


class ApiKeySummary(TypedDict):
    """A key as returned by list / metadata endpoints.

    ``raw_key`` is **never** present here — only on create / rotate
    (``CreatedKeyResponse``).
    """

    key_uuid: str
    app_uuid: str
    key_prefix: str
    name: str
    key_type: str  # "short_lived" | "permanent" | "expiring"
    expires_at: Optional[str]
    last_used_at: Optional[str]
    revoked_at: Optional[str]
    created_at: str


class CreatedKeyResponse(TypedDict):
    """Response from create / rotate.

    The ``raw_key`` field is shown **exactly once** — the server stores
    only the SHA-256 hash and cannot recover it later.
    """

    key_uuid: str
    raw_key: str
    key_prefix: str
    key_type: str
    expires_at: Optional[str]


class ExpiryInput(TypedDict, total=False):
    """Expiry envelope for ``expiring`` keys.

    Set **exactly one** of ``absolute`` (RFC3339 timestamp) or
    ``in_days`` (relative day count).
    """

    absolute: str
    in_days: int


class CreateApiKeyInput(TypedDict, total=False):
    """Body for POST /api/v1/apps/:app_uuid/api-keys.

    ``expiry`` is required when ``key_type == "expiring"`` and ignored
    otherwise.
    """

    name: str
    env: str  # "live" | "test"
    key_type: str  # "short_lived" | "permanent" | "expiring"
    expiry: ExpiryInput


# ---------------------------------------------------------------------------
# OAuth configs (admin)
# ---------------------------------------------------------------------------


class OAuthConfigSummary(TypedDict):
    """A per-app OAuth provider config (no secrets)."""

    provider: str  # "google" | "microsoft" | "github" | "apple"
    client_id: str
    redirect_uris: List[str]
    scopes: List[str]
    enabled: bool
    created_at: str
    updated_at: str


class CreateOAuthConfigInput(TypedDict, total=False):
    """Body for POST /api/v1/apps/:app_uuid/oauth-configs.

    ``provider_extras`` carries provider-specific extras as a JSON object.
    Required for Apple sign-in
    (``{"team_id": "...", "key_id": "...", "private_key": "<PEM>"}``);
    the backend strips the ``private_key`` field and re-stores it as
    ``private_key_encrypted`` under the app's DEK. Optional for
    providers that don't need extras (Google, Microsoft, GitHub).
    """

    provider: str
    client_id: str
    client_secret: str
    redirect_uris: List[str]
    scopes: List[str]
    enabled: bool
    provider_extras: Dict[str, Any]


class UpdateOAuthConfigInput(TypedDict, total=False):
    """Body for PATCH /api/v1/apps/:app_uuid/oauth-configs/:provider.

    Every field is optional. Sending ``client_secret`` as ``""`` or
    omitting it leaves the stored ciphertext untouched — only a
    non-empty value rotates the secret. ``provider_extras`` replaces
    the existing JSON blob entirely; for Apple a fresh ``private_key``
    triggers re-encryption under the app's DEK.
    """

    client_id: str
    client_secret: str
    redirect_uris: List[str]
    scopes: List[str]
    enabled: bool
    provider_extras: Dict[str, Any]


# ---------------------------------------------------------------------------
# WebAuthn relying-party config (admin)
# ---------------------------------------------------------------------------


class AppRpConfig(TypedDict):
    """Per-app WebAuthn relying-party config.

    ``rp_id`` is ``None`` when the app has no per-app override and the
    server falls back to the deployment-wide ``BUTTRBASE_WEBAUTHN_RP_ID``
    env var. ``rp_origins`` is the list of full origins (scheme + host +
    optional port) permitted to participate in passkey ceremonies under
    this RP.
    """

    app_uuid: str
    rp_id: Optional[str]
    rp_origins: List[str]


class UpdateAppRpConfigRequest(TypedDict, total=False):
    """Body for PATCH /api/v1/apps/:app_uuid/rp-config.

    Partial update — omit a field to leave it unchanged. Note: because
    this is an omit-vs-present patch, there is currently no way through
    this dataclass to explicitly clear ``rp_id`` back to the env-var
    fallback; that requires raw-JSON access.
    """

    rp_id: str
    rp_origins: List[str]


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------


class AuditRow(TypedDict):
    """A row from GET /api/v1/apps/:app_uuid/audit-log."""

    id: str
    app_uuid: str
    actor_user_uuid: Optional[str]
    action: str
    target_id: Optional[str]
    details: Optional[dict]
    ip: Optional[str]
    user_agent: Optional[str]
    created_at: str


# ---------------------------------------------------------------------------
# Passkeys (WebAuthn)
# ---------------------------------------------------------------------------
#
# The WebAuthn challenge / credential blobs are pass-through ``Any`` JSON —
# the browser's ``navigator.credentials.create / .get`` APIs consume and
# produce them directly. We deliberately don't introduce a webauthn helper
# library on the SDK side.


class PasskeyRegistrationChallenge(TypedDict):
    """Response from POST /api/passkeys/register/begin.

    ``challenge`` is a WebAuthn ``CreationChallengeResponse``; pass
    ``challenge['publicKey']`` to ``navigator.credentials.create`` in the
    browser. ``registration_state`` is an opaque server-signed blob that must
    be sent back unchanged on the matching complete call.
    """

    challenge: Any
    registration_state: str


class PasskeyRegistrationComplete(TypedDict):
    """Body for POST /api/passkeys/register/complete.

    ``credential`` is the WebAuthn ``RegisterPublicKeyCredential`` produced by
    the browser.
    """

    registration_state: str
    credential: Any


class PasskeyRegistrationResult(TypedDict):
    """Response from POST /api/passkeys/register/complete."""

    credential_id: str
    message: str


class PasskeyAuthChallenge(TypedDict):
    """Response from POST /api/passkeys/authenticate/begin."""

    challenge: Any
    auth_state: str


class PasskeyAuthComplete(TypedDict):
    """Body for POST /api/passkeys/authenticate/complete."""

    auth_state: str
    credential: Any


class PasskeyListItem(TypedDict):
    """A single row returned by GET /api/v1/me/passkeys.

    ``credential_id_prefix`` is the first 12 characters of the WebAuthn
    credential ID — enough to disambiguate in a dashboard without exposing
    the full identifier. Timestamps are RFC 3339 strings.
    """

    credential_uuid: str
    credential_id_prefix: str
    app_uuid: Optional[str]
    nickname: Optional[str]
    last_used_at: Optional[str]
    created_at: str


# ----- Password reset -----

class PasswordResetRequestResponse(TypedDict):
    """Response from POST /api/auth/request-password-reset."""

    message: str


class PasswordResetResponse(TypedDict):
    """Response from POST /api/auth/reset-password."""

    message: str


# ----- Webhooks -----

class Webhook(TypedDict):
    """A webhook object returned by the webhooks endpoints."""

    id: int
    url: str
    event_types: Optional[list]
    signing_secret: Optional[str]
    description: Optional[str]
    created_at: str


class WebhookListResponse(TypedDict):
    """Response from GET /api/v1/webhooks."""

    data: list


class WebhookDelivery(TypedDict):
    """A webhook delivery object returned by the deliveries endpoints."""

    id: int
    webhook_id: int
    event_type: str
    status: str
    created_at: str


class WebhookDeliveryRetryResponse(TypedDict):
    """Response from POST /api/v1/webhooks/{id}/deliveries/{delivery_id}/retry."""

    message: str


# ----- OAuth -----

class OAuthRefreshResponse(TypedDict):
    """Response from POST /v1/oauth/connections/{provider}/refresh."""

    provider: str
    access_token: str
    expires_at: Optional[str]


# ----- Email -----

class EmailSendResponse(TypedDict):
    """Response from POST /api/email/send."""

    message: str
    message_id: Optional[str]


# ── Registration 0.3.0+ ──────────────────────────────────────────────────────


class OrgChoiceCreate(TypedDict):
    """Org choice for creating a new organisation during finalize_registration."""

    type: Literal["create"]
    name: str


class OrgChoiceAcceptInvite(TypedDict):
    """Org choice for accepting an invitation during finalize_registration."""

    type: Literal["accept_invite"]
    invitation_token: str


OrgChoice = Union[OrgChoiceCreate, OrgChoiceAcceptInvite]


class FinalizeRegistrationRequest(TypedDict, total=False):
    """Body for POST /api/v1/auth/finalize-registration.

    ``email``, ``password``, ``app_uuid``, ``signup_token``, and
    ``org_choice`` are all required. ``first_name`` and ``last_name``
    are optional.
    """

    email: str           # required
    password: str        # required
    app_uuid: str        # required (UUID string)
    signup_token: str    # required — token from verify_otp_email
    org_choice: OrgChoice  # required
    first_name: str      # optional
    last_name: str       # optional


class CheckOrgNameResponse(TypedDict):
    """Response from POST /api/v1/auth/check-org-name."""

    available: bool
    reason: Optional[str]
    normalized: str


class TokenPair(TypedDict):
    """A token pair returned by OTP-verification and finalize-registration."""

    token: str
    refresh_token: Optional[str]
    user_uuid: Optional[str]


class RegistrationResult(TypedDict):
    """Full response from finalize_registration and register."""

    access_token: str
    refresh_token: str
    token_type: str
    expires_in: Optional[int]
    user_uuid: str
    org_uuid: str
    role: str
    message: Optional[str]


# ── Invitations ──────────────────────────────────────────────────────────────


class CreateInvitationRequest(TypedDict, total=False):
    """Body for POST /api/v1/organizations/{org_uuid}/invitations."""

    email: str
    role: str
    expires_in_hours: int


class InvitationResponse(TypedDict):
    """Response from POST /api/v1/organizations/{org_uuid}/invitations.

    The plaintext ``token`` is shown once — the server does not store it.
    """

    id: int
    org_uuid: str
    email: Optional[str]
    role: str
    expires_at: str
    token: str
    signup_url: str


class InvitationPreview(TypedDict):
    """Response from GET /api/v1/invitations/{token}/preview."""

    org_uuid: str
    org_name: str
    email: Optional[str]
    role: str
    expires_at: str
    valid: bool
    invalid_reason: Optional[str]


class AcceptInvitationResponse(TypedDict):
    """Response from POST /api/v1/invitations/{token}/accept."""

    org_uuid: str
    org_name: str
    role: str


class InvitationListItem(TypedDict):
    """A row from GET /api/v1/organizations/{org_uuid}/invitations."""

    id: int
    email: Optional[str]
    role: str
    expires_at: str
    accepted_at: Optional[str]
    revoked_at: Optional[str]
