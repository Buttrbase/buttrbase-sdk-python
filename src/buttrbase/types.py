"""Type definitions for the ButtrBase SDK."""
from __future__ import annotations

from typing import Optional

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
