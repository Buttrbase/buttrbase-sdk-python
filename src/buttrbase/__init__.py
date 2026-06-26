"""ButtrBase Python SDK."""
from .client import ButtrbaseClient
from .errors import ButtrbaseError
from . import webhooks
from . import verify
from .verify import ClaimsData, Claims, TokenPrincipal, principal_from_payload
from .types import (
    AcceptInvitationResponse,
    AppRpConfig,
    AuditRow,
    CheckOrgNameResponse,
    CreateCredentialResponse,
    CreateInvitationRequest,
    CreateOAuthConfigInput,
    Credential,
    DeviceItem,
    FinalizeRegistrationRequest,
    InvitationListItem,
    InvitationPreview,
    InvitationResponse,
    OAuthConfigSummary,
    OrgChoice,
    OrgChoiceAcceptInvite,
    OrgChoiceCreate,
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
    TenantHome,
    TokenPair,
    UpdateAppRpConfigRequest,
    UpdateOAuthConfigInput,
)

__all__ = [
    "ButtrbaseClient",
    "ButtrbaseError",
    "webhooks",
    # Token claims enrichment (data-envelope: roles / email)
    "verify",
    "ClaimsData",
    "Claims",
    "TokenPrincipal",
    "principal_from_payload",
    # Legacy types
    "Credential",
    "CreateCredentialResponse",
    "RotateSecretResponse",
    "SandboxResetResponse",
    # OAuth configs
    "OAuthConfigSummary",
    "CreateOAuthConfigInput",
    "UpdateOAuthConfigInput",
    # WebAuthn RP config
    "AppRpConfig",
    "UpdateAppRpConfigRequest",
    # Audit log
    "AuditRow",
    # Passkeys (WebAuthn)
    "PasskeyRegistrationChallenge",
    "PasskeyRegistrationComplete",
    "PasskeyRegistrationResult",
    "PasskeyAuthChallenge",
    "PasskeyAuthComplete",
    "PasskeyListItem",
    # Scope context (windowed / JIT scope re-mint)
    "ScopeContextResponse",
    # Devices (end-user self-service)
    "DeviceItem",
    "RevokeDeviceResponse",
    # Tenant home (public discovery)
    "TenantHome",
    # Registration 0.3.0+
    "OrgChoiceCreate",
    "OrgChoiceAcceptInvite",
    "OrgChoice",
    "FinalizeRegistrationRequest",
    "CheckOrgNameResponse",
    "TokenPair",
    "RegistrationResult",
    # Invitations 0.3.0+
    "CreateInvitationRequest",
    "InvitationResponse",
    "InvitationPreview",
    "AcceptInvitationResponse",
    "InvitationListItem",
]
__version__ = "0.5.0"
