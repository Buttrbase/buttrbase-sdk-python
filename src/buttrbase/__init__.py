"""ButtrBase Python SDK."""
from .client import ButtrbaseClient
from .errors import ButtrbaseError
from . import webhooks
from .types import (
    AcceptInvitationResponse,
    ApiKeySummary,
    AppRpConfig,
    AuditRow,
    CheckOrgNameResponse,
    CreateApiKeyInput,
    CreateCredentialResponse,
    CreateInvitationRequest,
    CreateOAuthConfigInput,
    CreatedKeyResponse,
    Credential,
    ExchangeResponse,
    ExpiryInput,
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
    RotateSecretResponse,
    SandboxResetResponse,
    TokenPair,
    UpdateAppRpConfigRequest,
    UpdateOAuthConfigInput,
)

__all__ = [
    "ButtrbaseClient",
    "ButtrbaseError",
    "webhooks",
    # Legacy types
    "Credential",
    "CreateCredentialResponse",
    "RotateSecretResponse",
    "SandboxResetResponse",
    # API key exchange
    "ExchangeResponse",
    # App API keys
    "ApiKeySummary",
    "CreatedKeyResponse",
    "CreateApiKeyInput",
    "ExpiryInput",
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
    # Registration 0.3.0+
    "OrgChoiceCreate",
    "OrgChoiceAcceptInvite",
    "OrgChoice",
    "FinalizeRegistrationRequest",
    "CheckOrgNameResponse",
    "TokenPair",
    # Invitations 0.3.0+
    "CreateInvitationRequest",
    "InvitationResponse",
    "InvitationPreview",
    "AcceptInvitationResponse",
    "InvitationListItem",
]
__version__ = "0.3.0"
