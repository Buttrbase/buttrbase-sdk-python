"""ButtrBase Python SDK."""
from .client import ButtrbaseClient
from .errors import ButtrbaseError
from . import webhooks
from .types import (
    ApiKeySummary,
    AppRpConfig,
    AuditRow,
    CreateApiKeyInput,
    CreateCredentialResponse,
    CreateOAuthConfigInput,
    CreatedKeyResponse,
    Credential,
    DeviceItem,
    ExchangeResponse,
    ExpiryInput,
    OAuthConfigSummary,
    PasskeyAuthChallenge,
    PasskeyAuthComplete,
    PasskeyListItem,
    PasskeyRegistrationChallenge,
    PasskeyRegistrationComplete,
    PasskeyRegistrationResult,
    RevokeDeviceResponse,
    RotateSecretResponse,
    SandboxResetResponse,
    ScopeContextResponse,
    TenantHome,
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
    # Scope context (windowed / JIT scope re-mint)
    "ScopeContextResponse",
    # Devices (end-user self-service)
    "DeviceItem",
    "RevokeDeviceResponse",
    # Tenant home (public discovery)
    "TenantHome",
]
__version__ = "0.2.0"
