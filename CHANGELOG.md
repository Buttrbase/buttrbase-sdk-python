# Changelog

## Unreleased — drop static API keys (OAuth2 client-credentials only)

### Breaking
- Removed static-API-key support. The platform now consolidates on OAuth2
  client-credentials (`client_id` + `client_secret`) as the single
  app-server credential.
- `ButtrbaseClient(api_key=...)` is now `ButtrbaseClient(access_token=...)`.
  The bearer-token slot (`client.api_key`) is renamed `client.access_token`.
  The parameter now defaults to `""` for anonymous clients.
- Removed `exchange_api_key` and `exchange_refresh_token`
  (`POST /api/v1/auth/api-key/exchange`).
- Removed app-level static API key admin: `list_app_api_keys`,
  `create_app_api_key`, `revoke_app_api_key`, `rotate_app_api_key`.
- Removed types: `ExchangeResponse`, `ApiKeySummary`, `CreatedKeyResponse`,
  `CreateApiKeyInput`, `ExpiryInput`.

### Notes
- Manage client-credentials via the existing `/credentials` endpoints
  (`create_credential`, `rotate_credential_secret`, `list_credentials`,
  `get_credential`, `delete_credential`). Exchange `client_id` +
  `client_secret` for an access token at your deployment's OAuth2 token
  endpoint, then pass it as `access_token`. The SDK does not yet expose a
  client-credentials token-grant method (no backend contract assumed here).

## Unreleased — app_uuid migration

### Breaking
- Methods taking `app` slug now take `app_uuid: str`: `register`, `send_otp`, `verify_otp`, `send_magic_link`, `verify_magic_link`.
- The OTP methods renamed from `otp_send`/`otp_verify` to `send_otp`/`verify_otp` to align with the backend route shape. The old names are removed — no aliases.
- `login` and `lookup_organizations` (formerly callers used a manual request) also take `app_uuid: str`.

### Added
- `oauth_start_url(provider, app_uuid, return_to)` — URL builder for the public OAuth start endpoint (no network call).
- OAuth config admin: `list_oauth_configs`, `create_oauth_config`, `update_oauth_config`, `delete_oauth_config`.
- `read_audit_log(app_uuid, limit=None, action_prefix=None)`.
- New types exported from `buttrbase`: `OAuthConfigSummary`, `CreateOAuthConfigInput`, `UpdateOAuthConfigInput`, `AuditRow`.

### Passkey support
- `passkey_register_begin()`, `passkey_register_complete(body)`,
  `passkey_authenticate_begin()`, `passkey_authenticate_complete(body)` —
  thin wrappers over `POST /api/passkeys/{register,authenticate}/{begin,complete}`.
  WebAuthn challenge / credential blobs are pass-through `Any` (the browser
  handles them). Begin endpoints unwrap the backend's `{data: ...}`
  envelope for ergonomics.
- `list_my_passkeys()` — `GET /api/v1/me/passkeys`. Returns
  `List[PasskeyListItem]` in descending `created_at` order.
- `delete_my_passkey(credential_uuid)` —
  `DELETE /api/v1/me/passkeys/{uuid}`. Owner check enforced by the backend.
- New TypedDicts: `PasskeyRegistrationChallenge`,
  `PasskeyRegistrationComplete`, `PasskeyRegistrationResult`,
  `PasskeyAuthChallenge`, `PasskeyAuthComplete`, `PasskeyListItem`.

## 0.1.0

- Initial release.
