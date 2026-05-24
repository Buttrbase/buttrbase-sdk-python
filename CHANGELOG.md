# Changelog

## Unreleased — app_uuid migration

### Breaking
- Methods taking `app` slug now take `app_uuid: str`: `register`, `send_otp`, `verify_otp`, `send_magic_link`, `verify_magic_link`.
- The OTP methods renamed from `otp_send`/`otp_verify` to `send_otp`/`verify_otp` to align with the backend route shape. The old names are removed — no aliases.
- `login` and `lookup_organizations` (formerly callers used a manual request) also take `app_uuid: str`.

### Added
- `exchange_api_key(api_key)`, `exchange_refresh_token(refresh_token)` — `POST /api/v1/auth/api-key/exchange`.
- `oauth_start_url(provider, app_uuid, return_to)` — URL builder for the public OAuth start endpoint (no network call).
- App-level API key admin: `list_app_api_keys`, `create_app_api_key`, `revoke_app_api_key`, `rotate_app_api_key`.
- OAuth config admin: `list_oauth_configs`, `create_oauth_config`, `update_oauth_config`, `delete_oauth_config`.
- `read_audit_log(app_uuid, limit=None, action_prefix=None)`.
- New types exported from `buttrbase`: `ExchangeResponse`, `ApiKeySummary`, `CreatedKeyResponse`, `CreateApiKeyInput`, `ExpiryInput`, `OAuthConfigSummary`, `CreateOAuthConfigInput`, `UpdateOAuthConfigInput`, `AuditRow`.

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
