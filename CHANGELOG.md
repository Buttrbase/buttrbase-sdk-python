# Changelog

## 0.6.0 — JWKS-backed RS256 Verifier (feature parity with Rust SDK)

Mirrors Rust SDK `Verifier`. Strictly additive — no existing fields removed or
renamed. Requires `PyJWT[crypto]>=2.8`; install via `pip install 'buttrbase[crypto]'`.

### Added

- `buttrbase.verify.Verifier` — RS256 JWKS-backed token verifier with an
  internal JWKS cache (via `PyJWKClient`). Constructor args:
  `Verifier(jwks_url, issuer, audience=None)`. Mirrors the Rust SDK's
  `VerifierConfig { jwks_url, issuer, audience: Option }`.
- `Verifier.verify_token(token: str) -> Claims` — fetches/caches the JWKS,
  validates RS256 signature + issuer (+ optional audience), returns enriched
  `Claims` (reusing the existing dataclasses — no duplication).
- `Verifier.verify_bearer(authorization: str) -> TokenPrincipal` — strips
  `Bearer ` prefix, calls `verify_token`, returns `TokenPrincipal`
  (roles/email/scopes/user_id/org_id). Mirrors Rust SDK's `verify_bearer`.
- `buttrbase.verify.VerifierError` — raised on any verification failure
  (bad signature, expired, wrong issuer, wrong audience, JWKS fetch error).
- Both `Verifier` and `VerifierError` re-exported from the top-level
  `buttrbase` package.
- `PyJWT[crypto]>=2.8` added as `[crypto]` optional extra in `pyproject.toml`.
  Install with `pip install 'buttrbase[crypto]'`.
- 22 new tests in `tests/test_verifier.py` — fully offline (PyJWKClient
  monkeypatched; RSA keypairs generated locally). Covers happy path, bad
  signature, wrong issuer, expired, wrong audience, missing Bearer, JWKS
  lookup failure, and end-to-end enriched claims / roles / email / scopes.

## 0.5.0 — token claims enrichment (data-envelope: roles / email)

Mirrors Rust SDK 0.6.0.  Strictly additive — no existing fields removed or renamed.

### Added

- `buttrbase.verify` module: `ClaimsData`, `Claims`, `TokenPrincipal`,
  `principal_from_payload`.
- `ClaimsData` carries the optional `roles`, `email`, `org_uuid`, and
  `user_uuid` fields from the buttrbase token `data` envelope.
- `Claims.from_dict(payload)` parses a decoded JWT payload (a plain `dict`)
  into a typed `Claims` object, populating `data` when the envelope is present.
- `TokenPrincipal.from_claims(claims)` derives the application-level principal:
  `roles: list[str]` (split from `data.roles` on commas and spaces, matching
  the Rust SDK split behaviour) and `email: str | None`.
- `principal_from_payload(payload)` — one-shot helper combining both steps.
- All four names re-exported from the top-level `buttrbase` package.
- No new runtime dependencies.

## 0.4.0 — magic-link cross-app federation

### Breaking
- `send_magic_link` keyword-only parameters reordered to lead with the
  federation pair: `(email, *, app_uuid=None, redirect_to=None, org_uuid=None)`.
  Passing `app_uuid` + an allowlisted `redirect_to` now points the email link
  at the caller app's own callback (`{redirect_to}?token=...`) so the app
  verifies the RS256 token itself; non-allowlisted/non-absolute targets fall
  back to the Buttrbase-hosted sign-in page.

### Notes
- Magic-link is the only browser flow that yields a JWKS-verifiable **RS256**
  access token. The email-OTP endpoints (`send_otp`/`verify_otp`) issue HS256
  tokens signed with Buttrbase's server secret, which the public JWKS cannot
  verify — third-party apps must use magic-link.
- `send` response documented as `{"sent", "dev_token", "expires_in_seconds"}`
  and `verify` as `{"access_token", "token_type", "user", "redirect_to"}`.
  `verify_magic_link(token)` takes only the token (the stale README note
  claiming it took `app_uuid` is corrected).

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

### Added
- `ButtrbaseClient(client_id=..., client_secret=...)` and an
  `authenticate()` method implementing the OAuth2 client-credentials grant
  (`POST /api/v1/auth/token`). Construct the client with the pair and authed
  calls work end-to-end: the SDK fetches an access token lazily before the
  first authenticated request, caches it as the bearer, and refreshes it
  (slightly early, using `expires_in`) when it expires. Passing
  `access_token=...` directly is still supported.

### Notes
- Manage client-credentials via the existing `/credentials` endpoints
  (`create_credential`, `rotate_credential_secret`, `list_credentials`,
  `get_credential`, `delete_credential`).

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
