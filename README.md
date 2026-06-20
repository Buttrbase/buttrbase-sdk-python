# Python SDK

> **Breaking — v0.2 — `app_uuid: str` replaces the `app` slug parameter** on `register`, `login`, `send_otp`, `verify_otp`, `send_magic_link`, and `lookup_organizations`. The backend no longer accepts slug-shaped app identifiers — pass the UUID directly. The OTP methods are also renamed from `otp_send`/`otp_verify` to `send_otp`/`verify_otp`. See `CHANGELOG.md`.

## Overview

The official Python SDK for ButtrBase. Synchronous, `requests`-based client covering every API surface — auth, organizations, billing, RBAC, teams, credentials, search, AI gateway, webhooks, zero-trust, and more.

## Installation

```bash
pip install buttrbase
```

## Quick Start

```python
from buttrbase import ButtrbaseClient

# App-server callers authenticate with an OAuth2 client-credentials pair
# (see "App Authentication" below). Construct with client_id/client_secret
# and the SDK fetches + refreshes the access token for you. End-user flows
# can start from an anonymous client and let login() stash the user token.
client = ButtrbaseClient(client_id="<client-id>", client_secret="<client-secret>")

# Login — app_uuid is required (the UUID for your app on ButtrBase)
resp = client.login(
    "user@example.com",
    "password",
    org_name="acme",
    app_uuid="018f1234-5678-7000-8000-000000000001",
)
print(resp["access_token"])

# Get profile
profile = client.get_profile()
print(profile)
```

## App Authentication (OAuth2 client-credentials)

App servers authenticate with an OAuth2 **client-credentials** pair —
a `client_id` and `client_secret`.

Manage client-credentials with the `/credentials` endpoints. The
`client_secret` is returned **only** on create and rotate — store it in a
secret manager.

```python
# Create a credential. client_secret is shown once.
created = client.create_credential("prod-server")
client_id = created["client_id"]
client_secret = created["client_secret"]  # store securely

# Rotate the secret when needed (also shown once).
rotated = client.rotate_credential_secret(created["credentials_id"])
client_secret = rotated["client_secret"]

# List / fetch / delete.
creds = client.list_credentials()
cred = client.get_credential(created["credentials_id"])
client.delete_credential(created["credentials_id"])
```

Construct the client with the pair and the SDK handles the token grant for
you — it exchanges `client_id` + `client_secret` at
`POST /api/v1/auth/token` lazily before the first authenticated request,
caches the resulting bearer, and refreshes it (slightly early) when it
expires:

```python
client = ButtrbaseClient(client_id="<client-id>", client_secret="<client-secret>")

# The first authed call transparently fetches a token; later calls reuse it.
profile = client.get_profile()

# Optional: fetch a token eagerly (e.g. to fail fast on bad credentials).
client.authenticate()
```

You can still pass `access_token="<token>"` directly if you obtain one out
of band; in that case the SDK uses it as-is.

## Authentication

### Register

```python
APP_UUID = "018f1234-5678-7000-8000-000000000001"

resp = client.register(
    "user@example.com",
    "password",
    org_name="acme",
    app_uuid=APP_UUID,
    first_name="Jane",
    last_name="Doe",
)
```

### Organization Lookup

```python
resp = client.lookup_organizations("user@example.com", app_uuid=APP_UUID)
```

### Login Options

```python
options = client.get_login_options("org-uuid")
```

### Magic-link (passwordless sign-in)

Magic-link is a two-step, email-based passwordless flow: **send** delivers a
one-time link to the user's inbox, and **verify** exchanges the link's token
for an access token.

#### Why magic-link (RS256) and not email OTP (HS256)

Magic-link is the **only browser flow that yields a JWKS-verifiable RS256
access token.** The generic email-OTP endpoints (`send_otp` / `verify_otp`)
issue **HS256** tokens signed with Buttrbase's server secret — the public JWKS
**cannot** verify those. So any third-party app that validates Buttrbase tokens
against the public JWKS **must use magic-link** for browser sign-in.

| Flow | Token alg | Signed with | Verifiable via public JWKS |
| --- | --- | --- | --- |
| Magic-link | RS256 | Buttrbase private key | ✅ Yes |
| Email OTP (`send_otp`/`verify_otp`) | HS256 | Buttrbase server secret | ❌ No |

#### Send → verify flow

1. **Send** — call `send_magic_link(email, app_uuid=..., redirect_to=...)`.
   Response: `{"sent": bool, "dev_token": str | None, "expires_in_seconds": int}`.
   `dev_token` is the raw one-time token, returned only in non-prod dev-echo
   mode (`None` in prod). The user receives an email with a link.
2. **Verify** — your callback receives the token (as `?token=...` on
   `redirect_to`, or you use `dev_token` in dev). Call
   `verify_magic_link(token)` to exchange it. Response:
   `{"access_token": str, "token_type": str, "user": {"user_uuid": str, "email": str}, "redirect_to": str | None}`.
   `access_token` is the RS256 JWT you verify against the JWKS.

#### Cross-app federation and the redirect allowlist

If you pass `app_uuid` together with a `redirect_to` whose **origin** is
registered on the Buttrbase application (its WebAuthn `rp_origins` or
configured redirect URL), the email link points at **your app's own callback**
(`{redirect_to}?token=...`), so your app verifies the RS256 token itself. This
is what enables a third-party app to own the sign-in completion.

- Non-allowlisted or non-absolute `redirect_to` targets **fall back** to the
  Buttrbase-hosted sign-in page.
- **Omit `redirect_to`** for the first-party (Buttrbase-hosted) flow.

#### Example

```python
# 1. Send the magic-link email pointing at your app's callback.
sent = client.send_magic_link(
    "user@example.com",
    app_uuid=APP_UUID,
    redirect_to="https://app.example.com/auth/callback",
)
print(sent["expires_in_seconds"])
token = sent.get("dev_token")  # dev-echo only; None in prod

# 2. In your callback handler, exchange the token for an RS256 access token.
#    (In prod the token arrives as ?token=... on your redirect_to URL.)
resp = client.verify_magic_link(token)
print(resp["access_token"])          # RS256 JWT — verify against the public JWKS
print(resp["user"]["user_uuid"])
```

### OTP (Passwordless Phone)

```python
client.send_otp("+15551234567", app_uuid=APP_UUID)
resp = client.verify_otp("+15551234567", "123456", app_uuid=APP_UUID)
```

### Passkey support (WebAuthn)

Thin wrappers around the four passkey ceremony endpoints. The WebAuthn JSON
blobs are pass-through `Any` — the browser's `navigator.credentials.create /
.get` APIs consume and produce them directly. No webauthn helper library is
pulled in on the SDK side.

```python
# Registration (requires an authenticated caller — the passkey is added to
# the user's existing account). The browser does the actual WebAuthn ceremony.
begin = client.passkey_register_begin()
# ... hand begin["challenge"] to the browser, get back a credential ...
result = client.passkey_register_complete({
    "registration_state": begin["registration_state"],
    "credential": browser_credential,
})
print(result["credential_id"])

# Authentication (anonymous):
ch = client.passkey_authenticate_begin()
# ... browser produces an assertion ...
session = client.passkey_authenticate_complete({
    "auth_state": ch["auth_state"],
    "credential": browser_assertion,
})

# List the signed-in user's enrolled passkeys (descending by created_at):
passkeys = client.list_my_passkeys()
for p in passkeys:
    print(p.get("nickname") or p["credential_id_prefix"], p["credential_uuid"])

# Revoke one by its credential_uuid (owner check enforced server-side):
client.delete_my_passkey(passkeys[0]["credential_uuid"])
```

### OAuth (Google / Microsoft / GitHub / Apple)

```python
# The SDK builds the URL — there is no network call here. Redirect
# the user-agent to the returned string; the backend 302s onward to
# the provider with a signed state token.
url = client.oauth_start_url(
    "google",
    app_uuid=APP_UUID,
    return_to="https://app.example.com/auth/google/callback",
)
# Send `url` back to the browser as a 302 Location.
```

### SSO (OIDC / SAML)

```python
url_resp = client.oidc_authorize_url("connection-uuid")
callback_resp = client.oidc_callback({"code": "...", "state": "..."})

saml_url = client.saml_authorize_url("connection-uuid")
saml_resp = client.saml_callback({"SAMLResponse": "..."})
```

## MFA / TOTP

```python
status = client.mfa_status_full()
enrollment = client.mfa_totp_enroll()
client.mfa_totp_activate("123456")
client.mfa_totp_verify("123456")
client.mfa_totp_challenge()
codes = client.mfa_generate_recovery_codes()
client.mfa_redeem_recovery_code("recovery-code")
client.mfa_totp_disable()
```

## Step-Up Auth

```python
resp = client.auth_step_up("totp-code")
# client.access_token is auto-replaced with the elevated token
```

## Organization Security

```python
settings = client.get_security_settings("org-uuid")
client.update_security_settings("org-uuid", {"mfa_required": True})

connections = client.list_sso_connections("org-uuid")
client.create_sso_connection("org-uuid", {"provider": "okta", "name": "Okta SSO"})

events = client.list_audit_events("org-uuid")
export = client.export_audit_events("org-uuid")
```

## Branding

```python
branding = client.get_branding("org-uuid")
client.update_branding("org-uuid", {"primary_color": "#FF0000"})
```

## Sessions & Devices

```python
sessions = client.org_session_inventory("org-uuid")
client.org_revoke_all_sessions("org-uuid")

accounts = client.list_device_accounts("device-uuid")
client.add_device_account("device-uuid", {"email": "user@example.com", "org_name": "Acme"})
client.switch_device_active_account("device-uuid", "account-uuid")

device_sessions = client.device_session_inventory("device-uuid")
client.revoke_all_device_sessions("device-uuid")
```

## API Keys v2

```python
keys = client.list_api_keys_v2("org-uuid")
new_key = client.create_api_key_v2("org-uuid", "my-api-key")
client.delete_api_key_v2("org-uuid", "key-uuid")
```

## Service Identities

```python
identities = client.list_service_identities("org-uuid")
identity = client.create_service_identity("org-uuid", {"name": "ci-runner"})
token = client.create_service_identity_automation_token("org-uuid", {"name": "ci"})
client.delete_service_identity("org-uuid", "key-uuid")
```

## Entitlements

```python
check = client.entitlements_check({"feature": "advanced-analytics", "org_uuid": "..."})
batch = client.entitlements_check_batch({"checks": [...]})
effective = client.entitlements_effective()
explanation = client.admin_entitlements_explain({"feature": "..."})
```

## Pricing

```python
preview = client.pricing_preview({"plan": "pro"})
quote = client.pricing_quote({"plan": "pro", "seats": 10})
session = client.pricing_checkout_session({"plan": "pro"})
catalog = client.catalog_pricing_preview({"plan": "pro"})
```

## Coupons & Gift Cards

```python
# Admin CRUD
coupons = client.admin_list_product_coupons("product-id")
coupon = client.admin_create_product_coupon("product-id", {"code": "SAVE20", "discount_type": "percent", "discount_value": 20})
client.admin_update_product_coupon("product-id", "coupon-id", {"active": False})
client.admin_delete_product_coupon("product-id", "coupon-id")

# Public validation
result = client.validate_coupon_public("SAVE20")
gc = client.validate_gift_card_public("GC-123")
redemption = client.redeem_gift_card_public("GC-123")
```

## Labels & Tags

```python
client.set_coupon_labels("coupon-id", ["summer", "promo"])
client.add_coupon_label("coupon-id", "flash-sale")
client.remove_coupon_label("coupon-id", "summer")

client.set_product_tags("product-id", ["featured", "new"])
client.add_product_tag("product-id", "bestseller")
client.remove_product_tag("product-id", "new")
```

## Analytics

```python
client.ingest_analytics_event({"event": "page_view", "page": "/pricing"})
app_overview = client.analytics_app_overview("app-uuid")
org_overview = client.analytics_org_overview("org-uuid")
```

## Teams

```python
team = client.create_team({"name": "Engineering", "org_uuid": "..."})
teams = client.list_org_teams("org-uuid")
inactive = client.list_inactive_teams("org-uuid")
client.reactivate_team("team-uuid")
client.archive_team("team-uuid")

members = client.list_team_members("team-uuid")
client.add_team_member("team-uuid", "user-uuid")
client.remove_team_member("team-uuid", "user-uuid")

observers = client.list_team_observers("team-uuid")
client.add_team_observer("team-uuid", "user-uuid")
client.remove_team_observer("team-uuid", "user-uuid")

user_teams = client.get_user_teams_list("user-uuid")
observed = client.get_user_observed_teams("user-uuid")
```

## Org Features

```python
features = client.list_org_features("org-uuid")
client.set_org_feature("org-uuid", {"feature_id": "dark-mode", "enabled": True})
client.remove_org_feature("org-uuid", "dark-mode")
```

## Roles & Permissions

```python
roles = client.list_roles()
permissions = client.list_all_permissions()
role_perms = client.get_role_permissions(1)
client.update_role_permissions(1, {"permissions": [1, 2, 3]})
```

## Billing

```python
checkout = client.checkout("price_123", coupon_code="SAVE20")
history = client.get_billing_history()
invoices = client.list_invoices()
config = client.get_provider_config("stripe")
client.add_add_on("extra-seats")
```

## Payments

```python
session = client.create_payment_checkout({"amount": 5000, "currency": "usd"})
invoice = client.send_invoice({"amount": 5000, "customer_email": "buyer@example.com"})
```

## Admin: Signing Keys

```python
keys = client.list_signing_keys("org-uuid")
client.rotate_signing_keys("org-uuid")
audit = client.list_signing_audit("org-uuid")
signed = client.sign_payload("org-uuid", {"claims": {"sub": "user-123"}})
```

## Admin: mTLS CA

```python
ca = client.get_ca("org-uuid")
ca = client.init_ca("org-uuid", {"common_name": "My CA"})
certs = client.list_certificates("org-uuid")
cert = client.issue_certificate("org-uuid", {"csr": "..."})
client.revoke_certificate("org-uuid", "serial-number")
```

## Admin: Secrets Vault

```python
secrets = client.list_secrets("org-uuid")
client.put_secret_admin("org-uuid", "DB_URL", "postgres://...")
secret = client.get_secret_by_name("org-uuid", "DB_URL")
client.delete_secret("org-uuid", "DB_URL")
```

## Admin: Zero Trust

```python
client.revoke_jti("jti-value")
metrics = client.org_metrics_admin("org-uuid")
client.re_encrypt_secrets("org-uuid")
client.re_encrypt_signing_keys("org-uuid")
client.re_encrypt_mtls_ca("org-uuid")
events = client.list_auth_events_admin("org-uuid")
client.purge_auth_events("org-uuid")
status = client.kms_status("org-uuid")
client.saml_cert_rollover("org-uuid", "conn-uuid", {"cert": "..."})
client.update_payment_settings("org-uuid", {"auto_charge": True})
```

## Admin: JIT Elevation

```python
grant = client.jit_request_grant("org-uuid", {"scope": "admin", "reason": "incident response"})
client.jit_approve_grant("org-uuid", "grant-uuid")
grants = client.jit_list_grants("org-uuid")
```

## Admin: Domains & Webhooks

```python
domains = client.list_domains("org-uuid")
domain = client.create_domain("org-uuid", "example.com")
client.verify_domain("org-uuid", 1)
client.delete_domain("org-uuid", 1)

endpoints = client.list_webhook_endpoints("org-uuid")
ep = client.create_webhook_endpoint("org-uuid", "https://hook.example.com", ["user.created"])
deliveries = client.list_webhook_deliveries("org-uuid")
```

## AI Gateway

```python
resp = client.ai_chat_completions("org-uuid", "openai", {
    "model": "gpt-4",
    "messages": [{"role": "user", "content": "Hello!"}]
})
```

## SMS & Email

```python
client.send_sms("to-phone", "Hello from ButtrBase!")
client.verify_email_identity("user@example.com")
```

## Errors

Errors are raised as `buttrbase.ButtrbaseError` with `status_code`, `code`, `detail`.

## Docs

See https://buttrbase.com/docs for the full API reference.

## OAuth Configs (admin)

```python
APP_UUID = "018f1234-5678-7000-8000-000000000001"

# Register a Google config — client_secret is encrypted at rest and
# never returned by any GET.
cfg = client.create_oauth_config(
    APP_UUID,
    {
        "provider": "google",
        "client_id": "1234.apps.googleusercontent.com",
        "client_secret": "GOCSPX-…",
        "redirect_uris": [
            "http://localhost:3000/auth/google/callback",
            "https://app.example.com/auth/google/callback",
        ],
        "scopes": ["openid", "email", "profile"],
        "enabled": True,
    },
)

# Patch — every field is optional. Omitting client_secret (or sending
# "") leaves the stored ciphertext untouched.
client.update_oauth_config(APP_UUID, "google", {"enabled": False})

configs = client.list_oauth_configs(APP_UUID)
client.delete_oauth_config(APP_UUID, "google")
```

## Audit Log

```python
# Most recent events for the app.
events = client.read_audit_log(APP_UUID, limit=50)

# Filter to just OAuth-config lifecycle events.
cfg_events = client.read_audit_log(
    APP_UUID, limit=100, action_prefix="oauth_config."
)
```

## Zero Trust: Scope Context, Devices & Tenant Discovery

Client-facing endpoints for windowed scope re-mint, self-service device-key
management, and public tenant-home discovery.

```python
# Windowed / JIT scope re-mint. Requires an authenticated end user; the new
# access token is stashed back onto the client. A scope you don't hold -> 403;
# a scope behind a step-up gate -> 401 (code == "step_up_required").
resp = client.scope_context(["billing:read", "billing:write"])
print(resp["token"], resp["scopes"])  # granted (sorted) subset

# List & revoke the caller's own device keys (no key material returned).
devices = client.list_devices()
for d in devices:
    print(d["device_uuid"], d["jkt"], d["last_seen_at"])
client.revoke_device("device-uuid")

# Public pre-auth discovery: resolve an ACTIVE tenant's home (404 otherwise).
home = client.get_tenant_home("org-uuid", app_id=42)
print(home["tenancy_mode"], home["home_region"], home["home_base_url"])
```

## Recipes

### Complete Onboarding

```python
from buttrbase import ButtrbaseClient

client = ButtrbaseClient(client_id="<client-id>", client_secret="<client-secret>")
APP_UUID = "018f1234-5678-7000-8000-000000000001"

# 1. Register and login
client.register(
    "admin@acme.com",
    "s3cur3!",
    org_name="acme",
    app_uuid=APP_UUID,
    first_name="Alice",
)
resp = client.login(
    "admin@acme.com",
    "s3cur3!",
    org_name="acme",
    app_uuid=APP_UUID,
)

# 2. Get profile
profile = client.get_profile()

# 3. Create a team and add a member
team = client.create_team({"name": "Engineering", "org_uuid": profile["org"]["uuid"]})
client.add_team_member(team["uuid"], "colleague-user-uuid")
```

### Backend-to-Backend Auth (OAuth2 client-credentials)

```python
# 1. (One-time) Create a client-credentials pair. client_secret is shown
#    once — store it in a secret manager.
admin = ButtrbaseClient(access_token=ADMIN_ACCESS_TOKEN)
created = admin.create_credential("prod-srv")
CLIENT_ID = created["client_id"]
CLIENT_SECRET = created["client_secret"]  # save this — shown once

# 2. Construct your server's client with the pair. The SDK runs the
#    client-credentials grant (POST /api/v1/auth/token) for you: it fetches
#    a token lazily before the first authed call, caches it, and refreshes
#    it automatically (slightly early) when it expires.
client = ButtrbaseClient(client_id=CLIENT_ID, client_secret=CLIENT_SECRET)

# 3. Just make calls — no manual token management needed.
profile = client.get_profile()
```

### Registering a Social Login Provider

```python
client.create_oauth_config(
    APP_UUID,
    {
        "provider": "microsoft",
        "client_id": "<azure-app-client-id>",
        "client_secret": "<azure-app-secret>",
        "redirect_uris": ["https://app.example.com/auth/microsoft/callback"],
        "scopes": ["openid", "email", "profile"],
        "enabled": True,
    },
)

# Then, from the browser flow:
url = client.oauth_start_url(
    "microsoft",
    app_uuid=APP_UUID,
    return_to="https://app.example.com/auth/microsoft/callback",
)
```

### MFA Enrollment

```python
# 1. Check MFA status
status = client.mfa_status_full()

# 2. Enroll in TOTP — returns secret + QR URL
enrollment = client.mfa_totp_enroll()
print(f"Scan this QR: {enrollment['qr_code_url']}")

# 3. Activate with code from authenticator app
client.mfa_totp_activate("123456")

# 4. Generate recovery codes
codes = client.mfa_generate_recovery_codes()
print(f"Save these recovery codes: {codes['codes']}")
```

### Checkout Flow

```python
# 1. Preview pricing
preview = client.pricing_preview({"plan": "pro", "seats": 10})

# 2. Check entitlement
check = client.entitlements_check("advanced-analytics", org_uuid="org-uuid")

# 3. Create checkout session
session = client.pricing_checkout_session({"plan": "pro", "seats": 10})
print(f"Redirect to: {session['url']}")
```

### SSO Setup

```python
# 1. Create an OIDC connection
conn = client.create_sso_connection("org-uuid", "okta", "Okta SSO",
    {"domain": "myorg.okta.com", "client_id": "...", "client_secret": "..."})

# 2. Get the authorize URL
url = client.oidc_authorize_url(conn["connection_uuid"])

# 3. Handle callback (on your server)
resp = client.oidc_callback({"code": "auth-code", "state": "state-value"})
```

### Secrets & Key Management

```python
# 1. Store a secret
client.put_secret_admin("org-uuid", "DATABASE_URL", "postgres://...")

# 2. List and retrieve secrets
secrets = client.list_secrets("org-uuid")
secret = client.get_secret_by_name("org-uuid", "DATABASE_URL")

# 3. Rotate signing keys
client.rotate_signing_keys("org-uuid")
audit = client.list_signing_audit("org-uuid")
```

## Releasing (maintainers)

Tagged pushes (`v*`) trigger `.github/workflows/release.yml`, which builds and publishes to PyPI via [trusted publishing](https://docs.pypi.org/trusted-publishers/) — no API token required.
