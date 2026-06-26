"""Tests for buttrbase.verify.Verifier — JWKS-backed RS256 signature verification.

All tests are fully offline: PyJWKClient is monkeypatched to return a locally
generated key so no network calls are made.
"""
from __future__ import annotations

import base64
import time
from typing import Any
from unittest.mock import MagicMock, patch

import jwt
import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt import PyJWK

from buttrbase import Verifier, VerifierError
from buttrbase.verify import Claims, TokenPrincipal


# ---------------------------------------------------------------------------
# Key generation helpers
# ---------------------------------------------------------------------------


def _generate_rsa_keypair():
    """Return (private_key, public_key) RSA-2048 pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    return private_key, private_key.public_key()


def _int_to_base64url(n: int) -> str:
    """Encode a big integer as base64url (no padding), as required by JWK."""
    length = (n.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()


def _make_jwk_dict(public_key: Any, kid: str = "test-kid-1") -> dict:
    """Build a minimal RS256 JWK dict from an RSA public key."""
    pub_numbers = public_key.public_numbers()
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": _int_to_base64url(pub_numbers.n),
        "e": _int_to_base64url(pub_numbers.e),
    }


# ---------------------------------------------------------------------------
# Token-signing fixture builder
# ---------------------------------------------------------------------------


def _sign_token(
    private_key: Any,
    *,
    kid: str = "test-kid-1",
    issuer: str = "https://auth.buttrbase.com",
    audience: str | None = None,
    sub: str = "11111111-1111-1111-1111-111111111111",
    org: str = "22222222-2222-2222-2222-222222222222",
    scope: list[str] | None = None,
    roles: str = "owner",
    email: str = "test@example.com",
    exp_offset: int = 3600,
) -> str:
    """Sign a token with the given private key, returning the JWT string."""
    now = int(time.time())
    payload: dict[str, Any] = {
        "sub": sub,
        "org": org,
        "iss": issuer,
        "iat": now,
        "exp": now + exp_offset,
        "scope": scope or ["read:messages", "write:messages"],
        "data": {"roles": roles, "email": email},
    }
    if audience is not None:
        payload["aud"] = audience
    return jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": kid})


def _make_pyjwk(public_key: Any, kid: str = "test-kid-1") -> PyJWK:
    """Build a PyJWK from a public key (for monkeypatching)."""
    return PyJWK.from_dict(_make_jwk_dict(public_key, kid))


# ---------------------------------------------------------------------------
# Helpers for patching PyJWKClient
# ---------------------------------------------------------------------------


def _patch_jwks_client(pyjwk: PyJWK):
    """Return a context manager that patches PyJWKClient so get_signing_key_from_jwt
    always returns *pyjwk* without making any network calls."""

    mock_client = MagicMock()
    mock_client.get_signing_key_from_jwt.return_value = pyjwk

    return patch(
        "buttrbase.verify.PyJWKClient",  # module path where Verifier imports it
        return_value=mock_client,
    )


# ---------------------------------------------------------------------------
# Tests — happy-path verify_token
# ---------------------------------------------------------------------------


class TestVerifierVerifyToken:
    def setup_method(self):
        self.private_key, self.public_key = _generate_rsa_keypair()
        self.pyjwk = _make_pyjwk(self.public_key)

    def test_verify_token_returns_claims(self):
        token = _sign_token(self.private_key)
        with _patch_jwks_client(self.pyjwk):
            verifier = Verifier(
                jwks_url="https://auth.example.com/.well-known/jwks.json",
                issuer="https://auth.buttrbase.com",
            )
            claims = verifier.verify_token(token)

        assert isinstance(claims, Claims)
        assert claims.sub == "11111111-1111-1111-1111-111111111111"
        assert claims.org == "22222222-2222-2222-2222-222222222222"

    def test_verify_token_populates_data_envelope(self):
        token = _sign_token(self.private_key, roles="owner,org_admin", email="user@corp.com")
        with _patch_jwks_client(self.pyjwk):
            verifier = Verifier(
                jwks_url="https://auth.example.com/.well-known/jwks.json",
                issuer="https://auth.buttrbase.com",
            )
            claims = verifier.verify_token(token)

        assert claims.data is not None
        assert claims.data.roles == "owner,org_admin"
        assert claims.data.email == "user@corp.com"

    def test_verify_token_with_audience(self):
        token = _sign_token(
            self.private_key,
            audience="my-app",
        )
        with _patch_jwks_client(self.pyjwk):
            verifier = Verifier(
                jwks_url="https://auth.example.com/.well-known/jwks.json",
                issuer="https://auth.buttrbase.com",
                audience="my-app",
            )
            claims = verifier.verify_token(token)

        assert claims.sub == "11111111-1111-1111-1111-111111111111"

    def test_verify_token_scope_populated(self):
        token = _sign_token(self.private_key, scope=["read:users", "write:users"])
        with _patch_jwks_client(self.pyjwk):
            verifier = Verifier(
                jwks_url="https://auth.example.com/.well-known/jwks.json",
                issuer="https://auth.buttrbase.com",
            )
            claims = verifier.verify_token(token)

        assert claims.scope == ["read:users", "write:users"]


# ---------------------------------------------------------------------------
# Tests — happy-path verify_bearer
# ---------------------------------------------------------------------------


class TestVerifierVerifyBearer:
    def setup_method(self):
        self.private_key, self.public_key = _generate_rsa_keypair()
        self.pyjwk = _make_pyjwk(self.public_key)

    def test_verify_bearer_returns_token_principal(self):
        token = _sign_token(self.private_key)
        with _patch_jwks_client(self.pyjwk):
            verifier = Verifier(
                jwks_url="https://auth.example.com/.well-known/jwks.json",
                issuer="https://auth.buttrbase.com",
            )
            principal = verifier.verify_bearer(f"Bearer {token}")

        assert isinstance(principal, TokenPrincipal)
        assert principal.user_id == "11111111-1111-1111-1111-111111111111"
        assert principal.org_id == "22222222-2222-2222-2222-222222222222"

    def test_verify_bearer_exposes_roles(self):
        token = _sign_token(self.private_key, roles="owner,org_admin")
        with _patch_jwks_client(self.pyjwk):
            verifier = Verifier(
                jwks_url="https://auth.example.com/.well-known/jwks.json",
                issuer="https://auth.buttrbase.com",
            )
            principal = verifier.verify_bearer(f"Bearer {token}")

        assert "owner" in principal.roles
        assert "org_admin" in principal.roles

    def test_verify_bearer_exposes_email(self):
        token = _sign_token(self.private_key, email="alice@example.com")
        with _patch_jwks_client(self.pyjwk):
            verifier = Verifier(
                jwks_url="https://auth.example.com/.well-known/jwks.json",
                issuer="https://auth.buttrbase.com",
            )
            principal = verifier.verify_bearer(f"Bearer {token}")

        assert principal.email == "alice@example.com"

    def test_verify_bearer_exposes_scopes(self):
        token = _sign_token(self.private_key, scope=["read:pages", "write:pages"])
        with _patch_jwks_client(self.pyjwk):
            verifier = Verifier(
                jwks_url="https://auth.example.com/.well-known/jwks.json",
                issuer="https://auth.buttrbase.com",
            )
            principal = verifier.verify_bearer(f"Bearer {token}")

        assert "read:pages" in principal.scopes
        assert "write:pages" in principal.scopes


# ---------------------------------------------------------------------------
# Tests — negative: bad Bearer header
# ---------------------------------------------------------------------------


class TestVerifierBearerHeaderErrors:
    def setup_method(self):
        self.private_key, self.public_key = _generate_rsa_keypair()
        self.pyjwk = _make_pyjwk(self.public_key)

    def test_missing_bearer_prefix_raises(self):
        token = _sign_token(self.private_key)
        with _patch_jwks_client(self.pyjwk):
            verifier = Verifier(
                jwks_url="https://auth.example.com/.well-known/jwks.json",
                issuer="https://auth.buttrbase.com",
            )
            with pytest.raises(VerifierError, match="Bearer"):
                verifier.verify_bearer(token)  # bare token, no "Bearer " prefix

    def test_empty_authorization_raises(self):
        with _patch_jwks_client(self.pyjwk):
            verifier = Verifier(
                jwks_url="https://auth.example.com/.well-known/jwks.json",
                issuer="https://auth.buttrbase.com",
            )
            with pytest.raises(VerifierError, match="Bearer"):
                verifier.verify_bearer("")

    def test_basic_scheme_raises(self):
        with _patch_jwks_client(self.pyjwk):
            verifier = Verifier(
                jwks_url="https://auth.example.com/.well-known/jwks.json",
                issuer="https://auth.buttrbase.com",
            )
            with pytest.raises(VerifierError, match="Bearer"):
                verifier.verify_bearer("Basic dXNlcjpwYXNz")


# ---------------------------------------------------------------------------
# Tests — negative: invalid / tampered / expired tokens
# ---------------------------------------------------------------------------


class TestVerifierTokenErrors:
    def setup_method(self):
        self.private_key, self.public_key = _generate_rsa_keypair()
        self.pyjwk = _make_pyjwk(self.public_key)
        # A separate keypair to generate a token signed by a different key
        self.other_private_key, _ = _generate_rsa_keypair()

    def test_bad_signature_raises(self):
        """Token signed with a different key → PyJWT raises → VerifierError."""
        token = _sign_token(self.other_private_key)  # signed with OTHER key
        with _patch_jwks_client(self.pyjwk):  # but verifier has ORIGINAL pubkey
            verifier = Verifier(
                jwks_url="https://auth.example.com/.well-known/jwks.json",
                issuer="https://auth.buttrbase.com",
            )
            with pytest.raises(VerifierError):
                verifier.verify_token(token)

    def test_expired_token_raises(self):
        """exp in the past → ExpiredSignatureError → VerifierError."""
        token = _sign_token(self.private_key, exp_offset=-3600)  # expired 1h ago
        with _patch_jwks_client(self.pyjwk):
            verifier = Verifier(
                jwks_url="https://auth.example.com/.well-known/jwks.json",
                issuer="https://auth.buttrbase.com",
            )
            with pytest.raises(VerifierError, match="[Ee]xpir"):
                verifier.verify_token(token)

    def test_wrong_issuer_raises(self):
        """Token from a different issuer → InvalidIssuerError → VerifierError."""
        token = _sign_token(self.private_key, issuer="https://evil.example.com")
        with _patch_jwks_client(self.pyjwk):
            verifier = Verifier(
                jwks_url="https://auth.example.com/.well-known/jwks.json",
                issuer="https://auth.buttrbase.com",  # expected issuer is different
            )
            with pytest.raises(VerifierError, match="[Ii]ssuer"):
                verifier.verify_token(token)

    def test_jwks_lookup_failure_raises(self):
        """When the JWKS lookup itself fails, VerifierError is raised."""
        token = _sign_token(self.private_key)
        mock_client = MagicMock()
        mock_client.get_signing_key_from_jwt.side_effect = Exception("connection refused")

        with patch("buttrbase.verify.PyJWKClient", return_value=mock_client):
            verifier = Verifier(
                jwks_url="https://auth.example.com/.well-known/jwks.json",
                issuer="https://auth.buttrbase.com",
            )
            with pytest.raises(VerifierError, match="JWKS key lookup failed"):
                verifier.verify_token(token)

    def test_wrong_audience_raises(self):
        """Token with no aud but verifier expects one → VerifierError."""
        # Token signed with aud="wrong-app" but verifier expects "my-app"
        token = _sign_token(self.private_key, audience="wrong-app")
        with _patch_jwks_client(self.pyjwk):
            verifier = Verifier(
                jwks_url="https://auth.example.com/.well-known/jwks.json",
                issuer="https://auth.buttrbase.com",
                audience="my-app",
            )
            with pytest.raises(VerifierError):
                verifier.verify_token(token)


# ---------------------------------------------------------------------------
# Tests — Verifier accessors / constructor
# ---------------------------------------------------------------------------


class TestVerifierAccessors:
    def test_issuer_accessor(self):
        with patch("buttrbase.verify.PyJWKClient"):
            v = Verifier(
                jwks_url="https://auth.example.com/.well-known/jwks.json",
                issuer="https://auth.buttrbase.com",
            )
        assert v.issuer == "https://auth.buttrbase.com"

    def test_audience_accessor_none(self):
        with patch("buttrbase.verify.PyJWKClient"):
            v = Verifier(
                jwks_url="https://auth.example.com/.well-known/jwks.json",
                issuer="https://auth.buttrbase.com",
            )
        assert v.audience is None

    def test_audience_accessor_set(self):
        with patch("buttrbase.verify.PyJWKClient"):
            v = Verifier(
                jwks_url="https://auth.example.com/.well-known/jwks.json",
                issuer="https://auth.buttrbase.com",
                audience="my-app",
            )
        assert v.audience == "my-app"

    def test_verifier_exported_from_top_level(self):
        from buttrbase import Verifier as V, VerifierError as VE
        assert V is not None
        assert VE is not None


# ---------------------------------------------------------------------------
# Tests — end-to-end: real RSA sig (no mock) using PyJWK.from_dict directly
# ---------------------------------------------------------------------------


class TestVerifierEndToEnd:
    """Verify using PyJWK.from_dict directly (no PyJWKClient network call),
    proving the whole verify_token → Claims path works with real crypto."""

    def setup_method(self):
        self.private_key, self.public_key = _generate_rsa_keypair()
        self.pyjwk = _make_pyjwk(self.public_key)

    def test_full_e2e_enriched_claims(self):
        token = _sign_token(
            self.private_key,
            roles="owner",
            email="test@example.com",
            scope=["read:messages"],
        )

        mock_client = MagicMock()
        mock_client.get_signing_key_from_jwt.return_value = self.pyjwk

        with patch("buttrbase.verify.PyJWKClient", return_value=mock_client):
            verifier = Verifier(
                jwks_url="https://auth.example.com/.well-known/jwks.json",
                issuer="https://auth.buttrbase.com",
            )
            claims = verifier.verify_token(token)

        assert claims.data is not None
        assert claims.data.roles == "owner"
        assert claims.data.email == "test@example.com"

        # Convert to principal (mirrors Rust SDK's claims_expose_roles_and_email test)
        principal = TokenPrincipal.from_claims(claims)
        assert "owner" in principal.roles
        assert principal.email == "test@example.com"

    def test_full_e2e_verify_bearer_roles_and_email(self):
        token = _sign_token(
            self.private_key,
            roles="org_admin,leadership",
            email="admin@corp.com",
        )

        mock_client = MagicMock()
        mock_client.get_signing_key_from_jwt.return_value = self.pyjwk

        with patch("buttrbase.verify.PyJWKClient", return_value=mock_client):
            verifier = Verifier(
                jwks_url="https://auth.example.com/.well-known/jwks.json",
                issuer="https://auth.buttrbase.com",
            )
            principal = verifier.verify_bearer(f"Bearer {token}")

        assert "org_admin" in principal.roles
        assert "leadership" in principal.roles
        assert principal.email == "admin@corp.com"
