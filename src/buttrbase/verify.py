"""Token claims enrichment — data-envelope extraction for buttrbase JWTs.

Strictly additive: existing SDK behaviour is unchanged.  This module
surfaces the ``roles`` and ``email`` fields that buttrbase embeds in the
``data`` object of every access token so downstream applications can
make role / identity decisions without a second HTTP round-trip.

Usage (offline, from a decoded payload dict)::

    from buttrbase.verify import Claims, TokenPrincipal, principal_from_payload

    # payload is the decoded JWT body (dict from json.loads / PyJWT.decode etc.)
    claims = Claims.from_dict(payload)
    principal = TokenPrincipal.from_claims(claims)
    # or in one step:
    principal = principal_from_payload(payload)

    print(principal.roles)   # e.g. ["owner", "org_admin"]
    print(principal.email)   # e.g. "test@example.com"

Usage (signature-verified, from a JWKS-backed live token)::

    from buttrbase.verify import Verifier

    verifier = Verifier(
        jwks_url="https://auth.buttrbase.com/.well-known/jwks.json",
        issuer="https://auth.buttrbase.com",
        # audience is optional — omit to skip aud validation (most consumers)
    )

    # Verify a bare token string → enriched Claims
    claims = verifier.verify_token("eyJ...")
    print(claims.data.roles)  # e.g. "owner"

    # Verify a Bearer authorization header → TokenPrincipal (auth-context)
    principal = verifier.verify_bearer("Bearer eyJ...")
    print(principal.roles)    # e.g. ["owner"]
    print(principal.email)    # e.g. "test@example.com"
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

__all__ = [
    "ClaimsData",
    "Claims",
    "TokenPrincipal",
    "principal_from_payload",
    "Verifier",
    "VerifierError",
]

# Delimiter pattern: one or more commas and/or spaces.
_ROLE_SPLIT = re.compile(r"[,\s]+")

# ---------------------------------------------------------------------------
# Optional PyJWT[crypto] import — module-level so it is patchable in tests.
# The Verifier class raises a helpful ImportError at construction time when
# PyJWT is absent, rather than at import time, preserving the no-crypto path.
# ---------------------------------------------------------------------------
try:
    import jwt as _jwt_module
    from jwt import PyJWKClient
    _JWT_AVAILABLE = True
except ImportError:  # pragma: no cover
    _jwt_module = None  # type: ignore[assignment]
    PyJWKClient = None  # type: ignore[assignment,misc]
    _JWT_AVAILABLE = False


@dataclass
class ClaimsData:
    """Identity enrichment carried inside the buttrbase ``data`` claim envelope.

    All fields are optional — tokens without ``data``, or ``data`` objects
    that omit individual fields, deserialise cleanly (the missing fields
    become ``None``).
    """

    roles: Optional[str] = None
    """Comma- and/or space-delimited role string, e.g. ``"owner"`` or
    ``"org_admin,leadership"``."""

    email: Optional[str] = None
    org_uuid: Optional[str] = None
    user_uuid: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ClaimsData":
        """Build a :class:`ClaimsData` from the raw ``data`` sub-object."""
        return cls(
            roles=data.get("roles"),
            email=data.get("email"),
            org_uuid=data.get("org_uuid"),
            user_uuid=data.get("user_uuid"),
        )


@dataclass
class Claims:
    """Typed view of a decoded buttrbase JWT payload.

    Additive: any claim fields not listed here are simply ignored rather
    than raising an error — forward-compatibility is preserved.
    """

    sub: str
    org: str
    exp: int
    iat: int
    scope: List[str] = field(default_factory=list)
    data: Optional[ClaimsData] = None

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "Claims":
        """Parse a decoded JWT payload (plain ``dict``) into :class:`Claims`.

        ``payload`` is the *decoded* body — i.e. a ``dict`` that came from
        ``json.loads(base64url_decode(jwt.split('.')[1]))`` or equivalent.
        No signature verification is performed here; integrate PyJWT or
        python-jose for that.
        """
        raw_data = payload.get("data")
        claims_data: Optional[ClaimsData] = None
        if isinstance(raw_data, dict):
            claims_data = ClaimsData.from_dict(raw_data)

        return cls(
            sub=str(payload.get("sub", "")),
            org=str(payload.get("org", "")),
            exp=int(payload.get("exp", 0)),
            iat=int(payload.get("iat", 0)),
            scope=list(payload.get("scope", [])),
            data=claims_data,
        )


@dataclass
class TokenPrincipal:
    """Application-level principal derived from a decoded buttrbase token.

    This is the Python equivalent of the Rust SDK's ``AuthContext``:
    stripped of JWT-internal bookkeeping, exposing only what handlers
    typically need.

    ``roles`` is derived by splitting ``data.roles`` on any combination of
    commas and spaces and filtering empty parts — matching the Rust SDK's
    ``split([',', ' ']).filter(|p| !p.is_empty())`` behaviour.
    """

    user_id: str
    org_id: str
    scopes: List[str]
    roles: List[str]
    email: Optional[str]

    @classmethod
    def from_claims(cls, claims: Claims) -> "TokenPrincipal":
        """Convert :class:`Claims` into a :class:`TokenPrincipal`."""
        roles: List[str] = []
        email: Optional[str] = None

        if claims.data is not None:
            if claims.data.roles:
                roles = [
                    p for p in _ROLE_SPLIT.split(claims.data.roles) if p
                ]
            email = claims.data.email

        return cls(
            user_id=claims.sub,
            org_id=claims.org,
            scopes=claims.scope,
            roles=roles,
            email=email,
        )


def principal_from_payload(payload: Dict[str, Any]) -> "TokenPrincipal":
    """One-shot helper: parse a decoded JWT payload into a :class:`TokenPrincipal`.

    Equivalent to ``TokenPrincipal.from_claims(Claims.from_dict(payload))``.

    Args:
        payload: Decoded JWT body as a plain ``dict`` (the middle segment of
                 the JWT, base64url-decoded and JSON-parsed).

    Returns:
        A :class:`TokenPrincipal` with ``roles`` (``list[str]``) and
        ``email`` (``str | None``) populated from the ``data`` envelope.
    """
    return TokenPrincipal.from_claims(Claims.from_dict(payload))


# ---------------------------------------------------------------------------
# JWKS-backed signature verifier
# ---------------------------------------------------------------------------


class VerifierError(Exception):
    """Raised when token verification fails.

    The ``message`` attribute carries a human-readable reason; it is safe
    to log but should **not** be forwarded verbatim to end-users in
    production because it may contain token fragments.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class Verifier:
    """RS256 JWKS-backed token verifier — Python mirror of the Rust SDK's
    ``Verifier`` type.

    Construct once at application startup and share the instance across
    handlers; :class:`jwt.PyJWKClient` manages its own JWKS cache internally.

    Args:
        jwks_url: Public JWKS discovery URL, e.g.
            ``"https://auth.buttrbase.com/.well-known/jwks.json"``.
        issuer: Expected ``iss`` claim, e.g. ``"https://auth.buttrbase.com"``.
        audience: Expected ``aud`` claim.  Pass ``None`` (the default) to skip
            audience validation — buttrbase access tokens do not carry a
            stable, per-application ``aud`` claim in most flows.
    """

    def __init__(
        self,
        jwks_url: str,
        issuer: str,
        audience: Optional[str] = None,
    ) -> None:
        if not _JWT_AVAILABLE or PyJWKClient is None:  # pragma: no cover
            raise ImportError(
                "buttrbase Verifier requires PyJWT[crypto]. "
                "Install it with: pip install 'PyJWT[crypto]'"
            )

        self._jwt = _jwt_module
        # PyJWKClient is module-level so tests can patch buttrbase.verify.PyJWKClient
        self._jwks_client: Any = PyJWKClient(jwks_url, cache_keys=True)
        self._issuer = issuer
        self._audience = audience

    @property
    def issuer(self) -> str:
        """The configured issuer string."""
        return self._issuer

    @property
    def audience(self) -> Optional[str]:
        """The configured audience, or ``None`` if audience validation is
        disabled."""
        return self._audience

    def verify_token(self, token: str) -> Claims:
        """Verify *token* and return the enriched :class:`Claims`.

        Signature validation uses the JWKS endpoint supplied at construction.
        The JWKS is fetched lazily and cached by :class:`~jwt.PyJWKClient`.
        A cache-miss triggers one automatic refresh.

        Args:
            token: A bare JWT string (without the ``Bearer `` prefix).

        Returns:
            :class:`Claims` — the full typed payload, including the ``data``
            envelope when present.

        Raises:
            VerifierError: If the token is malformed, the signature is invalid,
                the issuer does not match, the token is expired, or the ``kid``
                is not found in the JWKS.
        """
        try:
            signing_key = self._jwks_client.get_signing_key_from_jwt(token)
        except Exception as exc:
            raise VerifierError(f"JWKS key lookup failed: {exc}") from exc

        decode_options: Dict[str, Any] = {}
        if self._audience is None:
            decode_options["verify_aud"] = False

        try:
            payload: Dict[str, Any] = self._jwt.decode(
                token,
                signing_key,
                algorithms=["RS256"],
                issuer=self._issuer,
                audience=self._audience,
                options=decode_options,
            )
        except self._jwt.ExpiredSignatureError as exc:
            raise VerifierError(f"Token has expired: {exc}") from exc
        except self._jwt.InvalidIssuerError as exc:
            raise VerifierError(f"Invalid issuer: {exc}") from exc
        except self._jwt.InvalidAudienceError as exc:
            raise VerifierError(f"Invalid audience: {exc}") from exc
        except self._jwt.PyJWTError as exc:
            raise VerifierError(f"Token verification failed: {exc}") from exc

        return Claims.from_dict(payload)

    def verify_bearer(self, authorization: str) -> TokenPrincipal:
        """Strip a ``Bearer <token>`` header value, verify the token, and
        return the application-level :class:`TokenPrincipal`.

        Args:
            authorization: The raw ``Authorization`` header value, e.g.
                ``"Bearer eyJ..."``.

        Returns:
            :class:`TokenPrincipal` with ``roles``, ``email``, ``scopes``,
            ``user_id``, and ``org_id`` populated.

        Raises:
            VerifierError: If the header is not a ``Bearer`` token, or if
                verification of the token fails.
        """
        if not authorization or not authorization.startswith("Bearer "):
            raise VerifierError(
                "Authorization header is missing or is not a Bearer token"
            )
        token = authorization[len("Bearer "):]
        claims = self.verify_token(token)
        return TokenPrincipal.from_claims(claims)
