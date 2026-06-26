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
]

# Delimiter pattern: one or more commas and/or spaces.
_ROLE_SPLIT = re.compile(r"[,\s]+")


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
