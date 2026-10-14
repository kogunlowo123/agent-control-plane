"""OIDC verification, JWKS caching, signing keys, content screening, key generation."""

from __future__ import annotations

import base64
import json
import time
from pathlib import Path

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_control_plane import keygen
from agent_control_plane.domain.errors import UnauthorizedError, UnsafeContentError
from agent_control_plane.security.content import TextScreen
from agent_control_plane.security.oidc import (
    OperatorAuthenticator,
    RemoteJwks,
    StaticJwks,
    bearer_token,
    verify_jwt,
)
from agent_control_plane.security.signing import SigningKey, sign_digest, verify_digest
from tests.conftest import OPERATOR_AUDIENCE, OPERATOR_ISSUER
from tests.fakes import FakeIdp


def authenticator(idp: FakeIdp, now: float | None = None) -> OperatorAuthenticator:
    return OperatorAuthenticator(
        StaticJwks(idp.jwks()),
        issuer=OPERATOR_ISSUER,
        audience=OPERATOR_AUDIENCE,
        clock=(lambda: now) if now is not None else time.time,
    )


async def test_valid_operator_token(operator_idp: FakeIdp) -> None:
    token = operator_idp.mint(sub="alice", aud=OPERATOR_AUDIENCE, roles=["acp-auditor", 7])
    principal = await authenticator(operator_idp).authenticate(f"Bearer {token}")
    assert principal.subject == "alice"
    assert principal.roles == frozenset({"acp-auditor"})
    no_roles = operator_idp.mint(sub="bob", aud=OPERATOR_AUDIENCE, roles="acp-auditor")
    assert (
        await authenticator(operator_idp).authenticate(f"Bearer {no_roles}")
    ).roles == frozenset()


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ({"aud": "someone-else"}, "InvalidAudience"),
        ({"iss": "https://evil.test"}, "InvalidIssuer"),
    ],
)
async def test_wrong_issuer_or_audience(
    operator_idp: FakeIdp, mutation: dict[str, str], message: str
) -> None:
    claims = {"sub": "alice", "aud": OPERATOR_AUDIENCE}
    claims.update(mutation)
    token = operator_idp.mint(**claims)  # type: ignore[arg-type]
    if "iss" in mutation:
        now = int(time.time())
        token = jwt.encode(
            {
                "iss": mutation["iss"],
                "sub": "a",
                "aud": OPERATOR_AUDIENCE,
                "iat": now,
                "exp": now + 60,
            },
            operator_idp.key,
            algorithm="ES256",
            headers={"kid": operator_idp.kid},
        )
    with pytest.raises(UnauthorizedError, match=message):
        await authenticator(operator_idp).authenticate(f"Bearer {token}")


async def test_time_claims_use_injected_clock(operator_idp: FakeIdp) -> None:
    token = operator_idp.mint(sub="alice", aud=OPERATOR_AUDIENCE, ttl=60)
    now = time.time()
    with pytest.raises(UnauthorizedError, match="expired"):
        await authenticator(operator_idp, now + 3600).authenticate(f"Bearer {token}")
    with pytest.raises(UnauthorizedError, match="future"):
        await authenticator(operator_idp, now - 3600).authenticate(f"Bearer {token}")
    early = operator_idp.mint(sub="alice", aud=OPERATOR_AUDIENCE, nbf=int(now) + 600)
    with pytest.raises(UnauthorizedError, match="not yet valid"):
        await authenticator(operator_idp).authenticate(f"Bearer {early}")


async def test_malformed_and_unsigned_tokens(operator_idp: FakeIdp) -> None:
    auth = authenticator(operator_idp)
    for header in [None, "Basic abc", "Bearer ", "Bearer not-a-jwt"]:
        with pytest.raises(UnauthorizedError):
            await auth.authenticate(header)
    body = base64.urlsafe_b64encode(json.dumps({"sub": "x"}).encode()).rstrip(b"=").decode()
    head = (
        base64.urlsafe_b64encode(json.dumps({"alg": "none", "kid": "operator-1"}).encode())
        .rstrip(b"=")
        .decode()
    )
    with pytest.raises(UnauthorizedError, match="algorithm"):
        await auth.authenticate(f"Bearer {head}.{body}.")
    hs = jwt.encode(
        {"sub": "x"},
        "shared-secret-value-long-enough-32b",
        algorithm="HS256",
        headers={"kid": "operator-1"},
    )
    with pytest.raises(UnauthorizedError, match="algorithm"):
        await auth.authenticate(f"Bearer {hs}")
    other = FakeIdp(OPERATOR_ISSUER, kid="operator-1")
    forged = other.mint(sub="mallory", aud=OPERATOR_AUDIENCE, roles=["acp-platform-admin"])
    with pytest.raises(UnauthorizedError, match="InvalidSignature"):
        await auth.authenticate(f"Bearer {forged}")
    unknown_kid = FakeIdp(OPERATOR_ISSUER, kid="rotated").mint(sub="a", aud=OPERATOR_AUDIENCE)
    with pytest.raises(UnauthorizedError, match="unknown signing key"):
        await auth.authenticate(f"Bearer {unknown_kid}")
    no_numbers = jwt.encode(
        {
            "iss": OPERATOR_ISSUER,
            "sub": "a",
            "aud": OPERATOR_AUDIENCE,
            "iat": "now",
            "exp": "later",
        },
        operator_idp.key,
        algorithm="ES256",
        headers={"kid": "operator-1"},
    )
    with pytest.raises(UnauthorizedError):
        await auth.authenticate(f"Bearer {no_numbers}")
    with pytest.raises(UnauthorizedError):
        bearer_token("Bearer    ")


async def test_remote_jwks_caches_refreshes_and_rate_limits(operator_idp: FakeIdp) -> None:
    fetched: list[int] = []

    def handler(_: httpx.Request) -> httpx.Response:
        fetched.append(1)
        return httpx.Response(200, json=operator_idp.jwks())

    now = [0.0]
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        jwks = RemoteJwks("https://idp.test/jwks", client=http, clock=lambda: now[0])
        await jwks.key_for("operator-1")
        await jwks.key_for("operator-1")
        assert len(fetched) == 1
        with pytest.raises(UnauthorizedError, match="unknown"):
            await jwks.key_for("random-kid")  # refresh is rate limited within 30 s
        assert len(fetched) == 1
        now[0] = 31.0
        with pytest.raises(UnauthorizedError):
            await jwks.key_for("random-kid")
        assert len(fetched) == 2
        now[0] = 400.0  # stale: refetched
        await jwks.key_for("operator-1")
        assert len(fetched) == 3


async def test_remote_jwks_outage_keeps_cached_keys(operator_idp: FakeIdp) -> None:
    state = {"up": True}

    def handler(request: httpx.Request) -> httpx.Response:
        if not state["up"]:
            raise httpx.ConnectError("down", request=request)
        return httpx.Response(200, json=operator_idp.jwks())

    now = [0.0]
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        jwks = RemoteJwks("https://idp.test/jwks", client=http, clock=lambda: now[0])
        await jwks.key_for("operator-1")
        state["up"] = False
        now[0] = 1000.0
        assert await jwks.key_for("operator-1") is not None  # stale keys still serve
        with pytest.raises(UnauthorizedError, match="cannot fetch"):
            await RemoteJwks("https://idp.test/jwks", client=http).key_for("operator-1")


async def test_verify_jwt_requires_claims(operator_idp: FakeIdp) -> None:
    token = jwt.encode(
        {"sub": "a"}, operator_idp.key, algorithm="ES256", headers={"kid": "operator-1"}
    )
    with pytest.raises(UnauthorizedError, match="MissingRequiredClaim"):
        await verify_jwt(
            token, StaticJwks(operator_idp.jwks()), issuer="i", audience="a", now=time.time()
        )


def test_signing_keys(tmp_path: Path) -> None:
    key = SigningKey.ephemeral("bundle")
    signature = sign_digest(key, "sha256:abc")
    assert verify_digest(key.public, "sha256:abc", signature)
    assert not verify_digest(key.public, "sha256:abd", signature)
    assert not verify_digest(key.public, "sha256:abc", "!!not-base64!!")
    pem = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    path = tmp_path / "bundle-2026-10.pem"
    path.write_bytes(pem)
    loaded = SigningKey.from_file(path)
    assert loaded.key_id == "bundle-2026-10"
    from cryptography.hazmat.primitives.asymmetric import ec

    wrong = tmp_path / "ec.pem"
    wrong.write_bytes(
        ec.generate_private_key(ec.SECP256R1()).private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    with pytest.raises(ValueError, match="Ed25519"):
        SigningKey.from_file(wrong)


def test_keygen(capsys: pytest.CaptureFixture[str]) -> None:
    assert keygen.main(["audit-2026-10"]) == 0
    out, err = capsys.readouterr()
    assert out.startswith("-----BEGIN PRIVATE KEY-----")
    assert json.loads(err)["kid"] == "audit-2026-10"
    assert keygen.main(["Bad Id"]) == 2
    assert keygen.main([]) == 2


def test_text_screen() -> None:
    screen = TextScreen()
    assert screen.free_text("reason", "routine rotation") == "routine rotation"
    with pytest.raises(UnsafeContentError):
        screen.free_text("reason", "token ghp_" + "a" * 36)
    redacted = screen.free_text("reason", "call 555-867-5309 or mail bob@example.org")
    assert "bob@example.org" not in redacted
    screen.config_values({"REGION": "us-east-1"})
    with pytest.raises(UnsafeContentError, match="secret store"):
        screen.config_values({"KEY": "AKIAIOSFODNN7EXAMPLE"})
