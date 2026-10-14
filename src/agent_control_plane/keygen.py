"""Generate an Ed25519 signing key for the audit chain or policy bundles.

    python -m agent_control_plane.keygen <key-id> > <key-id>.pem 2> <key-id>.jwk.json

The private key (PEM) goes to stdout so it can be piped straight into the
cloud secret manager; the public JWK goes to stderr for distribution. The
key id becomes the file stem the service reads it from.
"""

from __future__ import annotations

import json
import re
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_control_plane.security.signing import SigningKey

KEY_ID = re.compile(r"^[a-z0-9][a-z0-9.\-]{0,62}$")


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1 or not KEY_ID.fullmatch(args[0]):
        sys.stderr.write("usage: python -m agent_control_plane.keygen <key-id>\n")
        return 2
    private = Ed25519PrivateKey.generate()
    pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    sys.stdout.write(pem.decode())
    sys.stderr.write(json.dumps(SigningKey(private, args[0]).jwk()) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
