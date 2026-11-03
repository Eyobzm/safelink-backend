"""Admin script: publish a signed rule package.
Usage: python tools_sign_rules.py rules.json <version>
Generate a key once: python -c "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as K;
import base64;from cryptography.hazmat.primitives import serialization as s;
k=K.generate();print(base64.b64encode(k.private_bytes(s.Encoding.Raw,s.PrivateFormat.Raw,s.NoEncryption())).decode())"
Embed the PUBLIC key in the Android app (SignatureVerifier)."""
import asyncio
import base64
import gzip
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.config import settings
from app.db.models import RuleVersion
from app.db.session import SessionLocal, init_db


async def main(path: str, version: int) -> None:
    key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(settings.rules_signing_key_b64))
    package = gzip.compress(open(path, "rb").read())
    await init_db()
    async with SessionLocal() as s:
        s.add(RuleVersion(version=version, package=package, signature=key.sign(package)))
        await s.commit()


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1], int(sys.argv[2])))
