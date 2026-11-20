import base64
import gzip
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select

from ..config import settings
from ..db.models import RuleVersion
from ..db.session import SessionLocal

# Same patterns the Android client ships as defaults (FR-IMP-02/03).
DEFAULT_PACKAGE = {
    "rules": [
        {
            "id": 1,
            "type": "DELETE_PATH",
            "regex": r"/(delete-video|remove-content|delete-account|confirm-termination|wipe)(\b|/|\?|$)",
            "reason_code": "IMP_DELETE_PATH",
            "enabled": True,
        },
        {
            "id": 2,
            "type": "DEVICE_LINK",
            "regex": r"(tg://(login|auth)|whatsapp://proxy)",
            "reason_code": "IMP_DEVICE_LINK",
            "enabled": True,
        },
        {
            "id": 3,
            "type": "OAUTH",
            "regex": r"[?&]redirect_uri=https?://",
            "reason_code": "IMP_OAUTH_REDIRECT",
            "enabled": True,
        },
    ]
}


def sign_package(package: bytes, private_key_b64: str) -> bytes:
    raw = base64.b64decode(private_key_b64)
    key = Ed25519PrivateKey.from_private_bytes(raw[:32])
    return key.sign(package)


async def ensure_seed() -> None:
    """Publish version 1 when a signing key is configured and the table is empty."""
    if not settings.rules_signing_key_b64:
        return
    async with SessionLocal() as s:
        existing = (await s.execute(select(RuleVersion.version).limit(1))).first()
        if existing:
            return
        package = gzip.compress(json.dumps(DEFAULT_PACKAGE).encode())
        signature = sign_package(package, settings.rules_signing_key_b64)
        s.add(RuleVersion(version=1, package=package, signature=signature))
        await s.commit()


async def get_delta(since: int) -> dict:
    """Return the latest signed package if newer than the client's version.
    Pilot simplification: one full package per version."""
    async with SessionLocal() as s:
        row = (
            await s.execute(select(RuleVersion).order_by(RuleVersion.version.desc()).limit(1))
        ).scalar_one_or_none()
    if row is None or row.version <= since:
        return {"version": since, "package": None, "signature": None}
    return {
        "version": row.version,
        "package": base64.b64encode(row.package).decode(),
        "signature": base64.b64encode(row.signature).decode(),
    }
