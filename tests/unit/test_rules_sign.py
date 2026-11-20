import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.services.rules_service import sign_package


def test_signed_package_verifies():
    key = Ed25519PrivateKey.generate()
    secret = base64.b64encode(key.private_bytes_raw()).decode()
    payload = b"rule-package"
    signature = sign_package(payload, secret)
    key.public_key().verify(signature, payload)
