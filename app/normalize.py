import hashlib
from urllib.parse import unquote, urlsplit, urlunsplit


def normalize_url(url: str) -> str:
    """Decode (up to 3 layers), lowercase scheme/host, drop fragment."""
    for _ in range(3):
        decoded = unquote(url)
        if decoded == url:
            break
        url = decoded
    parts = urlsplit(url.strip())
    host = (parts.hostname or "").lower()
    netloc = host + (f":{parts.port}" if parts.port else "")
    return urlunsplit((parts.scheme.lower(), netloc, parts.path, parts.query, ""))


def outbound_url(url: str) -> str:
    """URL sent to third parties: query string and fragment removed (privacy)."""
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, p.path, "", ""))


def url_hash(url: str) -> str:
    return hashlib.sha256(url.encode()).hexdigest()


def redact(url: str) -> str:
    """Host + path only, for logs and the reports table (NFR-PRIV-02)."""
    return outbound_url(url)
