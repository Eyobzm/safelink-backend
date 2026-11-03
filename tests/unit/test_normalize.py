from app.normalize import normalize_url, outbound_url, redact


def test_decodes_and_lowercases_host():
    assert normalize_url("HTTPS://Example.COM/%64elete-video") == "https://example.com/delete-video"


def test_double_encoding_decoded():
    assert "delete-video" in normalize_url("https://a.com/%2564elete-video")


def test_outbound_strips_query_and_fragment():
    assert outbound_url("https://a.com/login?token=SECRET#x") == "https://a.com/login"


def test_redact_has_no_query():
    assert "SECRET" not in redact("https://a.com/p?token=SECRET")
