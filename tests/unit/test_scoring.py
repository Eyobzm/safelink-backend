from app.scoring import ScanInput, decide


def make(**kw):
    base = dict(local_flags=[], gsb="clean", vt_status="clean", vt_detections=0,
                phishtank="clean", urlscan="unknown", redirect_hops=0)
    base.update(kw)
    return ScanInput(**base)


def test_all_clean_is_safe():
    assert decide(make()).verdict == "SAFE"


def test_gsb_flag_is_dangerous():
    assert decide(make(gsb="flagged")).verdict == "DANGEROUS"


def test_verified_phishtank_is_dangerous():
    assert decide(make(phishtank="flagged")).verdict == "DANGEROUS"


def test_unverified_phishtank_is_suspicious():
    assert decide(make(phishtank="unverified")).verdict == "SUSPICIOUS"


def test_vt_1_or_2_suspicious_3_dangerous_with_other_flag():
    assert decide(make(vt_detections=2)).verdict == "SUSPICIOUS"
    d = decide(make(vt_detections=3, urlscan="flagged", phishtank="flagged"))
    assert d.verdict == "DANGEROUS"


def test_redirect_chain_suspicious():
    assert decide(make(redirect_hops=3)).verdict == "SUSPICIOUS"


def test_dangerous_beats_suspicious():
    d = decide(make(gsb="flagged", redirect_hops=5, phishtank="unverified"))
    assert d.verdict == "DANGEROUS"


def test_all_engines_timeout_is_never_safe():
    d = decide(make(gsb="timeout", vt_status="timeout", phishtank="timeout"))
    assert d.verdict == "SUSPICIOUS" and d.degraded and "SCAN_DEGRADED" in d.reasons


def test_one_engine_failure_alone_is_degraded_suspicious():
    d = decide(make(gsb="error"))
    assert d.verdict == "SUSPICIOUS"


def test_local_lookalike_flag():
    assert decide(make(local_flags=["DOM_LOOKALIKE"])).verdict == "SUSPICIOUS"
