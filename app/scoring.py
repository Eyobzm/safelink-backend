"""Pure verdict logic (SRS section 8). No I/O so it is trivial to unit test."""
from dataclasses import dataclass, field


@dataclass
class ScanInput:
    local_flags: list[str]
    gsb: str
    vt_status: str
    vt_detections: int
    phishtank: str  # "flagged" = verified, "unverified" = unverified match
    urlscan: str
    redirect_hops: int


@dataclass
class Decision:
    verdict: str
    reasons: list[str] = field(default_factory=list)
    degraded: bool = False
    score: int = 0


def decide(s: ScanInput) -> Decision:
    reasons: list[str] = []

    if s.gsb == "flagged":
        reasons.append("TI_GSB")
    if s.phishtank == "flagged":
        reasons.append("TI_PT_VERIFIED")
    if s.vt_detections >= 3:
        reasons.append("TI_VT")

    engine_flags = sum(
        [s.gsb == "flagged", s.phishtank == "flagged", s.urlscan == "flagged", s.vt_detections >= 3]
    )
    # DANGEROUS always wins (FR-VER-05). TEAM DECISION: verified PhishTank alone = DANGEROUS.
    if s.gsb == "flagged" or s.phishtank == "flagged" or engine_flags >= 3:
        return Decision("DANGEROUS", reasons, degraded=False, score=100)

    answered = sum(x in ("clean", "flagged", "unverified") for x in (s.gsb, s.vt_status, s.phishtank))
    degraded = s.gsb in ("timeout", "error") or answered < 2

    if 1 <= s.vt_detections < 3:
        reasons.append("TI_VT")
    if s.phishtank == "unverified":
        reasons.append("TI_PT_UNVERIFIED")
    if s.redirect_hops >= 3:
        reasons.append("NET_REDIRECT_CHAIN")
    for code in ("DOM_LOOKALIKE", "DOM_LOW_TRUST_TLD", "NET_NO_TLS"):
        if code in s.local_flags:
            reasons.append(code)
    if degraded:
        reasons.append("SCAN_DEGRADED")

    if reasons:
        return Decision("SUSPICIOUS", reasons, degraded, score=min(40 + 10 * len(reasons), 90))
    return Decision("SAFE", [], False, 0)


MESSAGE_KEYS = {
    "TI_GSB": "msg_dangerous_hijack",
    "TI_PT_VERIFIED": "msg_dangerous_hijack",
    "TI_VT": "msg_suspicious_lookalike",
    "NET_REDIRECT_CHAIN": "msg_suspicious_redirect",
    "DOM_LOOKALIKE": "msg_suspicious_lookalike",
    "TI_PT_UNVERIFIED": "msg_suspicious_lookalike",
}


def message_key(decision: Decision) -> str:
    if decision.verdict == "SAFE":
        return "msg_safe"
    for r in decision.reasons:
        if r in MESSAGE_KEYS:
            return MESSAGE_KEYS[r]
    return "msg_suspicious_generic"
