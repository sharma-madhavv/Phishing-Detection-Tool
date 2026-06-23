"""
risk_scorer.py
---------------
Converts a list of Indicator objects into a single 0-100 risk score and
a categorical risk tier, then packages everything into a final per-email
analysis report.
"""

from dataclasses import asdict
from .indicators import run_all_checks

RISK_TIERS = [
    (75, "CRITICAL"),
    (50, "HIGH"),
    (25, "MEDIUM"),
    (10, "LOW"),
    (0, "MINIMAL"),
]


def score_to_tier(score):
    for threshold, tier in RISK_TIERS:
        if score >= threshold:
            return tier
    return "MINIMAL"


def compute_risk_score(indicators):
    """
    Sum indicator weights with mild diminishing returns so that one email
    triggering 10 small things doesn't auto-max at 100, while a couple of
    severe indicators still pushes the score high quickly.
    """
    if not indicators:
        return 0

    weights = sorted([i.weight for i in indicators], reverse=True)
    score = 0.0
    decay = 1.0
    for w in weights:
        score += w * decay
        decay *= 0.85  # each subsequent indicator contributes a bit less

    return min(100, round(score))


def analyze_email(email_data):
    """
    Full pipeline for one normalized email dict:
    run checks -> score -> classify -> return structured result.
    """
    indicators = run_all_checks(email_data)
    score = compute_risk_score(indicators)
    tier = score_to_tier(score)

    by_category = {}
    for ind in indicators:
        by_category.setdefault(ind.category, []).append(asdict(ind))

    return {
        "source_file": email_data.get("source_file", "unknown"),
        "message_id": email_data.get("message_id", ""),
        "subject": email_data.get("subject", ""),
        "from": email_data.get("from_raw", ""),
        "from_domain": _safe_domain(email_data.get("from_addr", "")),
        "to": email_data.get("to", ""),
        "date": email_data.get("date", ""),
        "ground_truth_label": email_data.get("label"),
        "risk_score": score,
        "risk_tier": tier,
        "indicator_count": len(indicators),
        "indicators": [asdict(i) for i in indicators],
        "indicators_by_category": by_category,
        "url_count": len(email_data.get("urls", []) or []),
        "attachment_count": len(email_data.get("attachments", []) or []),
        "urls": email_data.get("urls", []),
        "attachments": email_data.get("attachments", []),
    }


def _safe_domain(addr):
    if not addr or "@" not in addr:
        return ""
    return addr.split("@")[-1].lower()


def analyze_batch(email_list):
    """Run analyze_email over a list of normalized email dicts."""
    return [analyze_email(e) for e in email_list]
