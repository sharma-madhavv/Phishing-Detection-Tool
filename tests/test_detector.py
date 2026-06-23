"""
test_detector.py
------------------
Basic unit tests for the phishing detection pipeline.
Run with: pytest tests/ -v
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from detector.email_parser import parse_eml_file, parse_csv_row, extract_urls, parse_from_address
from detector.risk_scorer import analyze_email, compute_risk_score, score_to_tier
from detector.indicators import run_all_checks

SAMPLE_DIR = Path(__file__).parent.parent / "data" / "sample_emails"


def test_extract_urls_basic():
    text = "Visit http://example.com/page and https://test.org/foo?bar=1 today."
    urls = extract_urls(text)
    assert "http://example.com/page" in urls
    assert "https://test.org/foo?bar=1" in urls


def test_parse_from_address():
    name, addr = parse_from_address('"PayPal Security" <security@paypa1-verify.com>')
    assert name == "PayPal Security"
    assert addr == "security@paypa1-verify.com"


def test_phishing_paypal_sample_flagged_high_risk():
    result = analyze_email(parse_eml_file(SAMPLE_DIR / "phishing_paypal_spoof.eml"))
    assert result["risk_tier"] in ("HIGH", "CRITICAL")
    assert result["risk_score"] >= 50
    names = [i["name"] for i in result["indicators"]]
    assert "spf_fail" in names
    assert any(n in names for n in ("lookalike_domain", "display_name_spoof"))


def test_phishing_it_helpdesk_flags_urgency_and_shortener():
    result = analyze_email(parse_eml_file(SAMPLE_DIR / "phishing_it_helpdesk.eml"))
    names = [i["name"] for i in result["indicators"]]
    assert "url_shortener" in names
    assert "urgency_language" in names
    assert result["risk_score"] > 0


def test_phishing_invoice_flags_executable_and_mismatch():
    result = analyze_email(parse_eml_file(SAMPLE_DIR / "phishing_amazon_invoice.eml"))
    names = [i["name"] for i in result["indicators"]]
    assert "double_extension" in names or "executable_attachment" in names
    assert result["risk_tier"] in ("MEDIUM", "HIGH", "CRITICAL")


def test_legit_email_low_risk():
    result = analyze_email(parse_eml_file(SAMPLE_DIR / "legit_team_sync.eml"))
    assert result["risk_tier"] in ("MINIMAL", "LOW")
    assert result["risk_score"] < 25


def test_legit_github_notification_low_risk():
    result = analyze_email(parse_eml_file(SAMPLE_DIR / "legit_github_notification.eml"))
    assert result["risk_tier"] in ("MINIMAL", "LOW")


def test_csv_row_parsing_phishing_label():
    row = {
        "subject": "Verify your account",
        "sender": "support@fake-bank.com",
        "body": "Click here to verify your account immediately or it will be suspended.",
        "label": "phishing",
    }
    parsed = parse_csv_row(row, row_index=0, source_file="test.csv")
    assert parsed["label"] == "phishing"
    assert parsed["from_addr"] == "support@fake-bank.com"
    result = analyze_email(parsed)
    assert result["risk_score"] > 0


def test_csv_row_parsing_legit_label():
    row = {
        "subject": "Team meeting notes",
        "sender": "colleague@company.com",
        "body": "Here are the notes from today's meeting.",
        "label": "legitimate",
    }
    parsed = parse_csv_row(row, row_index=1, source_file="test.csv")
    assert parsed["label"] == "legitimate"
    result = analyze_email(parsed)
    assert result["risk_tier"] in ("MINIMAL", "LOW")


def test_score_to_tier_boundaries():
    assert score_to_tier(0) == "MINIMAL"
    assert score_to_tier(9) == "MINIMAL"
    assert score_to_tier(10) == "LOW"
    assert score_to_tier(25) == "MEDIUM"
    assert score_to_tier(50) == "HIGH"
    assert score_to_tier(75) == "CRITICAL"
    assert score_to_tier(100) == "CRITICAL"


def test_compute_risk_score_empty():
    assert compute_risk_score([]) == 0


def test_compute_risk_score_caps_at_100():
    from detector.indicators import Indicator
    huge_list = [Indicator("body", "test", "test", 50) for _ in range(10)]
    score = compute_risk_score(huge_list)
    assert score <= 100


def test_run_all_checks_handles_minimal_email():
    """Ensure the pipeline doesn't crash on a sparse/minimal email dict."""
    minimal_email = {
        "subject": "",
        "from_raw": "",
        "from_addr": "",
        "from_name": "",
        "reply_to": "",
        "return_path": "",
        "headers": {},
        "body_text": "",
        "body_html": "",
        "urls": [],
        "attachments": [],
        "received_chain": [],
    }
    indicators = run_all_checks(minimal_email)
    assert isinstance(indicators, list)


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
