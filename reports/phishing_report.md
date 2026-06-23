# Phishing Email Analysis Report

**Dataset:** `sample_emails_dataset.csv`  
**Generated:** 2026-06-22 11:16 UTC  
**Total emails analyzed:** 10

---

## 1. Executive Summary

- **Average risk score:** 36.5 / 100
- **Risk tier breakdown:**
  - CRITICAL: 0 (0.0%)
  - HIGH: 5 (50.0%)
  - MEDIUM: 1 (10.0%)
  - LOW: 0 (0.0%)
  - MINIMAL: 4 (40.0%)

- **Validation against ground-truth labels:** 9/10 correctly classified (90.0%) — using HIGH/CRITICAL tier as the 'predicted phishing' threshold.

## 2. Most Common Phishing Indicators

| Indicator | Occurrences |
|---|---|
| `lookalike_domain` | 3 |
| `suspicious_tld` | 3 |
| `lookalike_link_domain` | 3 |
| `suspicious_link_tld` | 3 |
| `urgency_language` | 3 |
| `generic_greeting` | 3 |
| `credential_harvesting_language` | 2 |
| `vague_cta_link_text` | 2 |
| `url_shortener` | 1 |
| `sender_link_domain_mismatch` | 1 |

## 3. Indicators by Category

| Category | Total Flags |
|---|---|
| body | 13 |
| url | 8 |
| sender | 6 |

## 4. High-Risk Emails (HIGH / CRITICAL tier)

### sample_emails_dataset.csv — Score: 72 (HIGH)
- **Subject:** Your Microsoft 365 subscription is expiring
- **From:** billing@microsoft-renew.top
- **Indicators flagged:** 6
  - **[sender] lookalike_domain** (+25): Sending domain 'microsoft-renew.top' closely resembles brand 'microsoft' (possible typosquatting / homoglyph domain).
  - **[sender] suspicious_tld** (+12): Sender domain uses an uncommon/high-abuse TLD ('.top').
  - **[url] lookalike_link_domain** (+25): Link domain resembles brand 'microsoft' but isn't the real domain (typosquat pattern).
  - **[url] suspicious_link_tld** (+12): 1 link(s) use high-risk/uncommon TLDs often abused for phishing.
  - **[body] urgency_language** (+12): Uses urgency/pressure language commonly seen in phishing (e.g. "update your payment").
  - **[body] generic_greeting** (+8): Uses a generic, non-personalized greeting ("dear user") instead of the recipient's name.

### sample_emails_dataset.csv — Score: 67 (HIGH)
- **Subject:** Verify your account now or it will be suspended
- **From:** support@secure-bank-alert.com
- **Indicators flagged:** 6
  - **[url] url_shortener** (+15): Email contains 1 shortened URL(s) which obscure the real destination.
  - **[url] sender_link_domain_mismatch** (+10): None of the links in the email point back to the sender's own domain.
  - **[body] urgency_language** (+20): Uses urgency/pressure language commonly seen in phishing (e.g. "verify your account").
  - **[body] credential_harvesting_language** (+25): Requests sensitive credentials or financial information (e.g. "enter your password").
  - **[body] generic_greeting** (+8): Uses a generic, non-personalized greeting ("dear customer") instead of the recipient's name.
  - **[body] vague_cta_link_text** (+8): Uses vague call-to-action link text ('Click here' / 'Verify now') instead of showing the real destination.

### sample_emails_dataset.csv — Score: 66 (HIGH)
- **Subject:** Confirm your Apple ID for security purposes
- **From:** appleid@apple-secure-id.info
- **Indicators flagged:** 5
  - **[sender] lookalike_domain** (+25): Sending domain 'apple-secure-id.info' closely resembles brand 'apple' (possible typosquatting / homoglyph domain).
  - **[sender] suspicious_tld** (+12): Sender domain uses an uncommon/high-abuse TLD ('.info').
  - **[url] lookalike_link_domain** (+25): Link domain resembles brand 'apple' but isn't the real domain (typosquat pattern).
  - **[url] suspicious_link_tld** (+12): 1 link(s) use high-risk/uncommon TLDs often abused for phishing.
  - **[body] generic_greeting** (+8): Uses a generic, non-personalized greeting ("dear customer") instead of the recipient's name.

### sample_emails_dataset.csv — Score: 66 (HIGH)
- **Subject:** Your package delivery failed
- **From:** delivery@dhl-tracking-update.click
- **Indicators flagged:** 5
  - **[sender] lookalike_domain** (+25): Sending domain 'dhl-tracking-update.click' closely resembles brand 'dhl' (possible typosquatting / homoglyph domain).
  - **[sender] suspicious_tld** (+12): Sender domain uses an uncommon/high-abuse TLD ('.click').
  - **[url] lookalike_link_domain** (+25): Link domain resembles brand 'dhl' but isn't the real domain (typosquat pattern).
  - **[url] suspicious_link_tld** (+12): 1 link(s) use high-risk/uncommon TLDs often abused for phishing.
  - **[body] vague_cta_link_text** (+8): Uses vague call-to-action link text ('Click here' / 'Verify now') instead of showing the real destination.

### sample_emails_dataset.csv — Score: 59 (HIGH)
- **Subject:** URGENT: Wire transfer required today
- **From:** ceo.office@companymail-secure.net
- **Indicators flagged:** 3
  - **[body] urgency_language** (+16): Uses urgency/pressure language commonly seen in phishing (e.g. "time sensitive").
  - **[body] credential_harvesting_language** (+20): Requests sensitive credentials or financial information (e.g. "wire transfer").
  - **[body] bec_style_request** (+30): Language pattern consistent with Business Email Compromise (BEC) / CEO-fraud requests (e.g. "wire transfer", "urgent wire") — urgent, confidential financial requests with no links or attachments, relying purely on social engineering.

## 5. Methodology

Each email is scored using independent heuristic checks across four areas: **header authentication** (SPF/DKIM/DMARC, Reply-To/Return-Path mismatches), **sender/domain analysis** (brand impersonation, typosquatting, free-mail abuse), **URL/link inspection** (shorteners, IP-literal links, anchor-text spoofing, lookalike domains), and **body content analysis** (urgency language, credential requests, generic greetings, financial bait). Attachment names are also checked for executable or macro-bearing file types.

Indicator weights are summed with diminishing returns per additional indicator, capped at 100, and mapped to a risk tier: CRITICAL (≥75), HIGH (≥50), MEDIUM (≥25), LOW (≥10), MINIMAL (<10).

**Note:** This is a heuristic triage tool for research, awareness, and SOC-analyst support — it does not replace email security gateways, sandboxing, or human judgment.