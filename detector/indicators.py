"""
indicators.py
-------------
Heuristic phishing indicator checks. Each function inspects one aspect of
a normalized email dict (see email_parser.py) and returns a list of
Indicator objects. Every indicator carries a category, a severity weight,
and a human-readable explanation, which together feed the risk scorer.

These are detection heuristics for analysis/education/triage, not a
guarantee of malicious intent. Always treat a HIGH score as "needs human
review", not "confirmed malicious".
"""

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse


URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "shorte.st", "rebrand.ly", "cutt.ly", "tiny.cc", "lnkd.in",
    "shorturl.at", "rb.gy", "shrtco.de",
}

SUSPICIOUS_TLDS = {
    ".zip", ".xyz", ".top", ".click", ".link", ".work", ".live", ".icu",
    ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".rest", ".info",
}

FREE_MAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com",
    "mail.com", "protonmail.com", "icloud.com", "yandex.com", "gmx.com",
}

BRAND_KEYWORDS = [
    "paypal", "amazon", "apple", "microsoft", "google", "netflix", "bankofamerica",
    "wellsfargo", "chase", "irs", "dhl", "fedex", "ups", "facebook", "instagram",
    "linkedin", "office365", "outlook", "americanexpress", "visa", "mastercard",
]

URGENCY_PHRASES = [
    "act now", "act immediately", "urgent action", "verify your account",
    "account suspended", "account has been locked", "confirm your identity",
    "unusual activity", "unauthorized access", "limited time", "expires today",
    "expires in 24 hours", "immediate attention", "final notice", "last warning",
    "click here immediately", "your account will be closed", "payment failed",
    "update your payment", "suspended", "restricted", "validate your account",
    "security alert", "we noticed something unusual", "failure to comply",
    "time sensitive", "before the bank closes", "process this today",
]

BEC_FRAUD_PHRASES = [
    "wire transfer", "urgent wire", "process a payment", "send the account details",
    "i need you to process", "confirm you can do this", "keep this confidential",
    "don't tell anyone", "between us", "change of bank details", "new payment instructions",
    "are you available right now", "can you do me a favor", "ceo", "executive request",
]

LOTTERY_PRIZE_PHRASES = [
    "you've won", "you have won", "congratulations! you", "claim your prize",
    "claim your reward", "selected to claim", "winning notification",
    "lucky winner", "gift card", "free reward", "claim now", "claim your $",
]

CREDENTIAL_REQUEST_PHRASES = [
    "enter your password", "confirm your password", "ssn", "social security number",
    "credit card number", "cvv", "pin number", "login credentials", "verify your password",
    "update your billing", "wire transfer", "bank account details", "routing number",
    "enter your details", "confirm your details", "username and password",
]

GENERIC_GREETINGS = [
    "dear customer", "dear user", "dear valued customer", "dear account holder",
    "dear sir/madam", "dear member", "valued customer", "dear client",
]

EXECUTABLE_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".jar", ".msi", ".com",
    ".pif", ".hta", ".ps1", ".wsf",
}

RISKY_DOC_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".zip", ".rar", ".7z", ".iso"}


@dataclass
class Indicator:
    category: str        # "header" | "sender" | "url" | "body" | "attachment"
    name: str             # short machine-readable id
    description: str      # human-readable explanation
    weight: int           # contribution to risk score (0-100 scale fragments)
    evidence: str = ""    # the specific value that triggered this


def _domain_of(addr_or_url):
    """Extract the registrable-ish domain from an email address or URL."""
    if not addr_or_url:
        return ""
    if "@" in addr_or_url and "://" not in addr_or_url:
        return addr_or_url.split("@")[-1].strip().lower()
    parsed = urlparse(addr_or_url)
    return (parsed.netloc or "").lower().split(":")[0]


def _levenshtein(a, b):
    """Simple edit distance, used for typosquat / lookalike domain detection."""
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    if len(b) == 0:
        return len(a)
    prev_row = range(len(b) + 1)
    for i, ca in enumerate(a):
        curr_row = [i + 1]
        for j, cb in enumerate(b):
            curr_row.append(min(
                prev_row[j + 1] + 1,
                curr_row[j] + 1,
                prev_row[j] + (ca != cb)
            ))
        prev_row = curr_row
    return prev_row[-1]


def _is_lookalike_brand(domain):
    """Check if a domain is suspiciously close to (but not exactly) a known brand domain."""
    if not domain:
        return None
    core = domain.split(".")[0]

    tokens = [core] + re.split(r'[-_]', core)

    for brand in BRAND_KEYWORDS:
        if core == brand:
            continue  # exact brand name as a domain root, handled by freemail/legit checks
        for token in tokens:
            if not token or token == brand:
                continue
            if brand in token and token != brand:
                return brand
            dist = _levenshtein(token, brand)
            if 0 < dist <= 2 and len(brand) > 3 and abs(len(token) - len(brand)) <= 2:
                return brand
    return None

def analyze_headers(email_data):
    """Inspect authentication results, header structure, and routing anomalies."""
    indicators = []
    headers = email_data.get("headers", {}) or {}

    if email_data.get("_no_headers") or not headers:
        return indicators  # CSV-only datasets often lack raw headers; skip silently

    auth_results = headers.get("authentication-results", "")
    received_spf = headers.get("received-spf", "")

    auth_blob = (auth_results + " " + received_spf).lower()

    if auth_blob.strip():
        if "spf=fail" in auth_blob or "spf=softfail" in auth_blob:
            indicators.append(Indicator(
                "header", "spf_fail",
                "SPF authentication failed — sending server is not authorized for this domain.",
                25, evidence=auth_results or received_spf
            ))
        if "dkim=fail" in auth_blob:
            indicators.append(Indicator(
                "header", "dkim_fail",
                "DKIM signature verification failed — message may have been altered or spoofed.",
                20, evidence=auth_results
            ))
        if "dmarc=fail" in auth_blob:
            indicators.append(Indicator(
                "header", "dmarc_fail",
                "DMARC policy check failed — domain alignment could not be verified.",
                20, evidence=auth_results
            ))
    else:
        indicators.append(Indicator(
            "header", "no_auth_results",
            "No SPF/DKIM/DMARC authentication-results header present (cannot verify sender authenticity).",
            8
        ))

    from_domain = _domain_of(email_data.get("from_addr", ""))
    reply_to = email_data.get("reply_to", "")
    return_path = email_data.get("return_path", "")

    if reply_to:
        reply_domain = _domain_of(parse_addr_safe(reply_to))
        if reply_domain and from_domain and reply_domain != from_domain:
            indicators.append(Indicator(
                "header", "reply_to_mismatch",
                f"Reply-To domain ('{reply_domain}') differs from From domain ('{from_domain}') — "
                "replies would be redirected elsewhere.",
                18, evidence=reply_to
            ))

    if return_path:
        rp_domain = _domain_of(parse_addr_safe(return_path))
        if rp_domain and from_domain and rp_domain != from_domain:
            indicators.append(Indicator(
                "header", "return_path_mismatch",
                f"Return-Path domain ('{rp_domain}') differs from From domain ('{from_domain}').",
                10, evidence=return_path
            ))

    received_chain = email_data.get("received_chain", [])
    if len(received_chain) >= 8:
        indicators.append(Indicator(
            "header", "long_received_chain",
            f"Unusually long Received header chain ({len(received_chain)} hops) — "
            "may indicate relaying through multiple/compromised servers.",
            6, evidence=str(len(received_chain))
        ))

    x_mailer = headers.get("x-mailer", "") or headers.get("user-agent", "")
    if x_mailer and any(tool in x_mailer.lower() for tool in ["php", "bulk", "mass", "mailer"]):
        indicators.append(Indicator(
            "header", "bulk_mailer_signature",
            f"Sent via a script/bulk-mailer signature ('{x_mailer}'), common in mass phishing campaigns.",
            8, evidence=x_mailer
        ))

    return indicators


def parse_addr_safe(raw):
    import email.utils
    _, addr = email.utils.parseaddr(raw)
    return addr.strip().lower()



def analyze_sender(email_data):
    indicators = []
    from_name = (email_data.get("from_name") or "").strip()
    from_addr = (email_data.get("from_addr") or "").strip().lower()
    from_domain = _domain_of(from_addr)

    if not from_addr:
        indicators.append(Indicator(
            "sender", "missing_sender",
            "No parsable sender address found.",
            10
        ))
        return indicators


    name_lower = from_name.lower()
    for brand in BRAND_KEYWORDS:
        if brand in name_lower and brand not in from_domain:
            indicators.append(Indicator(
                "sender", "display_name_spoof",
                f"Display name references '{brand.title()}' but sending domain is '{from_domain}', "
                "a classic brand-impersonation pattern.",
                22, evidence=f"{from_name} <{from_addr}>"
            ))
            break

    lookalike = _is_lookalike_brand(from_domain)
    if lookalike:
        indicators.append(Indicator(
            "sender", "lookalike_domain",
            f"Sending domain '{from_domain}' closely resembles brand '{lookalike}' "
            "(possible typosquatting / homoglyph domain).",
            25, evidence=from_domain
        ))

    if from_domain in FREE_MAIL_DOMAINS:
        for brand in BRAND_KEYWORDS:
            if brand in name_lower or brand in (email_data.get("subject", "") or "").lower():
                indicators.append(Indicator(
                    "sender", "freemail_brand_claim",
                    f"Claims to be from '{brand.title()}' but was sent via a free webmail provider "
                    f"('{from_domain}') instead of a corporate domain.",
                    20, evidence=from_domain
                ))
                break

   
    for tld in SUSPICIOUS_TLDS:
        if from_domain.endswith(tld):
            indicators.append(Indicator(
                "sender", "suspicious_tld",
                f"Sender domain uses an uncommon/high-abuse TLD ('{tld}').",
                12, evidence=from_domain
            ))
            break

    # Numeric / random-looking domain (common in throwaway phishing infra)
    domain_root = from_domain.split(".")[0] if from_domain else ""
    if domain_root and (re.search(r'\d{3,}', domain_root) or len(re.findall(r'[bcdfghjklmnpqrstvwxyz]{5,}', domain_root)) > 0):
        indicators.append(Indicator(
            "sender", "random_looking_domain",
            f"Sender domain root ('{domain_root}') looks randomly generated, common for disposable phishing infrastructure.",
            10, evidence=from_domain
        ))

    return indicators


# ---------------------------------------------------------------------------
# URL / LINK analysis
# ---------------------------------------------------------------------------

def analyze_urls(email_data):
    indicators = []
    urls = email_data.get("urls", []) or []
    from_domain = _domain_of(email_data.get("from_addr", ""))

    if not urls:
        return indicators

    shortener_hits = []
    ip_url_hits = []
    mismatch_hits = []
    lookalike_hits = []
    suspicious_tld_hits = []
    at_symbol_hits = []

    for url in urls:
        domain = _domain_of(url)
        if not domain:
            continue

        if domain in URL_SHORTENERS:
            shortener_hits.append(url)

        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
            ip_url_hits.append(url)

        if "@" in urlparse(url).netloc:
            at_symbol_hits.append(url)

        lookalike = _is_lookalike_brand(domain)
        if lookalike:
            lookalike_hits.append((url, lookalike))

        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                suspicious_tld_hits.append(url)
                break

        if from_domain and domain != from_domain and not domain.endswith("." + from_domain):
            mismatch_hits.append(url)

    if shortener_hits:
        indicators.append(Indicator(
            "url", "url_shortener",
            f"Email contains {len(shortener_hits)} shortened URL(s) which obscure the real destination.",
            15, evidence=shortener_hits[0]
        ))

    if ip_url_hits:
        indicators.append(Indicator(
            "url", "ip_address_url",
            "A link points directly to a raw IP address instead of a domain name — highly unusual for legitimate mail.",
            28, evidence=ip_url_hits[0]
        ))

    if at_symbol_hits:
        indicators.append(Indicator(
            "url", "at_symbol_url",
            "A link uses the '@' trick in its URL, which browsers ignore everything before — "
            "a known way to disguise the real destination.",
            25, evidence=at_symbol_hits[0]
        ))

    if lookalike_hits:
        url, brand = lookalike_hits[0]
        indicators.append(Indicator(
            "url", "lookalike_link_domain",
            f"Link domain resembles brand '{brand}' but isn't the real domain (typosquat pattern).",
            25, evidence=url
        ))

    if suspicious_tld_hits:
        indicators.append(Indicator(
            "url", "suspicious_link_tld",
            f"{len(suspicious_tld_hits)} link(s) use high-risk/uncommon TLDs often abused for phishing.",
            12, evidence=suspicious_tld_hits[0]
        ))

    if mismatch_hits and len(mismatch_hits) == len(urls) and from_domain:
        indicators.append(Indicator(
            "url", "sender_link_domain_mismatch",
            "None of the links in the email point back to the sender's own domain.",
            10, evidence=mismatch_hits[0]
        ))

    if len(urls) >= 6:
        indicators.append(Indicator(
            "url", "excessive_links",
            f"Unusually high number of links ({len(urls)}) in a single email.",
            6, evidence=str(len(urls))
        ))

    return indicators


# ---------------------------------------------------------------------------
# BODY / CONTENT analysis
# ---------------------------------------------------------------------------

def analyze_body(email_data):
    indicators = []
    subject = (email_data.get("subject") or "").lower()
    body = (email_data.get("body_text") or "") + " " + (email_data.get("body_html") or "")
    body_lower = body.lower()
    combined = subject + " " + body_lower

    urgency_hits = [p for p in URGENCY_PHRASES if p in combined]
    if urgency_hits:
        indicators.append(Indicator(
            "body", "urgency_language",
            f"Uses urgency/pressure language commonly seen in phishing (e.g. \"{urgency_hits[0]}\").",
            min(8 + 4 * len(urgency_hits), 24),
            evidence="; ".join(urgency_hits[:3])
        ))

    cred_hits = [p for p in CREDENTIAL_REQUEST_PHRASES if p in combined]
    if cred_hits:
        indicators.append(Indicator(
            "body", "credential_harvesting_language",
            f"Requests sensitive credentials or financial information (e.g. \"{cred_hits[0]}\").",
            min(15 + 5 * len(cred_hits), 30),
            evidence="; ".join(cred_hits[:3])
        ))

    greeting_hits = [p for p in GENERIC_GREETINGS if p in combined]
    if greeting_hits:
        indicators.append(Indicator(
            "body", "generic_greeting",
            f"Uses a generic, non-personalized greeting (\"{greeting_hits[0]}\") instead of the recipient's name.",
            8, evidence=greeting_hits[0]
        ))

    # "Click here" style anchor text hiding the real link
    if re.search(r'click\s+here|verify\s+now|update\s+now|confirm\s+now|login\s+here', combined):
        indicators.append(Indicator(
            "body", "vague_cta_link_text",
            "Uses vague call-to-action link text ('Click here' / 'Verify now') instead of showing the real destination.",
            8
        ))

    # Mismatched/forged HTML link text vs href (anchor says one thing, href goes elsewhere)
    html = email_data.get("body_html", "") or ""
    anchor_mismatches = _find_anchor_text_href_mismatches(html)
    if anchor_mismatches:
        indicators.append(Indicator(
            "body", "anchor_text_href_mismatch",
            "Link display text doesn't match its actual destination URL — a strong deception indicator.",
            22, evidence=anchor_mismatches[0]
        ))

    # Poor grammar / spelling proxy: excessive exclamation marks, ALL CAPS shouting
    exclam_count = body.count("!")
    if exclam_count >= 5:
        indicators.append(Indicator(
            "body", "excessive_punctuation",
            f"Excessive exclamation marks ({exclam_count}) — common in low-effort mass phishing.",
            5, evidence=str(exclam_count)
        ))

    caps_words = re.findall(r'\b[A-Z]{4,}\b', body)
    if len(caps_words) >= 5:
        indicators.append(Indicator(
            "body", "excessive_caps",
            "Excessive ALL-CAPS words used for artificial urgency/emphasis.",
            5, evidence=str(len(caps_words))
        ))

    # Money/financial bait
    if re.search(r'\$\s?\d{2,}[,.]?\d*|won\s+a\s+prize|lottery|inheritance|claim\s+your\s+reward', combined):
        indicators.append(Indicator(
            "body", "financial_bait",
            "References a financial reward, prize, lottery, or unexpected sum of money — classic bait pattern.",
            12
        ))

    lottery_hits = [p for p in LOTTERY_PRIZE_PHRASES if p in combined]
    if lottery_hits:
        indicators.append(Indicator(
            "body", "lottery_prize_bait",
            f"Uses prize/lottery/giveaway bait language (e.g. \"{lottery_hits[0]}\") to lure clicks.",
            min(15 + 4 * len(lottery_hits), 25),
            evidence="; ".join(lottery_hits[:3])
        ))

    bec_hits = [p for p in BEC_FRAUD_PHRASES if p in combined]
    if len(bec_hits) >= 2:
        indicators.append(Indicator(
            "body", "bec_style_request",
            f"Language pattern consistent with Business Email Compromise (BEC) / CEO-fraud requests "
            f"(e.g. \"{bec_hits[0]}\", \"{bec_hits[1]}\") — urgent, confidential financial requests "
            "with no links or attachments, relying purely on social engineering.",
            min(15 + 6 * len(bec_hits), 30),
            evidence="; ".join(bec_hits[:4])
        ))

    return indicators


def _find_anchor_text_href_mismatches(html):
    """Find <a href="X">Y</a> where Y looks like a URL/brand but doesn't match X's domain."""
    mismatches = []
    if not html:
        return mismatches
    anchor_pattern = re.compile(
        r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL
    )
    for href, text in anchor_pattern.findall(html):
        text_clean = re.sub('<[^<]+?>', '', text).strip()
        text_url_match = re.search(r'(https?://[^\s<]+|www\.[^\s<]+)', text_clean)
        if text_url_match:
            displayed = text_url_match.group(1)
            displayed_domain = _domain_of(displayed if "://" in displayed else "http://" + displayed)
            href_domain = _domain_of(href)
            if displayed_domain and href_domain and displayed_domain != href_domain:
                mismatches.append(f"shown: {displayed_domain} -> actual: {href_domain}")
    return mismatches


# ---------------------------------------------------------------------------
# ATTACHMENT analysis
# ---------------------------------------------------------------------------

def analyze_attachments(email_data):
    indicators = []
    attachments = email_data.get("attachments", []) or []

    for fname in attachments:
        lower = fname.lower()
        ext = "." + lower.rsplit(".", 1)[-1] if "." in lower else ""

        if ext in EXECUTABLE_EXTENSIONS:
            indicators.append(Indicator(
                "attachment", "executable_attachment",
                f"Attachment '{fname}' has an executable/script extension ({ext}) — high risk.",
                30, evidence=fname
            ))
        elif ext in RISKY_DOC_EXTENSIONS:
            indicators.append(Indicator(
                "attachment", "macro_or_archive_attachment",
                f"Attachment '{fname}' is a macro-enabled document or compressed archive ({ext}), "
                "commonly used to deliver malware payloads.",
                18, evidence=fname
            ))

        # Double extension trick: invoice.pdf.exe
        parts = lower.split(".")
        if len(parts) >= 3 and ("." + parts[-1]) in EXECUTABLE_EXTENSIONS:
            indicators.append(Indicator(
                "attachment", "double_extension",
                f"Attachment '{fname}' uses a double file extension to disguise its real type.",
                25, evidence=fname
            ))

    return indicators


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def run_all_checks(email_data):
    """Run every analysis module and return a flat list of Indicator objects."""
    indicators = []
    indicators += analyze_headers(email_data)
    indicators += analyze_sender(email_data)
    indicators += analyze_urls(email_data)
    indicators += analyze_body(email_data)
    indicators += analyze_attachments(email_data)
    return indicators
