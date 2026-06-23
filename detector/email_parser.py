"""
email_parser.py
----------------
Parses raw email files (.eml, .msg) and CSV dataset rows into a single
normalized structure that the rest of the pipeline can analyze:

    {
        "message_id": str,
        "subject": str,
        "from_raw": str,        # full From header
        "from_addr": str,       # parsed email address
        "from_name": str,       # display name
        "reply_to": str,
        "return_path": str,
        "to": str,
        "date": str,
        "received_chain": [str, ...],   # Received: headers, top to bottom
        "headers": {k: v, ...},          # all headers, lowercase keys
        "body_text": str,
        "body_html": str,
        "urls": [str, ...],
        "attachments": [str, ...],
        "source_file": str,
        "label": str | None,    # ground-truth label if present in dataset (phishing/legit)
    }
"""

import email
import re
from email import policy
from email.parser import BytesParser
from pathlib import Path

URL_REGEX = re.compile(
    r'(?:href=["\']?)?(https?://[^\s"\'<>\)\]]+)', re.IGNORECASE
)


def _decode_header_value(value):
    """Best-effort decode of an email header value to a clean string."""
    if value is None:
        return ""
    try:
        parts = email.header.decode_header(str(value))
        decoded = ""
        for text, enc in parts:
            if isinstance(text, bytes):
                decoded += text.decode(enc or "utf-8", errors="replace")
            else:
                decoded += text
        return decoded.strip()
    except Exception:
        return str(value).strip()


def extract_urls(text):
    """Extract all http/https URLs from a text or HTML blob."""
    if not text:
        return []
    found = URL_REGEX.findall(text)
    seen = set()
    urls = []
    for u in found:
        u = u.rstrip('.,;:)')
        if u not in seen:
            seen.add(u)
            urls.append(u)
    return urls


def parse_from_address(from_raw):
    """Split a From header into (display_name, email_address)."""
    if not from_raw:
        return "", ""
    name, addr = email.utils.parseaddr(from_raw)
    return name.strip(), addr.strip().lower()


def get_body_parts(msg):
    """Walk a Message object and return (plain_text, html_text, attachment_names)."""
    plain, html, attachments = "", "", []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition", ""))

            if "attachment" in disposition or part.get_filename():
                fname = part.get_filename()
                if fname:
                    attachments.append(_decode_header_value(fname))
                continue

            try:
                payload = part.get_payload(decode=True)
                if payload is None:
                    continue
                charset = part.get_content_charset() or "utf-8"
                text = payload.decode(charset, errors="replace")
            except Exception:
                continue

            if content_type == "text/plain":
                plain += text
            elif content_type == "text/html":
                html += text
    else:
        disposition = str(msg.get("Content-Disposition", ""))
        if "attachment" in disposition or msg.get_filename():
            fname = msg.get_filename()
            if fname:
                attachments.append(_decode_header_value(fname))
            return plain.strip(), html.strip(), attachments

        try:
            payload = msg.get_payload(decode=True)
            charset = msg.get_content_charset() or "utf-8"
            text = payload.decode(charset, errors="replace") if payload else str(msg.get_payload())
        except Exception:
            text = str(msg.get_payload())

        if msg.get_content_type() == "text/html":
            html = text
        else:
            plain = text

    return plain.strip(), html.strip(), attachments


def parse_eml_bytes(raw_bytes, source_file="unknown.eml", label=None):
    """Parse raw .eml bytes into the normalized email dict."""
    msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    return _normalize_message(msg, source_file, label)


def parse_eml_file(filepath, label=None):
    path = Path(filepath)
    with open(path, "rb") as f:
        raw_bytes = f.read()
    return parse_eml_bytes(raw_bytes, source_file=path.name, label=label)


def _normalize_message(msg, source_file, label=None):
    headers = {}
    for k in msg.keys():
        headers[k.lower()] = _decode_header_value(msg.get(k))

    from_raw = msg.get("From", "")
    from_name, from_addr = parse_from_address(_decode_header_value(from_raw))

    received_chain = msg.get_all("Received", []) or []
    received_chain = [_decode_header_value(r) for r in received_chain]

    plain, html, attachments = get_body_parts(msg)
    body_combined = plain + "\n" + html

    return {
        "message_id": _decode_header_value(msg.get("Message-ID", "")),
        "subject": _decode_header_value(msg.get("Subject", "")),
        "from_raw": _decode_header_value(from_raw),
        "from_addr": from_addr,
        "from_name": from_name,
        "reply_to": _decode_header_value(msg.get("Reply-To", "")),
        "return_path": _decode_header_value(msg.get("Return-Path", "")),
        "to": _decode_header_value(msg.get("To", "")),
        "date": _decode_header_value(msg.get("Date", "")),
        "received_chain": received_chain,
        "headers": headers,
        "body_text": plain,
        "body_html": html,
        "urls": extract_urls(body_combined),
        "attachments": attachments,
        "source_file": source_file,
        "label": label,
    }


def parse_msg_file(filepath, label=None):
    """
    Parse an Outlook .msg file. Requires the optional 'extract-msg' package.
    Raises a clear error if it's not installed.
    """
    try:
        import extract_msg
    except ImportError as e:
        raise ImportError(
            "Reading .msg files requires the 'extract-msg' package. "
            "Install it with: pip install extract-msg"
        ) from e

    path = Path(filepath)
    m = extract_msg.Message(str(path))

    headers = {}
    if m.header:
        for k, v in m.header.items():
            headers[k.lower()] = str(v)

    from_raw = m.sender or ""
    from_name, from_addr = parse_from_address(from_raw)

    body_text = m.body or ""
    body_html = getattr(m, "htmlBody", "") or ""
    if isinstance(body_html, bytes):
        body_html = body_html.decode("utf-8", errors="replace")

    attachments = [a.longFilename or a.shortFilename or "attachment"
                   for a in (m.attachments or [])]

    return {
        "message_id": headers.get("message-id", ""),
        "subject": m.subject or "",
        "from_raw": from_raw,
        "from_addr": from_addr,
        "from_name": from_name,
        "reply_to": headers.get("reply-to", ""),
        "return_path": headers.get("return-path", ""),
        "to": m.to or "",
        "date": str(m.date) if m.date else "",
        "received_chain": [v for k, v in headers.items() if k == "received"],
        "headers": headers,
        "body_text": body_text,
        "body_html": body_html if isinstance(body_html, str) else "",
        "urls": extract_urls(body_text + "\n" + str(body_html)),
        "attachments": attachments,
        "source_file": path.name,
        "label": label,
    }


def parse_csv_row(row, row_index=0, source_file="dataset.csv"):
    """
    Normalize a CSV row (dict) into the standard structure.
    Tries common column name variants used in public phishing datasets
    (e.g. Nazario, Enron-spam, Kaggle phishing email CSVs).
    """
    def col(*names):
        for n in names:
            for key in row:
                if key.lower().strip() == n:
                    val = row[key]
                    return val.strip() if isinstance(val, str) else val
        return ""

    subject = col("subject", "email subject", "title")
    body = col("body", "text", "email text", "message", "content", "email_text")
    sender = col("from", "sender", "sender_email", "from_email", "email_from")
    receiver = col("to", "receiver", "recipient")
    urls_field = col("urls", "url")
    label_raw = col("label", "class", "type", "category", "is_phishing", "result")

    label = None
    if label_raw != "":
        label_str = str(label_raw).strip().lower()
        if label_str in ("1", "phishing", "spam", "phish", "true", "yes", "malicious"):
            label = "phishing"
        elif label_str in ("0", "legit", "legitimate", "ham", "false", "no", "safe"):
            label = "legitimate"
        else:
            label = label_str

    body_text = str(body) if body else ""
    from_name, from_addr = parse_from_address(str(sender)) if sender else ("", "")
    if not from_addr and sender:
        from_addr = str(sender).strip().lower()

    urls = extract_urls(body_text)
    if urls_field:
        urls += [u.strip() for u in str(urls_field).split(",") if u.strip()]

    return {
        "message_id": f"csv-row-{row_index}",
        "subject": str(subject) if subject else "",
        "from_raw": str(sender) if sender else "",
        "from_addr": from_addr,
        "from_name": from_name,
        "reply_to": "",
        "return_path": "",
        "to": str(receiver) if receiver else "",
        "date": col("date"),
        "received_chain": [],
        "headers": {},  # CSV datasets typically don't include raw headers
        "body_text": body_text,
        "body_html": "",
        "urls": list(dict.fromkeys(urls)),
        "attachments": [],
        "source_file": source_file,
        "label": label,
        "_no_headers": True,  # flag so the scorer knows header checks are unavailable
    }
