# 🛡️ Phishing Email Detection Tool

A header + body analysis tool for detecting phishing indicators in email datasets. Built to **collect, analyze, classify, and document** phishing email samples — with a CLI for batch processing and a Streamlit dashboard for interactive exploration.

> ⚠️ **Disclaimer:** This is a heuristic triage and awareness tool for research, education, and SOC-analyst support. It is **not** a substitute for a commercial email security gateway, and a high score should be treated as "needs human review," not "confirmed malicious."

---

## ✨ Features

- **Multi-format ingestion**: `.eml`, `.msg` (Outlook), `.csv` datasets, `.zip` archives, or whole folders — any mix.
- **Header analysis**: SPF / DKIM / DMARC results, Reply-To & Return-Path mismatches, Received-chain anomalies, bulk-mailer fingerprints.
- **Sender & domain analysis**: brand impersonation in display names, typosquatted/lookalike domains, free-webmail abuse, suspicious TLDs.
- **Link/URL inspection**: URL shorteners, raw IP-address links, the `@`-symbol URL trick, anchor-text vs. real-href mismatches, lookalike link domains.
- **Body content analysis**: urgency/pressure language, credential-harvesting requests, generic greetings, lottery/prize bait, Business Email Compromise (BEC) patterns.
- **Attachment checks**: executable extensions, macro-enabled documents, double-extension disguises (`invoice.pdf.exe`).
- **Risk scoring**: every email gets a 0–100 score and a tier — `MINIMAL` / `LOW` / `MEDIUM` / `HIGH` / `CRITICAL`.
- **Reporting**: auto-generated Markdown findings report + JSON + CSV exports, including accuracy validation against any ground-truth labels in your dataset.
- **Two interfaces**: a scriptable CLI and an interactive Streamlit dashboard.

---

## 📁 Project Structure

```
phishing-detection-tool/
├── app.py                       # Streamlit dashboard
├── cli.py                       # Command-line interface
├── detector/
│   ├── email_parser.py          # Normalizes .eml / .msg / CSV rows into one structure
│   ├── indicators.py             # All phishing heuristic checks (header/sender/url/body/attachment)
│   ├── risk_scorer.py            # Converts indicators -> 0-100 score -> risk tier
│   ├── dataset_loader.py         # Discovers & loads files/folders/zips
│   └── report_generator.py       # Builds Markdown/JSON/CSV findings reports
├── data/
│   ├── sample_emails/             # Sample .eml files (3 phishing, 2 legitimate)
│   └── sample_emails_dataset.csv  # Sample labeled CSV dataset
├── tests/
│   └── test_detector.py          # Unit tests for the detection pipeline
├── reports/                      # Generated reports land here
├── requirements.txt
└── README.md
```

---

## 🚀 Quick Start

### 1. Install

```bash
git clone https://github.com/<your-username>/phishing-detection-tool.git
cd phishing-detection-tool
pip install -r requirements.txt
```

> `extract-msg` (for `.msg` support) is optional — the tool works fine on `.eml`/`.csv` without it.

### 2. Run the CLI

```bash
# Analyze a folder of sample emails
python cli.py --input data/sample_emails --output reports

# Analyze a CSV dataset (with optional ground-truth label column)
python cli.py --input data/sample_emails_dataset.csv --output reports

# Analyze a single email
python cli.py --input path/to/suspicious_email.eml

# Only show emails scoring 50+ in the console
python cli.py --input data/sample_emails --min-score 50
```

This prints a colorized per-email breakdown plus a summary, and writes:
- `reports/phishing_report.md` — human-readable findings report
- `reports/phishing_results.json` — full structured results
- `reports/phishing_results.csv` — flat results table

### 3. Run the Streamlit dashboard

```bash
streamlit run app.py
```

Then either upload files directly in the browser, or point it at a server-side path (e.g. `data/sample_emails`). The dashboard has four tabs:

| Tab | What it shows |
|---|---|
| 📊 Overview | Aggregate stats, risk tier distribution, top indicators |
| 📧 Email Explorer | Per-email drill-down with filters and flagged indicators |
| 📄 Report | Full Markdown report + download buttons (MD/JSON/CSV) |
| 🎓 Prevention Guidelines | Awareness checklist for individuals & organizations |

---

## 📊 Using Your Own Dataset

### CSV format
The loader recognizes common column-name variants from public phishing datasets (Nazario, Enron-Spam, Kaggle phishing-email CSVs, etc.):

| Field | Recognized column names |
|---|---|
| Subject | `subject`, `email subject`, `title` |
| Body | `body`, `text`, `email text`, `message`, `content`, `email_text` |
| Sender | `from`, `sender`, `sender_email`, `from_email`, `email_from` |
| Label (optional) | `label`, `class`, `type`, `category`, `is_phishing`, `result` |

Label values like `1`/`phishing`/`spam`/`true` are normalized to `phishing`; `0`/`legit`/`ham`/`false` to `legitimate`. If your dataset has labels, the tool will automatically report classification accuracy in the summary.

### Raw email files
Just point `--input` at a `.eml` file, a `.msg` file, a folder containing many of either (recursively), or a `.zip` archive of the same. Mixed folders (CSV + EML + MSG together) work too.

---

## 🧠 How Scoring Works

1. Every email is run through ~25 independent heuristic checks across 5 categories (header, sender, url, body, attachment).
2. Each triggered check ("indicator") has a fixed severity weight.
3. Weights are summed with **diminishing returns** — the 2nd, 3rd, 4th... indicator contributes progressively less, so one email tripping 10 minor things doesn't auto-max the score, while 2-3 severe indicators (e.g. SPF fail + lookalike domain + credential request) push the score high quickly.
4. The final 0–100 score maps to a tier:

| Score | Tier |
|---|---|
| ≥ 75 | 🔴 CRITICAL |
| ≥ 50 | 🟠 HIGH |
| ≥ 25 | 🟡 MEDIUM |
| ≥ 10 | 🔵 LOW |
| < 10 | 🟢 MINIMAL |

See `detector/indicators.py` for the full, documented list of checks and their weights — every weight and phrase list is plain Python and easy to tune for your own dataset.

---

## 🎓 Prevention & Awareness Guidelines

### For Individuals
1. Verify the sender's actual email address, not just the display name.
2. Don't trust urgency — legitimate organizations rarely threaten instant account closure.
3. Hover before you click; check that the real link destination matches the claimed organization.
4. Never enter credentials via an emailed link — navigate to the official site directly.
5. Be suspicious of generic greetings ("Dear Customer") from companies you have an account with.
6. Watch for lookalike domains (`paypa1.com`, `arnazon.com`, `secure-paypal-verify.com`).
7. Don't open unexpected attachments, especially `.exe`, `.scr`, `.zip`, or macro-enabled Office files.
8. Report suspicious emails to IT/security rather than just deleting them.

### For Organizations
1. Enforce SPF, DKIM, and DMARC on all domains; monitor DMARC aggregate reports.
2. Deploy email security gateways with attachment sandboxing and link rewriting.
3. Run regular phishing simulation campaigns to measure detection rates.
4. Maintain a low-friction "Report Phishing" channel and act on reports quickly.
5. Apply least-privilege access to limit blast radius from compromised accounts.
6. Use multi-factor authentication (MFA) everywhere.
7. Monitor for typosquatted domains targeting your brand.
8. Train employees continuously — phishing tactics evolve constantly.

### Quick Reference: Red Flags Checklist

| Category | Watch For |
|---|---|
| Header | Missing/failed SPF, DKIM, or DMARC; Reply-To ≠ From domain |
| Sender | Brand name in display name but mismatched domain; free webmail claiming to be a company; lookalike domains |
| Links | URL shorteners; raw IP links; anchor text that doesn't match the real href; unusual TLDs (`.top`, `.xyz`, `.click`, `.icu`...) |
| Body | Urgency/threat language; requests for passwords/SSN/card numbers; generic greetings; prize/lottery bait; unusual wire-transfer requests |
| Attachments | `.exe`, `.scr`, `.js`, `.vbs`; macro-enabled Office docs (`.docm`); double extensions (`invoice.pdf.exe`) |

---

## 🧪 Testing

```bash
pip install pytest
pytest tests/ -v
```

Tests cover header/URL/body indicator logic, CSV row normalization, risk-score boundary conditions, and end-to-end analysis of the bundled sample emails.

---

## 🔧 Extending the Tool

- **Add a new indicator**: write a function (or extend an existing one) in `detector/indicators.py` that returns `Indicator(category, name, description, weight, evidence=...)` objects, then add it to `run_all_checks()`.
- **Tune weights**: all severity weights are plain integers at the top of `indicators.py` — adjust them based on false-positive/negative rates on your own dataset.
- **Add a new file format**: extend `detector/dataset_loader.py` and `detector/email_parser.py`.
- **Integrate threat-intel APIs** (e.g. VirusTotal, URLhaus, WHOIS lookups) by adding a new check module that calls out to those services and returns additional `Indicator`s — the architecture is designed to make this a drop-in addition.

---

## 📜 License

MIT — see [LICENSE](LICENSE).

## ⚠️ Responsible Use

This tool is intended for **defensive security research, education, and email-safety awareness**. Do not use it to develop phishing content. Always handle phishing sample datasets (including any you collect yourself) per your organization's data-handling policy, since they may contain real victim data or malicious payloads.
