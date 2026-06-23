"""
report_generator.py
---------------------
Builds the "Document findings clearly" deliverable: a Markdown report
summarizing dataset-wide statistics plus per-email findings, alongside
machine-readable JSON and CSV exports.
"""

import json
import csv
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


def summarize_batch(results):
    """Aggregate stats across all analyzed emails."""
    total = len(results)
    tier_counts = Counter(r["risk_tier"] for r in results)
    avg_score = round(sum(r["risk_score"] for r in results) / total, 1) if total else 0

    indicator_counter = Counter()
    category_counter = Counter()
    for r in results:
        for ind in r["indicators"]:
            indicator_counter[ind["name"]] += 1
            category_counter[ind["category"]] += 1

    # Accuracy vs ground truth, if labels are present in the dataset
    labeled = [r for r in results if r.get("ground_truth_label") in ("phishing", "legitimate")]
    accuracy_stats = None
    if labeled:
        correct = 0
        for r in labeled:
            predicted_phish = r["risk_tier"] in ("HIGH", "CRITICAL")
            actual_phish = r["ground_truth_label"] == "phishing"
            if predicted_phish == actual_phish:
                correct += 1
        accuracy_stats = {
            "labeled_count": len(labeled),
            "correct": correct,
            "accuracy_pct": round(100 * correct / len(labeled), 1),
        }

    return {
        "total_emails": total,
        "average_risk_score": avg_score,
        "tier_breakdown": dict(tier_counts),
        "top_indicators": indicator_counter.most_common(10),
        "category_breakdown": dict(category_counter),
        "accuracy_vs_labels": accuracy_stats,
    }


def generate_markdown_report(results, summary, dataset_name="dataset"):
    """Build a human-readable Markdown findings report."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = []
    lines.append(f"# Phishing Email Analysis Report")
    lines.append("")
    lines.append(f"**Dataset:** `{dataset_name}`  ")
    lines.append(f"**Generated:** {now}  ")
    lines.append(f"**Total emails analyzed:** {summary['total_emails']}")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 1. Executive Summary")
    lines.append("")
    lines.append(f"- **Average risk score:** {summary['average_risk_score']} / 100")
    lines.append("- **Risk tier breakdown:**")
    for tier in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL"]:
        count = summary["tier_breakdown"].get(tier, 0)
        pct = round(100 * count / summary["total_emails"], 1) if summary["total_emails"] else 0
        lines.append(f"  - {tier}: {count} ({pct}%)")

    if summary.get("accuracy_vs_labels"):
        acc = summary["accuracy_vs_labels"]
        lines.append("")
        lines.append(
            f"- **Validation against ground-truth labels:** {acc['correct']}/{acc['labeled_count']} "
            f"correctly classified ({acc['accuracy_pct']}%) — using HIGH/CRITICAL tier as the "
            f"'predicted phishing' threshold."
        )

    lines.append("")
    lines.append("## 2. Most Common Phishing Indicators")
    lines.append("")
    lines.append("| Indicator | Occurrences |")
    lines.append("|---|---|")
    for name, count in summary["top_indicators"]:
        lines.append(f"| `{name}` | {count} |")

    lines.append("")
    lines.append("## 3. Indicators by Category")
    lines.append("")
    lines.append("| Category | Total Flags |")
    lines.append("|---|---|")
    for cat, count in sorted(summary["category_breakdown"].items(), key=lambda x: -x[1]):
        lines.append(f"| {cat} | {count} |")

    lines.append("")
    lines.append("## 4. High-Risk Emails (HIGH / CRITICAL tier)")
    lines.append("")
    high_risk = [r for r in results if r["risk_tier"] in ("HIGH", "CRITICAL")]
    high_risk.sort(key=lambda r: -r["risk_score"])

    if not high_risk:
        lines.append("_No emails reached HIGH or CRITICAL risk tier._")
    else:
        for r in high_risk[:50]:
            lines.append(f"### {r['source_file']} — Score: {r['risk_score']} ({r['risk_tier']})")
            lines.append(f"- **Subject:** {r['subject'] or '(none)'}")
            lines.append(f"- **From:** {r['from'] or '(unknown)'}")
            lines.append(f"- **Indicators flagged:** {r['indicator_count']}")
            for ind in r["indicators"]:
                lines.append(f"  - **[{ind['category']}] {ind['name']}** (+{ind['weight']}): {ind['description']}")
            lines.append("")

    lines.append("## 5. Methodology")
    lines.append("")
    lines.append(
        "Each email is scored using independent heuristic checks across four areas: "
        "**header authentication** (SPF/DKIM/DMARC, Reply-To/Return-Path mismatches), "
        "**sender/domain analysis** (brand impersonation, typosquatting, free-mail abuse), "
        "**URL/link inspection** (shorteners, IP-literal links, anchor-text spoofing, lookalike domains), "
        "and **body content analysis** (urgency language, credential requests, generic greetings, financial bait). "
        "Attachment names are also checked for executable or macro-bearing file types."
    )
    lines.append("")
    lines.append(
        "Indicator weights are summed with diminishing returns per additional indicator, "
        "capped at 100, and mapped to a risk tier: "
        "CRITICAL (≥75), HIGH (≥50), MEDIUM (≥25), LOW (≥10), MINIMAL (<10)."
    )
    lines.append("")
    lines.append(
        "**Note:** This is a heuristic triage tool for research, awareness, and SOC-analyst "
        "support — it does not replace email security gateways, sandboxing, or human judgment."
    )

    return "\n".join(lines)


def write_reports(results, output_dir, dataset_name="dataset"):
    """
    Write all three output formats (Markdown, JSON, CSV) to output_dir.
    Returns dict of {format: path}.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    summary = summarize_batch(results)

    md_path = output_dir / "phishing_report.md"
    json_path = output_dir / "phishing_results.json"
    csv_path = output_dir / "phishing_results.csv"

    md_content = generate_markdown_report(results, summary, dataset_name)
    md_path.write_text(md_content, encoding="utf-8")

    json_path.write_text(
        json.dumps({"summary": summary, "results": results}, indent=2, default=str),
        encoding="utf-8"
    )

    fieldnames = [
        "source_file", "subject", "from", "from_domain", "to", "date",
        "risk_score", "risk_tier", "indicator_count", "url_count",
        "attachment_count", "ground_truth_label", "top_indicators"
    ]
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            row = {k: r.get(k, "") for k in fieldnames if k != "top_indicators"}
            row["top_indicators"] = "; ".join(i["name"] for i in r["indicators"][:5])
            writer.writerow(row)

    return {"markdown": str(md_path), "json": str(json_path), "csv": str(csv_path)}
