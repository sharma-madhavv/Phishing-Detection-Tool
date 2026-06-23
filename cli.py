"""
cli.py
------
Command-line interface for the Phishing Email Detection Tool.

Usage:
    python cli.py --input data/sample_emails --output reports/
    python cli.py --input my_dataset.csv --output reports/
    python cli.py --input suspicious_email.eml

Run `python cli.py --help` for all options.
"""

import argparse
import sys
from pathlib import Path

from detector.dataset_loader import load_dataset
from detector.risk_scorer import analyze_batch
from detector.report_generator import write_reports, summarize_batch

TIER_COLORS = {
    "CRITICAL": "\033[1;91m",
    "HIGH": "\033[91m",
    "MEDIUM": "\033[93m",
    "LOW": "\033[94m",
    "MINIMAL": "\033[92m",
}
RESET = "\033[0m"


def colorize(text, tier):
    return f"{TIER_COLORS.get(tier, '')}{text}{RESET}"


def main():
    parser = argparse.ArgumentParser(
        description="Phishing Email Detection Tool — analyze email headers & body for phishing indicators."
    )
    parser.add_argument(
        "--input", "-i", required=True,
        help="Path to a .eml, .msg, .csv file, a directory, or a .zip archive of emails."
    )
    parser.add_argument(
        "--output", "-o", default="reports",
        help="Directory to write the Markdown/JSON/CSV report into (default: reports/)."
    )
    parser.add_argument(
        "--min-score", type=int, default=0,
        help="Only print emails with risk score >= this value to the console (report still includes all)."
    )
    parser.add_argument(
        "--quiet", "-q", action="store_true",
        help="Suppress per-email console output; only show the final summary."
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    print(f"[*] Loading dataset from: {input_path}")
    try:
        emails = load_dataset(input_path)
    except Exception as e:
        print(f"[!] Failed to load dataset: {e}", file=sys.stderr)
        sys.exit(1)

    if not emails:
        print("[!] No emails were loaded. Check the input path and supported formats (.eml, .msg, .csv, .zip).")
        sys.exit(1)

    print(f"[*] Loaded {len(emails)} email(s). Running phishing indicator analysis...\n")
    results = analyze_batch(emails)
    results.sort(key=lambda r: -r["risk_score"])

    if not args.quiet:
        for r in results:
            if r["risk_score"] < args.min_score:
                continue
            tier_label = colorize(f"[{r['risk_tier']:8}]", r["risk_tier"])
            print(f"{tier_label} Score: {r['risk_score']:3} | {r['source_file']:30} | {r['subject'][:60]}")
            for ind in r["indicators"][:4]:
                print(f"            - {ind['name']}: {ind['description']}")
            if r["indicator_count"] > 4:
                print(f"            ... and {r['indicator_count'] - 4} more indicator(s)")
            print()

    summary = summarize_batch(results)
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Total emails analyzed : {summary['total_emails']}")
    print(f"Average risk score    : {summary['average_risk_score']}")
    print("Risk tier breakdown   :")
    for tier in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL"]:
        count = summary["tier_breakdown"].get(tier, 0)
        print(f"  {colorize(tier, tier):18} {count}")

    if summary.get("accuracy_vs_labels"):
        acc = summary["accuracy_vs_labels"]
        print(f"Accuracy vs labels    : {acc['correct']}/{acc['labeled_count']} ({acc['accuracy_pct']}%)")

    print()
    paths = write_reports(results, args.output, dataset_name=str(input_path.name))
    print(f"[*] Reports written:")
    for fmt, path in paths.items():
        print(f"    - {fmt}: {path}")


if __name__ == "__main__":
    main()
