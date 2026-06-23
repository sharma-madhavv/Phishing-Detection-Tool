"""
app.py
------
Streamlit dashboard for the Phishing Email Detection Tool.

Run with:
    streamlit run app.py
"""

import sys
import tempfile
from pathlib import Path
from collections import Counter

import streamlit as st
import pandas as pd

sys.path.insert(0, str(Path(__file__).parent))

from detector.dataset_loader import load_from_bytes, load_dataset
from detector.risk_scorer import analyze_batch
from detector.report_generator import summarize_batch, generate_markdown_report

st.set_page_config(
    page_title="Phishing Email Detection Tool",
    page_icon="🛡️",
    layout="wide",
)

TIER_COLORS = {
    "CRITICAL": "#7f1d1d",
    "HIGH": "#dc2626",
    "MEDIUM": "#d97706",
    "LOW": "#2563eb",
    "MINIMAL": "#16a34a",
}


def tier_badge(tier):
    color = TIER_COLORS.get(tier, "#888")
    return f'<span style="background-color:{color};color:white;padding:3px 10px;border-radius:6px;font-weight:600;font-size:0.85em;">{tier}</span>'


def main():
    st.title("🛡️ Phishing Email Detection Tool")
    st.caption("Header + body analysis for phishing indicator detection, risk scoring, and reporting.")

    if "results" not in st.session_state:
        st.session_state.results = None
        st.session_state.dataset_name = ""

    with st.sidebar:
        st.header("📥 Load Dataset")
        mode = st.radio("Input method", ["Upload files", "Server path"], index=0)

        emails = None

        if mode == "Upload files":
            uploaded = st.file_uploader(
                "Upload .eml, .msg, .csv, or .zip file(s)",
                type=["eml", "msg", "csv", "zip"],
                accept_multiple_files=True,
            )
            if uploaded and st.button("Analyze uploaded files", type="primary"):
                emails = []
                progress = st.progress(0, text="Parsing files...")
                for i, file in enumerate(uploaded):
                    try:
                        emails.extend(load_from_bytes(file.name, file.getvalue()))
                    except Exception as e:
                        st.warning(f"Skipped {file.name}: {e}")
                    progress.progress((i + 1) / len(uploaded))
                progress.empty()
                st.session_state.dataset_name = f"{len(uploaded)} uploaded file(s)"

        else:
            server_path = st.text_input(
                "Path on server (file, folder, or zip)",
                value="data/sample_emails",
                help="Path relative to where the app is running, e.g. data/sample_emails"
            )
            if st.button("Analyze server path", type="primary"):
                try:
                    emails = load_dataset(server_path)
                    st.session_state.dataset_name = server_path
                except Exception as e:
                    st.error(f"Failed to load: {e}")

        if emails is not None:
            if not emails:
                st.warning("No emails could be parsed from the input.")
            else:
                with st.spinner(f"Analyzing {len(emails)} email(s)..."):
                    st.session_state.results = analyze_batch(emails)
                st.success(f"Analyzed {len(emails)} email(s).")

        st.divider()
        st.markdown(
            "**Supported formats:** `.eml`, `.msg`, `.csv`, `.zip` (mixed folders supported)\n\n"
            "**CSV columns recognized:** subject, body/text, from/sender, to, label/class, urls"
        )

    results = st.session_state.results

    if not results:
        st.info(
            "👈 Upload email files or point to a dataset path in the sidebar to begin analysis.\n\n"
            "This tool inspects **email headers** (SPF/DKIM/DMARC, Reply-To mismatches), "
            "**sender domains**, **links/URLs**, and **body content** to flag phishing indicators "
            "and compute a 0–100 risk score per email."
        )
        render_guidelines()
        return

    render_dashboard(results)


def render_dashboard(results):
    summary = summarize_batch(results)

    tab1, tab2, tab3, tab4 = st.tabs(
        ["📊 Overview", "📧 Email Explorer", "📄 Report", "🎓 Prevention Guidelines"]
    )

    with tab1:
        render_overview(results, summary)

    with tab2:
        render_explorer(results)

    with tab3:
        render_report(results, summary)

    with tab4:
        render_guidelines()


def render_overview(results, summary):
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Emails", summary["total_emails"])
    c2.metric("Average Risk Score", summary["average_risk_score"])
    high_risk_count = summary["tier_breakdown"].get("CRITICAL", 0) + summary["tier_breakdown"].get("HIGH", 0)
    c3.metric("High/Critical Risk", high_risk_count)
    if summary.get("accuracy_vs_labels"):
        c4.metric("Accuracy vs Labels", f"{summary['accuracy_vs_labels']['accuracy_pct']}%")
    else:
        c4.metric("Labeled Emails", "N/A")

    st.subheader("Risk Tier Distribution")
    tier_df = pd.DataFrame([
        {"Tier": t, "Count": summary["tier_breakdown"].get(t, 0)}
        for t in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL"]
    ])
    st.bar_chart(tier_df.set_index("Tier"))

    col_a, col_b = st.columns(2)
    with col_a:
        st.subheader("Top Phishing Indicators")
        if summary["top_indicators"]:
            ind_df = pd.DataFrame(summary["top_indicators"], columns=["Indicator", "Occurrences"])
            st.dataframe(ind_df, use_container_width=True, hide_index=True)
        else:
            st.write("No indicators triggered across this dataset.")

    with col_b:
        st.subheader("Flags by Category")
        if summary["category_breakdown"]:
            cat_df = pd.DataFrame(
                sorted(summary["category_breakdown"].items(), key=lambda x: -x[1]),
                columns=["Category", "Count"]
            )
            st.dataframe(cat_df, use_container_width=True, hide_index=True)


def render_explorer(results):
    st.subheader("Per-Email Risk Breakdown")

    col1, col2, col3 = st.columns(3)
    with col1:
        tier_filter = st.multiselect(
            "Filter by risk tier",
            ["CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL"],
            default=["CRITICAL", "HIGH"]
        )
    with col2:
        search = st.text_input("Search subject/sender", "")
    with col3:
        sort_desc = st.checkbox("Sort by score (descending)", value=True)

    filtered = results
    if tier_filter:
        filtered = [r for r in filtered if r["risk_tier"] in tier_filter]
    if search:
        s = search.lower()
        filtered = [r for r in filtered if s in r["subject"].lower() or s in r["from"].lower()]
    filtered = sorted(filtered, key=lambda r: -r["risk_score"] if sort_desc else r["risk_score"])

    st.caption(f"Showing {len(filtered)} of {len(results)} email(s)")

    for r in filtered[:200]:
        header = f"{r['risk_score']:>3} | {r['source_file']} — {r['subject'][:70] or '(no subject)'}"
        with st.expander(header):
            st.markdown(tier_badge(r["risk_tier"]), unsafe_allow_html=True)
            colx, coly = st.columns(2)
            with colx:
                st.write(f"**From:** {r['from'] or '(unknown)'}")
                st.write(f"**To:** {r['to'] or '(unknown)'}")
                st.write(f"**Date:** {r['date'] or '(unknown)'}")
            with coly:
                st.write(f"**URLs found:** {r['url_count']}")
                st.write(f"**Attachments:** {r['attachment_count']}")
                if r.get("ground_truth_label"):
                    st.write(f"**Dataset label:** {r['ground_truth_label']}")

            if r["indicators"]:
                st.markdown("**Flagged indicators:**")
                for ind in r["indicators"]:
                    st.markdown(
                        f"- `[{ind['category']}]` **{ind['name']}** (+{ind['weight']}): {ind['description']}"
                        + (f"\n  > Evidence: `{ind['evidence']}`" if ind.get("evidence") else "")
                    )
            else:
                st.write("No indicators triggered — appears low risk based on current heuristics.")

            if r["urls"]:
                st.markdown("**Links found in email:**")
                for u in r["urls"][:10]:
                    st.code(u, language=None)


def render_report(results, summary):
    st.subheader("Findings Report")
    dataset_name = st.session_state.get("dataset_name", "dataset")
    md_report = generate_markdown_report(results, summary, dataset_name)
    st.markdown(md_report)

    st.divider()
    st.download_button(
        "⬇️ Download Markdown Report",
        data=md_report,
        file_name="phishing_report.md",
        mime="text/markdown",
    )

    import json
    st.download_button(
        "⬇️ Download JSON Results",
        data=json.dumps({"summary": summary, "results": results}, indent=2, default=str),
        file_name="phishing_results.json",
        mime="application/json",
    )

    df = pd.DataFrame([{
        "source_file": r["source_file"],
        "subject": r["subject"],
        "from": r["from"],
        "risk_score": r["risk_score"],
        "risk_tier": r["risk_tier"],
        "indicator_count": r["indicator_count"],
        "url_count": r["url_count"],
        "attachment_count": r["attachment_count"],
        "ground_truth_label": r.get("ground_truth_label") or "",
    } for r in results])
    st.download_button(
        "⬇️ Download CSV Results",
        data=df.to_csv(index=False),
        file_name="phishing_results.csv",
        mime="text/csv",
    )


def render_guidelines():
    st.subheader("🎓 Phishing Prevention & Awareness Guidelines")

    st.markdown("""
**For Individuals**
1. **Verify the sender's actual email address**, not just the display name — hover or tap to reveal it.
2. **Don't trust urgency.** Real organizations rarely demand instant action under threat of account closure.
3. **Hover before you click.** Check that link destinations match the real organization's domain.
4. **Never enter credentials via an emailed link.** Navigate to the official site directly instead.
5. **Be wary of generic greetings** ("Dear Customer") on emails claiming to be from a company you have an account with.
6. **Check for lookalike domains** — `paypa1.com`, `arnazon.com`, `secure-paypal-verify.com` are not the real thing.
7. **Don't open unexpected attachments**, especially `.exe`, `.scr`, `.zip`, or macro-enabled Office files.
8. **Report suspicious emails** to your IT/security team rather than just deleting them.

**For Organizations**
1. **Enforce SPF, DKIM, and DMARC** on your domains, and monitor DMARC aggregate reports for abuse.
2. **Deploy email security gateways** with attachment sandboxing and link rewriting/scanning.
3. **Run regular phishing simulation campaigns** to measure and improve employee detection rates.
4. **Maintain a clear, low-friction reporting channel** (e.g. a "Report Phishing" button) and act on reports quickly.
5. **Apply least-privilege access** so a single compromised account has limited blast radius.
6. **Use multi-factor authentication (MFA)** everywhere — it neutralizes most credential-phishing outcomes.
7. **Maintain a domain-monitoring process** to detect typosquatted lookalike domains targeting your brand.
8. **Train employees regularly**, not just once a year — phishing tactics evolve continuously.

**Red Flags Checklist (Quick Reference)**

| Category | Watch For |
|---|---|
| Header | Missing/failed SPF, DKIM, or DMARC; Reply-To ≠ From domain |
| Sender | Display name impersonates a brand; free webmail claiming to be a company; lookalike domains |
| Links | URL shorteners; raw IP links; anchor text that doesn't match the real href; unusual TLDs |
| Body | Urgency/threat language; requests for passwords/SSN/card numbers; generic greetings; prize/lottery bait |
| Attachments | `.exe`, `.scr`, `.js`, `.vbs`; macro-enabled Office docs; double extensions like `invoice.pdf.exe` |

> ⚠️ This tool's risk scores are **heuristic triage signals for awareness and research**, not a
> definitive verdict. Always escalate suspicious emails to a qualified security team.
""")


if __name__ == "__main__":
    main()
