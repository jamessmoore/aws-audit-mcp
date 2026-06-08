"""
report.py — Audit report generator for aws-audit-mcp.

Accepts the raw findings dict produced by EC2Auditor.audit() and renders
it as either a Markdown string or a PDF (via WeasyPrint HTML→PDF pipeline).

Usage:
    from report import generate_markdown_report, generate_pdf_report

    findings = json.loads(audit_ec2_result)
    md  = generate_markdown_report(findings, region="us-east-1")
    pdf = generate_pdf_report(findings, region="us-east-1")   # returns bytes
"""

import json
import base64
from datetime import datetime, timezone
from typing import Any

# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢",
    "info":     "⚪",
}
SEVERITY_COLOR = {
    "critical": "#c0392b",
    "high":     "#e67e22",
    "medium":   "#f1c40f",
    "low":      "#27ae60",
    "info":     "#95a5a6",
}


def _all_findings(findings: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten all findings from all check categories into a single sorted list."""
    flat = []

    for item in findings.get("untagged_instances", []):
        flat.append({
            "check":          "Untagged Instance",
            "resource_id":    item["instance_id"],
            "severity":       item["severity"],
            "issue":          f"Missing required tags: {', '.join(item['missing_tags'])}",
            "recommendation": item["recommendation"],
        })

    for item in findings.get("public_instances", []):
        flat.append({
            "check":          "Public IP Assigned",
            "resource_id":    item["instance_id"],
            "severity":       item["severity"],
            "issue":          f"Instance has public IP: {item['public_ip']}",
            "recommendation": item["recommendation"],
        })

    for item in findings.get("security_group_issues", []):
        flat.append({
            "check":          "Permissive Security Group",
            "resource_id":    item["security_group_id"],
            "severity":       item["severity"],
            "issue":          f"{item['issue']} (SG: {item['security_group_name']})",
            "recommendation": item["recommendation"],
        })

    flat.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))
    return flat


def _risk_posture(summary: dict[str, Any]) -> tuple[str, str]:
    """Return (label, color) based on finding counts."""
    if summary.get("critical", 0) > 0:
        return "CRITICAL RISK", "#c0392b"
    elif summary.get("high", 0) > 0:
        return "HIGH RISK", "#e67e22"
    elif summary.get("total_findings", 0) > 0:
        return "MODERATE RISK", "#f1c40f"
    else:
        return "CLEAN", "#27ae60"


def _executive_summary(findings: dict[str, Any], region: str) -> str:
    """Generate a plain-English 2-3 sentence executive summary."""
    summary    = findings.get("summary", {})
    total      = summary.get("total_findings", 0)
    critical   = summary.get("critical", 0)
    high       = summary.get("high", 0)
    untagged   = len(findings.get("untagged_instances", []))
    public_ips = len(findings.get("public_instances", []))
    sg_issues  = len(findings.get("security_group_issues", []))

    if total == 0:
        return (
            f"The EC2 audit of region **{region}** returned no findings. "
            "All scanned instances are tagged correctly, have no unnecessary public IPs, "
            "and all security groups restrict inbound access appropriately. "
            "No immediate action is required."
        )

    parts = []
    if untagged:
        parts.append(f"{untagged} untagged instance{'s' if untagged > 1 else ''}")
    if public_ips:
        parts.append(f"{public_ips} instance{'s' if public_ips > 1 else ''} with public IPs")
    if sg_issues:
        parts.append(f"{sg_issues} overly permissive security group rule{'s' if sg_issues > 1 else ''}")

    finding_list = ", ".join(parts[:-1]) + (" and " if len(parts) > 1 else "") + parts[-1]

    urgency = ""
    if critical > 0:
        urgency = (
            f"**{critical} critical finding{'s' if critical > 1 else ''} require immediate remediation** — "
            "open SSH or RDP access from the internet represents active attack surface. "
        )
    elif high > 0:
        urgency = (
            f"**{high} high-severity finding{'s' if high > 1 else ''} should be addressed within 24–48 hours.** "
        )

    return (
        f"The EC2 audit of region **{region}** identified **{total} finding{'s' if total > 1 else ''}** "
        f"across the following categories: {finding_list}. "
        f"{urgency}"
        "Full details and remediation steps are provided in the findings section below."
    )


# ---------------------------------------------------------------------------
# Markdown renderer
# ---------------------------------------------------------------------------

def generate_markdown_report(
    findings: dict[str, Any],
    region: str = "unknown",
    account_id: str = "N/A",
) -> str:
    """
    Render audit findings as a Markdown string suitable for sharing as a
    GitHub Gist, Confluence page, Notion doc, or email attachment.
    """
    now         = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    all_items   = _all_findings(findings)
    summary     = findings.get("summary", {})
    total       = summary.get("total_findings", 0)
    risk_label, _ = _risk_posture(summary)

    lines = []

    # --- Header ---
    lines += [
        "# AWS Infrastructure Audit Report",
        "",
        f"| Field | Value |",
        f"|---|---|",
        f"| **Account** | {account_id} |",
        f"| **Region** | {region} |",
        f"| **Scan Date** | {now} |",
        f"| **Overall Risk** | {risk_label} |",
        f"| **Total Findings** | {total} |",
        f"| **Critical** | {summary.get('critical', 0)} |",
        f"| **High** | {summary.get('high', 0)} |",
        "",
        "---",
        "",
    ]

    # --- Executive Summary ---
    lines += [
        "## Executive Summary",
        "",
        _executive_summary(findings, region),
        "",
        "---",
        "",
    ]

    # --- Findings Table ---
    if all_items:
        lines += [
            "## Findings",
            "",
            "| Severity | Check | Resource ID | Issue |",
            "|---|---|---|---|",
        ]
        for item in all_items:
            sev   = item["severity"].upper()
            emoji = SEVERITY_EMOJI.get(item["severity"], "")
            lines.append(
                f"| {emoji} {sev} | {item['check']} | `{item['resource_id']}` | {item['issue']} |"
            )
        lines += ["", "---", ""]

    # --- Finding Details ---
    if all_items:
        lines += ["## Finding Details", ""]
        for i, item in enumerate(all_items, start=1):
            emoji = SEVERITY_EMOJI.get(item["severity"], "")
            lines += [
                f"### {i}. {emoji} {item['check']} — `{item['resource_id']}`",
                "",
                f"**Severity:** {item['severity'].upper()}  ",
                f"**Resource:** `{item['resource_id']}`  ",
                f"**Issue:** {item['issue']}  ",
                f"**Recommendation:** {item['recommendation']}",
                "",
            ]
        lines += ["---", ""]

    # --- Footer ---
    lines += [
        "*Report generated by [aws-audit-mcp](https://github.com/jamessmoore/aws-audit-mcp) "
        "— WebTech HQ | [webtechhq.com](https://webtechhq.com)*",
        "",
    ]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTML renderer (used by both PDF pipeline and standalone HTML export)
# ---------------------------------------------------------------------------

def generate_html_report(
    findings: dict[str, Any],
    region: str = "unknown",
    account_id: str = "N/A",
) -> str:
    """
    Render audit findings as a self-contained HTML string.
    Designed for WeasyPrint PDF conversion — no external assets.
    """
    now           = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    all_items     = _all_findings(findings)
    summary       = findings.get("summary", {})
    total         = summary.get("total_findings", 0)
    risk_label, risk_color = _risk_posture(summary)
    exec_summary  = _executive_summary(findings, region)

    def badge(severity: str) -> str:
        color = SEVERITY_COLOR.get(severity, "#95a5a6")
        return (
            f'<span style="background:{color};color:white;padding:2px 8px;'
            f'border-radius:3px;font-size:11px;font-weight:bold;'
            f'text-transform:uppercase;">{severity}</span>'
        )

    # --- Finding detail cards ---
    detail_html = ""
    if all_items:
        cards = []
        for i, item in enumerate(all_items, start=1):
            border_color = SEVERITY_COLOR.get(item["severity"], "#ccc")
            cards.append(f"""
            <div style="border-left:4px solid {border_color};padding:12px 16px;
                        margin-bottom:16px;background:#fafafa;border-radius:0 4px 4px 0;">
              <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">
                <span style="font-weight:bold;color:#333;">#{i} — {item['check']}</span>
                {badge(item['severity'])}
              </div>
              <table style="border-collapse:collapse;width:100%;font-size:13px;">
                <tr><td style="padding:3px 8px 3px 0;color:#666;width:140px;">Resource</td>
                    <td style="font-family:monospace;color:#333;">{item['resource_id']}</td></tr>
                <tr><td style="padding:3px 8px 3px 0;color:#666;">Issue</td>
                    <td style="color:#333;">{item['issue']}</td></tr>
                <tr><td style="padding:3px 8px 3px 0;color:#666;">Recommendation</td>
                    <td style="color:#333;">{item['recommendation']}</td></tr>
              </table>
            </div>""")
        detail_html = "\n".join(cards)

    # --- Summary table rows ---
    table_rows = ""
    if all_items:
        for item in all_items:
            table_rows += f"""
            <tr>
              <td style="padding:8px 12px;">{badge(item['severity'])}</td>
              <td style="padding:8px 12px;">{item['check']}</td>
              <td style="padding:8px 12px;font-family:monospace;font-size:12px;">{item['resource_id']}</td>
              <td style="padding:8px 12px;font-size:13px;">{item['issue']}</td>
            </tr>"""

    # Replace markdown bold with <strong> in exec summary for HTML output
    exec_html = exec_summary.replace("**", "<strong>", 1)
    while "**" in exec_html:
        exec_html = exec_html.replace("**", "</strong>", 1).replace("**", "<strong>", 1) \
            if exec_html.count("**") >= 2 else exec_html.replace("**", "")

    findings_section = ""
    if all_items:
        findings_section = f"""
        <h2 style="color:#2c3e50;border-bottom:2px solid #eee;padding-bottom:6px;">Findings Summary</h2>
        <table style="width:100%;border-collapse:collapse;margin-bottom:32px;font-size:13px;">
          <thead>
            <tr style="background:#f0f0f0;">
              <th style="padding:8px 12px;text-align:left;">Severity</th>
              <th style="padding:8px 12px;text-align:left;">Check</th>
              <th style="padding:8px 12px;text-align:left;">Resource ID</th>
              <th style="padding:8px 12px;text-align:left;">Issue</th>
            </tr>
          </thead>
          <tbody>{table_rows}</tbody>
        </table>

        <h2 style="color:#2c3e50;border-bottom:2px solid #eee;padding-bottom:6px;">Finding Details</h2>
        {detail_html}
        """
    else:
        findings_section = """
        <div style="background:#d5f5e3;border:1px solid #27ae60;border-radius:4px;padding:16px;
                    text-align:center;color:#1e8449;font-weight:bold;font-size:15px;">
          ✅ No findings — this environment is clean.
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <style>
    @page {{ margin: 20mm 18mm; }}
    body {{ font-family: Arial, Helvetica, sans-serif; color: #2c3e50;
           font-size: 13px; line-height: 1.5; margin: 0; padding: 0; }}
    h1   {{ color: #1a252f; font-size: 22px; margin-bottom: 4px; }}
    h2   {{ font-size: 16px; }}
    table {{ font-size: 13px; }}
  </style>
</head>
<body>

  <!-- Cover block -->
  <div style="border-bottom:3px solid #2c3e50;padding-bottom:16px;margin-bottom:24px;">
    <h1>AWS Infrastructure Audit Report</h1>
    <table style="border-collapse:collapse;margin-top:10px;">
      <tr>
        <td style="padding:3px 24px 3px 0;color:#666;">Account</td>
        <td style="font-weight:bold;">{account_id}</td>
      </tr>
      <tr>
        <td style="padding:3px 24px 3px 0;color:#666;">Region</td>
        <td style="font-weight:bold;">{region}</td>
      </tr>
      <tr>
        <td style="padding:3px 24px 3px 0;color:#666;">Scan Date</td>
        <td style="font-weight:bold;">{now}</td>
      </tr>
      <tr>
        <td style="padding:3px 24px 3px 0;color:#666;">Total Findings</td>
        <td style="font-weight:bold;">{total}</td>
      </tr>
      <tr>
        <td style="padding:3px 24px 3px 0;color:#666;">Overall Risk</td>
        <td>
          <span style="background:{risk_color};color:white;padding:3px 10px;
                       border-radius:3px;font-weight:bold;font-size:12px;">
            {risk_label}
          </span>
        </td>
      </tr>
    </table>
  </div>

  <!-- Executive Summary -->
  <h2 style="color:#2c3e50;border-bottom:2px solid #eee;padding-bottom:6px;">Executive Summary</h2>
  <p style="margin-bottom:24px;">{exec_html}</p>

  <!-- Severity counters -->
  <div style="display:flex;gap:12px;margin-bottom:32px;">
    <div style="flex:1;background:#fdf2f2;border:1px solid #e74c3c;border-radius:4px;
                padding:12px;text-align:center;">
      <div style="font-size:28px;font-weight:bold;color:#c0392b;">{summary.get('critical', 0)}</div>
      <div style="font-size:11px;color:#c0392b;font-weight:bold;text-transform:uppercase;">Critical</div>
    </div>
    <div style="flex:1;background:#fef9f0;border:1px solid #e67e22;border-radius:4px;
                padding:12px;text-align:center;">
      <div style="font-size:28px;font-weight:bold;color:#e67e22;">{summary.get('high', 0)}</div>
      <div style="font-size:11px;color:#e67e22;font-weight:bold;text-transform:uppercase;">High</div>
    </div>
    <div style="flex:1;background:#fefdf0;border:1px solid #f1c40f;border-radius:4px;
                padding:12px;text-align:center;">
      <div style="font-size:28px;font-weight:bold;color:#d4ac0d;">{summary.get('medium', 0) if 'medium' in summary else len([f for f in all_items if f['severity'] == 'medium'])}</div>
      <div style="font-size:11px;color:#d4ac0d;font-weight:bold;text-transform:uppercase;">Medium</div>
    </div>
    <div style="flex:1;background:#f0fdf4;border:1px solid #27ae60;border-radius:4px;
                padding:12px;text-align:center;">
      <div style="font-size:28px;font-weight:bold;color:#27ae60;">{total}</div>
      <div style="font-size:11px;color:#27ae60;font-weight:bold;text-transform:uppercase;">Total</div>
    </div>
  </div>

  {findings_section}

  <!-- Footer -->
  <div style="border-top:1px solid #eee;margin-top:40px;padding-top:12px;
              font-size:11px;color:#999;text-align:center;">
    Generated by aws-audit-mcp &mdash; WebTech HQ | webtechhq.com
  </div>

</body>
</html>"""


# ---------------------------------------------------------------------------
# PDF renderer
# ---------------------------------------------------------------------------

def generate_pdf_report(
    findings: dict[str, Any],
    region: str = "unknown",
    account_id: str = "N/A",
) -> bytes:
    """
    Render audit findings as PDF bytes using WeasyPrint.
    Raises ImportError with a helpful message if WeasyPrint is not installed.
    """
    try:
        from weasyprint import HTML
    except ImportError:
        raise ImportError(
            "WeasyPrint is required for PDF generation. "
            "Install it with: pip install weasyprint\n"
            "System dependencies (Debian/Ubuntu): "
            "apt-get install -y libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b"
        )

    html_content = generate_html_report(findings, region=region, account_id=account_id)
    return HTML(string=html_content).write_pdf()


# ---------------------------------------------------------------------------
# Convenience: encode PDF to base64 for MCP tool return
# ---------------------------------------------------------------------------

def generate_pdf_report_b64(
    findings: dict[str, Any],
    region: str = "unknown",
    account_id: str = "N/A",
) -> str:
    """
    Returns PDF as a base64-encoded string suitable for returning from an MCP tool.
    Callers can decode and write to disk: open('report.pdf','wb').write(base64.b64decode(result))
    """
    pdf_bytes = generate_pdf_report(findings, region=region, account_id=account_id)
    return base64.b64encode(pdf_bytes).decode("utf-8")
