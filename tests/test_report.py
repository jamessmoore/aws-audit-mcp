"""
tests/test_report.py — Unit tests for report.py

Tests run against synthetic findings dicts — no AWS credentials required.
Run with: pytest tests/test_report.py -v
"""

import json
import base64
import pytest
from report import (
    generate_markdown_report,
    generate_html_report,
    _all_findings,
    _risk_posture,
    _executive_summary,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def findings_with_all_issues():
    """Findings that exercise every check category and severity level."""
    return {
        "untagged_instances": [
            {
                "instance_id":    "i-0abc123def456001",
                "missing_tags":   ["Name", "Environment", "Owner"],
                "severity":       "high",
                "recommendation": "Add missing tags for compliance and cost tracking",
            }
        ],
        "public_instances": [
            {
                "instance_id":    "i-0abc123def456002",
                "public_ip":      "54.12.34.56",
                "severity":       "medium",
                "recommendation": "Review if public IP is necessary; consider NAT or bastion host",
            }
        ],
        "security_group_issues": [
            {
                "security_group_id":   "sg-0critical001",
                "security_group_name": "open-sg",
                "issue":               "Allows world access on port 22",
                "severity":            "critical",
                "recommendation":      "Restrict CIDR to known IPs or use security group references",
            },
            {
                "security_group_id":   "sg-0high001",
                "security_group_name": "open-sg",
                "issue":               "Allows world access on port 443",
                "severity":            "high",
                "recommendation":      "Restrict CIDR to known IPs or use security group references",
            },
        ],
        "summary": {
            "total_findings": 4,
            "critical":       1,
            "high":           2,
        },
    }


@pytest.fixture
def findings_clean():
    """Findings dict representing a fully compliant environment."""
    return {
        "untagged_instances":  [],
        "public_instances":    [],
        "security_group_issues": [],
        "summary": {
            "total_findings": 0,
            "critical":       0,
            "high":           0,
        },
    }


@pytest.fixture
def findings_high_only():
    """Findings with only high severity — no criticals."""
    return {
        "untagged_instances": [
            {
                "instance_id":    "i-0abc123def456010",
                "missing_tags":   ["Owner"],
                "severity":       "high",
                "recommendation": "Add missing tags for compliance and cost tracking",
            }
        ],
        "public_instances":      [],
        "security_group_issues": [],
        "summary": {
            "total_findings": 1,
            "critical":       0,
            "high":           1,
        },
    }


# ---------------------------------------------------------------------------
# _all_findings
# ---------------------------------------------------------------------------

class TestAllFindings:
    def test_flattens_all_categories(self, findings_with_all_issues):
        flat = _all_findings(findings_with_all_issues)
        assert len(flat) == 4

    def test_sorted_critical_first(self, findings_with_all_issues):
        flat = _all_findings(findings_with_all_issues)
        assert flat[0]["severity"] == "critical"

    def test_medium_after_high(self, findings_with_all_issues):
        flat = _all_findings(findings_with_all_issues)
        severities = [f["severity"] for f in flat]
        assert severities.index("medium") > severities.index("high")

    def test_empty_findings_returns_empty_list(self, findings_clean):
        assert _all_findings(findings_clean) == []

    def test_resource_ids_preserved(self, findings_with_all_issues):
        flat = _all_findings(findings_with_all_issues)
        resource_ids = {f["resource_id"] for f in flat}
        assert "i-0abc123def456001" in resource_ids
        assert "i-0abc123def456002" in resource_ids
        assert "sg-0critical001" in resource_ids


# ---------------------------------------------------------------------------
# _risk_posture
# ---------------------------------------------------------------------------

class TestRiskPosture:
    def test_critical_risk_when_critical_findings(self, findings_with_all_issues):
        label, color = _risk_posture(findings_with_all_issues["summary"])
        assert label == "CRITICAL RISK"
        assert color == "#c0392b"

    def test_high_risk_when_high_no_critical(self, findings_high_only):
        label, color = _risk_posture(findings_high_only["summary"])
        assert label == "HIGH RISK"
        assert color == "#e67e22"

    def test_clean_when_no_findings(self, findings_clean):
        label, color = _risk_posture(findings_clean["summary"])
        assert label == "CLEAN"
        assert color == "#27ae60"


# ---------------------------------------------------------------------------
# _executive_summary
# ---------------------------------------------------------------------------

class TestExecutiveSummary:
    def test_clean_summary_mentions_no_findings(self, findings_clean):
        summary = _executive_summary(findings_clean, region="us-east-1")
        assert "no findings" in summary.lower()
        assert "us-east-1" in summary

    def test_critical_summary_mentions_immediate_remediation(self, findings_with_all_issues):
        summary = _executive_summary(findings_with_all_issues, region="us-east-1")
        assert "immediate" in summary.lower()

    def test_summary_mentions_region(self, findings_with_all_issues):
        summary = _executive_summary(findings_with_all_issues, region="eu-west-2")
        assert "eu-west-2" in summary

    def test_summary_mentions_total_count(self, findings_with_all_issues):
        summary = _executive_summary(findings_with_all_issues, region="us-east-1")
        assert "4" in summary


# ---------------------------------------------------------------------------
# generate_markdown_report
# ---------------------------------------------------------------------------

class TestMarkdownReport:
    def test_returns_string(self, findings_with_all_issues):
        result = generate_markdown_report(findings_with_all_issues, region="us-east-1")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_contains_report_title(self, findings_with_all_issues):
        md = generate_markdown_report(findings_with_all_issues, region="us-east-1")
        assert "AWS Infrastructure Audit Report" in md

    def test_contains_region(self, findings_with_all_issues):
        md = generate_markdown_report(findings_with_all_issues, region="ap-southeast-1")
        assert "ap-southeast-1" in md

    def test_contains_account_id(self, findings_with_all_issues):
        md = generate_markdown_report(
            findings_with_all_issues, region="us-east-1", account_id="123456789012"
        )
        assert "123456789012" in md

    def test_contains_all_instance_ids(self, findings_with_all_issues):
        md = generate_markdown_report(findings_with_all_issues, region="us-east-1")
        assert "i-0abc123def456001" in md
        assert "i-0abc123def456002" in md
        assert "sg-0critical001" in md

    def test_contains_severity_labels(self, findings_with_all_issues):
        md = generate_markdown_report(findings_with_all_issues, region="us-east-1")
        assert "CRITICAL" in md
        assert "HIGH" in md
        assert "MEDIUM" in md

    def test_clean_report_no_findings_table(self, findings_clean):
        md = generate_markdown_report(findings_clean, region="us-east-1")
        # Clean report should not have a findings table header
        assert "| Severity |" not in md

    def test_clean_report_mentions_clean(self, findings_clean):
        md = generate_markdown_report(findings_clean, region="us-east-1")
        assert "no findings" in md.lower() or "clean" in md.lower()

    def test_contains_webtechhq_branding(self, findings_with_all_issues):
        md = generate_markdown_report(findings_with_all_issues, region="us-east-1")
        assert "webtechhq.com" in md

    def test_finding_details_section_present(self, findings_with_all_issues):
        md = generate_markdown_report(findings_with_all_issues, region="us-east-1")
        assert "Finding Details" in md

    def test_recommendations_included(self, findings_with_all_issues):
        md = generate_markdown_report(findings_with_all_issues, region="us-east-1")
        assert "Restrict CIDR" in md


# ---------------------------------------------------------------------------
# generate_html_report
# ---------------------------------------------------------------------------

class TestHtmlReport:
    def test_returns_valid_html_string(self, findings_with_all_issues):
        html = generate_html_report(findings_with_all_issues, region="us-east-1")
        assert html.strip().startswith("<!DOCTYPE html>")
        assert "</html>" in html

    def test_contains_region(self, findings_with_all_issues):
        html = generate_html_report(findings_with_all_issues, region="us-west-2")
        assert "us-west-2" in html

    def test_contains_critical_color(self, findings_with_all_issues):
        html = generate_html_report(findings_with_all_issues, region="us-east-1")
        assert "#c0392b" in html  # critical red

    def test_clean_html_shows_clean_message(self, findings_clean):
        html = generate_html_report(findings_clean, region="us-east-1")
        assert "clean" in html.lower()

    def test_contains_all_resource_ids(self, findings_with_all_issues):
        html = generate_html_report(findings_with_all_issues, region="us-east-1")
        assert "i-0abc123def456001" in html
        assert "sg-0critical001" in html

    def test_weasyprint_page_rule_present(self, findings_with_all_issues):
        html = generate_html_report(findings_with_all_issues, region="us-east-1")
        assert "@page" in html

    def test_severity_counter_tiles_present(self, findings_with_all_issues):
        html = generate_html_report(findings_with_all_issues, region="us-east-1")
        assert "Critical" in html
        assert "High" in html


# ---------------------------------------------------------------------------
# generate_report MCP tool integration (tests main.py tool logic inline)
# ---------------------------------------------------------------------------

class TestGenerateReportTool:
    """
    Tests the report dispatch logic from main.py without spinning up the
    full MCP server. Import and call the handler function directly.
    """

    def _call_tool(self, audit_json: str, format: str, region: str = "us-east-1"):
        """Replicates the generate_report tool body for direct testing."""
        from report import generate_markdown_report, generate_html_report, generate_pdf_report_b64
        try:
            findings = json.loads(audit_json)
        except json.JSONDecodeError as e:
            return json.dumps({"error": f"Invalid audit_json: {str(e)}"})

        fmt = format.lower().strip()
        if fmt == "markdown":
            return generate_markdown_report(findings, region=region)
        elif fmt == "html":
            return generate_html_report(findings, region=region)
        elif fmt == "pdf":
            try:
                b64 = generate_pdf_report_b64(findings, region=region)
                return json.dumps({"format": "pdf", "encoding": "base64", "data": b64})
            except ImportError as e:
                md = generate_markdown_report(findings, region=region)
                return json.dumps({"warning": str(e), "fallback": "markdown", "report": md})
        else:
            return json.dumps({"error": f"Unknown format '{format}'"})

    def test_markdown_format_returns_string(self, findings_with_all_issues):
        audit_json = json.dumps(findings_with_all_issues)
        result = self._call_tool(audit_json, "markdown")
        assert "AWS Infrastructure Audit Report" in result

    def test_html_format_returns_html(self, findings_with_all_issues):
        audit_json = json.dumps(findings_with_all_issues)
        result = self._call_tool(audit_json, "html")
        assert "<!DOCTYPE html>" in result

    def test_invalid_json_returns_error(self):
        result = self._call_tool("this is not json", "markdown")
        parsed = json.loads(result)
        assert "error" in parsed

    def test_unknown_format_returns_error(self, findings_with_all_issues):
        audit_json = json.dumps(findings_with_all_issues)
        result = self._call_tool(audit_json, "excel")
        parsed = json.loads(result)
        assert "error" in parsed

    def test_pdf_returns_base64_or_fallback(self, findings_with_all_issues):
        audit_json = json.dumps(findings_with_all_issues)
        result = self._call_tool(audit_json, "pdf")
        parsed = json.loads(result)
        # Either PDF succeeded with base64 data, or WeasyPrint unavailable with markdown fallback
        assert "data" in parsed or "fallback" in parsed

    def test_pdf_base64_decodes_to_bytes(self, findings_with_all_issues):
        audit_json = json.dumps(findings_with_all_issues)
        result = self._call_tool(audit_json, "pdf")
        parsed = json.loads(result)
        if "data" in parsed:
            decoded = base64.b64decode(parsed["data"])
            assert len(decoded) > 0
            # PDF magic bytes
            assert decoded[:4] == b"%PDF"
