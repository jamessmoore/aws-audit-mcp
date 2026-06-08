import json
import logging
from mcp.server.fastmcp import FastMCP
from audit import EC2Auditor
from config import AWSCredentials
from report import generate_markdown_report, generate_pdf_report_b64, generate_html_report

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize MCP server
mcp = FastMCP("aws-audit-mcp")


@mcp.tool()
def audit_ec2(access_key_id: str, secret_access_key: str, region: str) -> str:
    """
    Audit EC2 infrastructure for compliance and security issues.

    Args:
        access_key_id: AWS access key ID
        secret_access_key: AWS secret access key
        region: AWS region (e.g., 'us-east-1')

    Returns:
        JSON string containing audit findings
    """
    try:
        credentials = AWSCredentials(
            access_key_id=access_key_id,
            secret_access_key=secret_access_key,
            region=region
        )

        auditor = EC2Auditor(credentials)
        findings = auditor.audit()

        logger.info(f"Audit complete for region {region}. Found {findings['summary']['total_findings']} issues.")
        return json.dumps(findings, indent=2, default=str)

    except Exception as e:
        logger.error(f"Audit failed: {str(e)}")
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
def generate_report(
    audit_json: str,
    format: str = "markdown",
    region: str = "unknown",
    account_id: str = "N/A",
) -> str:
    """
    Generate a formatted audit report from the JSON output of audit_ec2.

    Accepts the raw JSON string returned by audit_ec2 and renders it as a
    client-ready report. Markdown is returned as a string. PDF is returned
    as a base64-encoded string that can be decoded and written to disk.

    Args:
        audit_json:  JSON string from audit_ec2 (pass the output directly)
        format:      Output format — "markdown", "html", or "pdf"
                     markdown → returns Markdown string
                     html     → returns HTML string (useful for preview/embedding)
                     pdf      → returns base64-encoded PDF bytes
        region:      AWS region that was audited (for report header)
        account_id:  AWS account ID or alias (for report header, optional)

    Returns:
        Formatted report string (Markdown/HTML) or base64-encoded PDF.
        For PDF: decode with base64.b64decode(result) and write to a .pdf file.

    Example workflow in Claude Desktop:
        1. Call audit_ec2 → get JSON findings
        2. Call generate_report(audit_json=<that JSON>, format="pdf", region="us-east-1")
        3. Save the decoded PDF as aws-audit-report-2026-06.pdf
    """
    try:
        findings = json.loads(audit_json)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"Invalid audit_json — could not parse: {str(e)}"})

    fmt = format.lower().strip()

    try:
        if fmt == "markdown":
            return generate_markdown_report(findings, region=region, account_id=account_id)

        elif fmt == "html":
            return generate_html_report(findings, region=region, account_id=account_id)

        elif fmt == "pdf":
            logger.info(f"Generating PDF report for region={region}, account={account_id}")
            b64 = generate_pdf_report_b64(findings, region=region, account_id=account_id)
            return json.dumps({
                "format":   "pdf",
                "encoding": "base64",
                "data":     b64,
                "hint":     "Decode with: import base64; open('report.pdf','wb').write(base64.b64decode(data))"
            })

        else:
            return json.dumps({
                "error": f"Unknown format '{format}'. Supported: markdown, html, pdf"
            })

    except ImportError as e:
        # WeasyPrint not installed — return Markdown as fallback with instructions
        logger.warning(f"PDF generation unavailable: {e}")
        md = generate_markdown_report(findings, region=region, account_id=account_id)
        return json.dumps({
            "warning":  str(e),
            "fallback": "markdown",
            "report":   md,
        })

    except Exception as e:
        logger.error(f"Report generation failed: {str(e)}")
        return json.dumps({"error": str(e)})


if __name__ == "__main__":
    mcp.run()
