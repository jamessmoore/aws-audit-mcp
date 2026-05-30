import json
import logging
from mcp.server.fastmcp import FastMCP
from audit import EC2Auditor
from config import AWSCredentials

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

if __name__ == "__main__":
    mcp.run()