# AWS Audit MCP Server

An MCP server that audits your AWS EC2 infrastructure for compliance and security issues.

## Quick Start

### Build and Run

```bash
docker build -t aws-audit-mcp .
docker run -p 5000:5000 aws-audit-mcp
```

### Usage with Claude

Call the `audit_ec2` tool with your AWS credentials:

```json
{
  "access_key_id": "YOUR_KEY",
  "secret_access_key": "YOUR_SECRET",
  "region": "us-east-1"
}
```

## Audit Checks (EC2)

- Untagged instances (missing Name, Environment, Owner)
- Public IP assignments
- Overly permissive security groups (0.0.0.0/0 access)

## Future Expansions

- RDS audit
- S3 audit
- Cost anomaly detection
- Cross-account role assumption
- Lambda function deployment