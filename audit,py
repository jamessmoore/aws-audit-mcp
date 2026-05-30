import boto3
from typing import List, Dict, Any
from config import AWSCredentials

class EC2Auditor:
    def __init__(self, credentials: AWSCredentials):
        self.client = boto3.client(
            'ec2',
            region_name=credentials.region,
            aws_access_key_id=credentials.access_key_id,
            aws_secret_access_key=credentials.secret_access_key
        )
    
    def audit(self) -> Dict[str, Any]:
        """Run full EC2 audit and return findings."""
        findings = {
            "untagged_instances": self._find_untagged(),
            "public_instances": self._find_public_ips(),
            "security_group_issues": self._audit_security_groups(),
            "summary": {}
        }
        
        findings["summary"] = {
            "total_findings": sum(len(v) if isinstance(v, list) else 0 for v in findings.values() if v != findings["summary"]),
            "critical": self._count_severity(findings, "critical"),
            "high": self._count_severity(findings, "high"),
        }
        
        return findings
    
    def _find_untagged(self) -> List[Dict[str, Any]]:
        """Find EC2 instances without required tags."""
        response = self.client.describe_instances(
            Filters=[{'Name': 'instance-state-name', 'Values': ['running', 'stopped']}]
        )
        
        untagged = []
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                required_tags = ['Name', 'Environment', 'Owner']
                missing = [t for t in required_tags if t not in tags]
                
                if missing:
                    untagged.append({
                        "instance_id": instance['InstanceId'],
                        "missing_tags": missing,
                        "severity": "high",
                        "recommendation": "Add missing tags for compliance and cost tracking"
                    })
        
        return untagged
    
    def _find_public_ips(self) -> List[Dict[str, Any]]:
        """Find instances with public IPs."""
        response = self.client.describe_instances(
            Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
        )
        
        public = []
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                if instance.get('PublicIpAddress'):
                    public.append({
                        "instance_id": instance['InstanceId'],
                        "public_ip": instance['PublicIpAddress'],
                        "severity": "medium",
                        "recommendation": "Review if public IP is necessary; consider NAT or bastion host"
                    })
        
        return public
    
    def _audit_security_groups(self) -> List[Dict[str, Any]]:
        """Find overly permissive security groups."""
        response = self.client.describe_security_groups()
        
        issues = []
        for sg in response['SecurityGroups']:
            for rule in sg.get('IpPermissions', []):
                # Check for 0.0.0.0/0 rules
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        issues.append({
                            "security_group_id": sg['GroupId'],
                            "security_group_name": sg['GroupName'],
                            "issue": f"Allows world access on port {rule.get('FromPort', 'all')}",
                            "severity": "critical" if rule.get('FromPort') in [22, 3389] else "high",
                            "recommendation": "Restrict CIDR to known IPs or use security group references"
                        })
        
        return issues
    
    def _count_severity(self, findings: Dict, severity: str) -> int:
        """Count findings by severity."""
        count = 0
        for key, value in findings.items():
            if isinstance(value, list):
                count += sum(1 for item in value if isinstance(item, dict) and item.get('severity') == severity)
        return count