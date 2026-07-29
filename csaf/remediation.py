"""Remediation guidance keyed by control ID."""

from __future__ import annotations

REMEDIATION = {
    "CSAF-AWS-IAM-001": "Enable a hardware or virtual MFA device on the root user and store it securely offline.",
    "CSAF-AWS-IAM-002": "Delete all root access keys; use IAM roles or federated identities for programmatic access.",
    "CSAF-AWS-IAM-003": "Stop using the root user for routine tasks; delegate to least-privilege IAM roles.",
    "CSAF-AWS-IAM-004": "Set an account password policy requiring length >= 14 with complexity and reuse prevention.",
    "CSAF-AWS-IAM-005": "Require MFA for every IAM user with console access; enforce with an MFA-conditional policy.",
    "CSAF-AWS-IAM-006": "Rotate active access keys on a schedule (<= 90 days) and remove keys that are no longer needed.",
    "CSAF-AWS-IAM-007": "Disable or delete passwords and access keys unused beyond the inactivity threshold.",
    "CSAF-AWS-IAM-008": "Replace Action:* / Resource:* grants with least-privilege, service-scoped policies.",
    "CSAF-AWS-IAM-009": "Create an IAM Access Analyzer analyzer at the account or organization level and triage findings.",
    "CSAF-AWS-IAM-010": "Remove privilege-escalation-enabling permissions from non-admin principals; add permission boundaries.",
    "CSAF-AWS-S3-001": "Enable all four account-level S3 Block Public Access settings.",
    "CSAF-AWS-S3-002": "Remove public bucket policies/ACLs and enable Block Public Access on affected buckets.",
    "CSAF-AWS-S3-003": "Enable default SSE-KMS or SSE-S3 encryption on every bucket.",
    "CSAF-AWS-S3-004": "Add a bucket policy statement denying requests where aws:SecureTransport is false.",
    "CSAF-AWS-EC2-001": "Set instance metadata options to HttpTokens=required to enforce IMDSv2.",
    "CSAF-AWS-EC2-002": "Enable EBS encryption by default in each region.",
    "CSAF-AWS-EC2-003": "Restrict security groups on public instances and remove admin-port exposure to 0.0.0.0/0.",
    "CSAF-AWS-NET-001": "Restrict security-group ingress for ports 22/3389 to known management CIDRs or a bastion.",
    "CSAF-AWS-NET-002": "Remove all inbound and outbound rules from every default security group.",
    "CSAF-AWS-NET-003": "Enable VPC flow logs to CloudWatch Logs or S3 for every VPC in scope.",
    "CSAF-AWS-LOG-001": "Create a multi-region CloudTrail trail that is enabled and logging.",
    "CSAF-AWS-LOG-002": "Enable log file validation on all CloudTrail trails.",
    "CSAF-AWS-LOG-003": "Configure CloudTrail to encrypt log files with a customer-managed KMS key.",
    "CSAF-AWS-LOG-004": "Enable AWS Config recording in each region with an appropriate delivery channel.",
    "CSAF-AWS-LOG-005": "Enable Amazon GuardDuty in every region and route findings to your SIEM.",
    "CSAF-AWS-KMS-001": "Enable automatic annual rotation on customer-managed symmetric KMS keys.",
    "CSAF-AWS-RDS-001": "Recreate or snapshot-restore RDS instances with storage encryption enabled.",
    "CSAF-AWS-RDS-002": "Set PubliclyAccessible=false and place RDS instances in private subnets.",
    "CSAF-AWS-OPS-001": "Document and periodically test a break-glass procedure for root and privileged access.",
}


def remediation_for(control_id: str) -> str:
    return REMEDIATION.get(control_id, "Review the control expectation and align the configuration accordingly.")
