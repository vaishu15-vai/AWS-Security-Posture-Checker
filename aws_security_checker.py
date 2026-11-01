"""Read-only AWS security posture checker.

The checker accepts an AWS access-key CSV exported by IAM, but never writes
credentials to a report. Prefer a least-privilege, short-lived audit user.
"""

from __future__ import annotations

import argparse
import csv
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPORT_FIELDS = ["severity", "service", "resource", "issue", "fix"]
DEFAULT_KEY_FILE = "security-auditor_accessKeys (1).csv"


def load_credentials(path: Path) -> tuple[str, str]:
    """Load the two IAM CSV columns without printing either credential."""
    with path.open(newline="", encoding="utf-8-sig") as file:
        row = next(csv.DictReader(file), None)
    if not row:
        raise ValueError(f"No credential row found in {path}")

    access_key = row.get("Access key ID") or row.get("Access key Id")
    secret_key = row.get("Secret access key")
    if not access_key or not secret_key:
        raise ValueError("CSV must contain Access key ID and Secret access key columns")
    return access_key.strip(), secret_key.strip()


def finding(severity: str, service: str, resource: str, issue: str, fix: str) -> dict[str, str]:
    return {
        "severity": severity,
        "service": service,
        "resource": resource,
        "issue": issue,
        "fix": fix,
    }


def check_iam(iam: Any) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for page in iam.get_paginator("list_users").paginate():
        for user in page.get("Users", []):
            username = user["UserName"]
            mfa_devices = iam.list_mfa_devices(UserName=username).get("MFADevices", [])
            if not mfa_devices:
                findings.append(
                    finding("HIGH", "IAM", username, "MFA not enabled", "Enable a virtual or hardware MFA device")
                )

            for key in iam.list_access_keys(UserName=username).get("AccessKeyMetadata", []):
                if key.get("Status") != "Active":
                    continue
                age_days = (datetime.now(timezone.utc) - key["CreateDate"]).days
                if age_days >= 90:
                    findings.append(
                        finding(
                            "MEDIUM",
                            "IAM",
                            f"{username} ({key['AccessKeyId']})",
                            f"Active access key is {age_days} days old",
                            "Rotate the key and deactivate the old one",
                        )
                    )
    return findings


def check_iam_policy(iam: Any) -> list[dict[str, str]]:
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
    except iam.exceptions.NoSuchEntityException:
        return [
            finding(
                "MEDIUM",
                "IAM",
                "Account password policy",
                "No account password policy configured",
                "Configure a strong password policy with length and complexity requirements",
            )
        ]

    requirements = {
        "MinimumPasswordLength": 14,
        "RequireUppercaseCharacters": True,
        "RequireLowercaseCharacters": True,
        "RequireNumbers": True,
        "RequireSymbols": True,
    }
    if any(policy.get(key) != expected for key, expected in requirements.items()):
        return [
            finding(
                "MEDIUM",
                "IAM",
                "Account password policy",
                "Password policy does not meet the recommended baseline",
                "Require 14+ characters and uppercase, lowercase, number, and symbol characters",
            )
        ]
    return []


def check_security_groups(ec2: Any) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for page in ec2.get_paginator("describe_security_groups").paginate():
        for group in page.get("SecurityGroups", []):
            group_name = group.get("GroupName", group["GroupId"])
            for permission in group.get("IpPermissions", []):
                if permission.get("IpProtocol") not in {"tcp", "-1"}:
                    continue
                from_port = permission.get("FromPort")
                to_port = permission.get("ToPort")
                covers_ssh = permission.get("IpProtocol") == "-1" or (
                    from_port is not None and to_port is not None and from_port <= 22 <= to_port
                )
                public_ipv4 = any(ip.get("CidrIp") == "0.0.0.0/0" for ip in permission.get("IpRanges", []))
                if covers_ssh and public_ipv4:
                    findings.append(
                        finding(
                            "HIGH",
                            "EC2-SG",
                            f"{group['GroupId']} ({group_name})",
                            "Port 22 (SSH) open to the internet",
                            "Restrict source to your IP or a VPN/bastion host",
                        )
                    )
                    break
    return findings


def check_s3(s3: Any) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for bucket in s3.list_buckets().get("Buckets", []):
        name = bucket["Name"]
        try:
            config = s3.get_public_access_block(Bucket=name).get("PublicAccessBlockConfiguration", {})
        except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
            config = {}
        if not all(config.get(flag, False) for flag in (
            "BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"
        )):
            findings.append(
                finding(
                    "HIGH",
                    "S3",
                    name,
                    "No complete Block Public Access configuration",
                    "Enable all four S3 Block Public Access settings",
                )
            )
    return findings


def check_cloudtrail(cloudtrail: Any) -> list[dict[str, str]]:
    trails = cloudtrail.describe_trails(includeShadowTrails=False).get("trailList", [])
    findings: list[dict[str, str]] = []
    if not trails:
        findings.append(
            finding(
                "HIGH",
                "CloudTrail",
                "Account",
                "No CloudTrail trail configured",
                "Create a multi-region CloudTrail trail and send logs to protected S3",
            )
        )
        return findings
    statuses = cloudtrail.get_trail_status(Name=trails[0]["Name"])
    if not statuses.get("IsLogging", False):
        findings.append(
            finding(
                "HIGH",
                "CloudTrail",
                trails[0]["Name"],
                "CloudTrail trail is not logging",
                "Start logging and alert when the trail stops",
            )
        )
    return findings


def write_report(findings: list[dict[str, str]], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=REPORT_FIELDS)
        writer.writeheader()
        writer.writerows(findings)


def build_session(key_file: Path, region: str | None) -> Any:
    try:
        import boto3
    except ImportError as error:
        raise RuntimeError("boto3 is required. Install it with: python -m pip install boto3") from error

    access_key, secret_key = load_credentials(key_file)
    return boto3.Session(aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region)


def run(session: Any) -> list[dict[str, str]]:
    checks = [
        ("Checking IAM users...", lambda: check_iam(session.client("iam"))),
        ("Checking IAM policies...", lambda: check_iam_policy(session.client("iam"))),
        ("Checking Security groups...", lambda: check_security_groups(session.client("ec2"))),
        ("Checking S3 buckets...", lambda: check_s3(session.client("s3"))),
        ("Checking CloudTrail...", lambda: check_cloudtrail(session.client("cloudtrail"))),
    ]
    findings: list[dict[str, str]] = []
    for label, check in checks:
        print(label)
        findings.extend(check())
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="Run read-only AWS security posture checks.")
    parser.add_argument("--credentials", type=Path, default=Path(os.getenv("AWS_CREDENTIALS_FILE", DEFAULT_KEY_FILE)))
    parser.add_argument("--region", default=os.getenv("AWS_DEFAULT_REGION", "us-east-1"))
    parser.add_argument("--output", type=Path, default=Path("security_report.csv"))
    args = parser.parse_args()

    try:
        findings = run(build_session(args.credentials, args.region))
        write_report(findings, args.output)
    except Exception as error:  # Entry-point boundary: show the actionable error, then exit.
        print(f"Error: {error}", file=sys.stderr)
        return 1

    high_count = sum(item["severity"] == "HIGH" for item in findings)
    print(f"\nDone. {len(findings)} findings ({high_count} high). Report: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
