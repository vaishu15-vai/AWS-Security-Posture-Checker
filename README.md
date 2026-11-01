# AWS Security Posture Checker

An interactive, read-only AWS audit tool with a browser dashboard. It checks common posture issues across IAM, EC2 security groups, S3, and CloudTrail, then writes a CSV that can be filtered and searched in `dashboard.html`.

## Important credential safety

The supplied IAM access-key CSV is local-only and is ignored by Git. Never publish it, paste its contents into screenshots, or commit it. The checker reads it only to create a temporary boto3 session; it does not write credentials to the report. For real use, create a dedicated audit identity with read-only permissions and rotate/delete the supplied key if it was exposed anywhere.

## Run it

```powershell
python -m pip install -r requirements.txt
python aws_security_checker.py --credentials "security-auditor_accessKeys (1).csv" --region us-east-1
```

The command prints each check and creates `security_report.csv`. The checks are read-only, but AWS API calls can still incur normal API costs. The IAM CSV export format is supported; alternatively set `AWS_CREDENTIALS_FILE` and `AWS_DEFAULT_REGION`.

Open `dashboard.html` in Chrome or Edge, choose **Open security_report.csv**, and use the severity/service filters. **Load demo data** displays fake, masked rows without contacting AWS.

### AWS permissions

Attach [`audit-read-only-policy.json`](audit-read-only-policy.json) to the audit identity before running the live check. If AWS returns `AccessDenied`, the checker stops instead of producing an incomplete report. The policy grants only the read actions used by this project. A typical setup is:

```powershell
aws iam put-user-policy --user-name security-auditor --policy-name SecurityPostureCheckerReadOnly --policy-document file://audit-read-only-policy.json
```

Then rerun the checker. The supplied key authenticated successfully during validation, but its user currently lacks `iam:ListUsers`, so the live report was intentionally not created until this policy is attached.

## Checks

- IAM users without MFA and active access keys at least 90 days old
- EC2 security groups exposing SSH (port 22) to `0.0.0.0/0`
- S3 buckets missing one or more Block Public Access settings
- Missing or stopped CloudTrail logging

The dashboard is interactive: drag and drop a CSV onto the header, search across findings, filter by severity/service, click a row for remediation details, reset filters, and export the filtered view.

## Sample output

Keep screenshots in [`screenshots/`](screenshots/). Recommended evidence:

1. Terminal output showing the check completed.
2. A **Before** dashboard/CSV screenshot with findings.
3. An **After** screenshot after remediating the findings in AWS.

Only use masked or fake account IDs, bucket names, and access-key IDs in published material. `sample_report.csv` is safe demo data for documentation and interviews.
"# AWS-Security-Posture-Checker" 
