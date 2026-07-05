"""S3 misconfiguration checks."""
from __future__ import annotations

import boto3
from botocore.exceptions import ClientError

from ..models import Finding, Severity
from ..registry import register

# The four settings that together make up S3 "Block Public Access".
_PAB_FLAGS = (
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
)


@register
def public_access_block(session: boto3.Session) -> list[Finding]:
    """Flag S3 buckets that don't fully enable Block Public Access.

    CIS 2.1.5 - every bucket should have all four Block Public Access settings
    enabled so it can't be exposed by an ACL or bucket policy.
    """
    s3 = session.client("s3")
    findings: list[Finding] = []

    for bucket in s3.list_buckets().get("Buckets", []):
        name = bucket["Name"]

        try:
            pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            disabled = [flag for flag in _PAB_FLAGS if not pab.get(flag, False)]
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                disabled = list(_PAB_FLAGS)   # no PAB at all - worst case
            else:
                raise

        if disabled:
            findings.append(
                Finding(
                    check_id="s3_public_access_block",
                    title=f"Bucket does not fully block public access "
                          f"(disabled: {', '.join(disabled)})",
                    cis_control="CIS 2.1.5",
                    severity=Severity.HIGH,
                    resource=name,
                    remediation="Enable all four S3 Block Public Access settings "
                                "on the bucket or at the account level.",
                )
            )

    return findings