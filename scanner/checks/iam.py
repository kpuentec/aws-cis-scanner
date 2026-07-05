"""IAM misconfiguration checks."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote

import boto3
from botocore.exceptions import ClientError

from ..models import Finding, Severity
from ..registry import register


@register
def users_without_mfa(session: boto3.Session) -> list[Finding]:
    """Flag IAM users who have console access but no MFA device.

    CIS 1.10 - any user who can log into the console must have MFA enabled.
    Users without console access are skipped (MFA isn't relevant to them here).
    """
    iam = session.client("iam")
    findings: list[Finding] = []

    for user in iam.list_users().get("Users", []):
        username = user["UserName"]

        # Does the user have a console password? No login profile -> no console.
        try:
            iam.get_login_profile(UserName=username)
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                continue
            raise

        if not iam.list_mfa_devices(UserName=username).get("MFADevices", []):
            findings.append(
                Finding(
                    check_id="iam_user_without_mfa",
                    title="IAM user has console access but no MFA device",
                    cis_control="CIS 1.10",
                    severity=Severity.HIGH,
                    resource=username,
                    remediation="Enable an MFA device for this user, or remove "
                                "console access if it isn't needed.",
                )
            )

    return findings


def _load_policy_document(document) -> dict:
    """Normalize an IAM policy document to a dict.

    moto returns it as a dict; real AWS returns a URL-encoded JSON string.
    Handle both so the check works in production, not just under test.
    """
    if isinstance(document, str):
        return json.loads(unquote(document))
    return document


def _grants_full_admin(document: dict) -> bool:
    """True if the policy allows Action '*' on Resource '*' in any statement."""
    statements = document.get("Statement", [])
    if isinstance(statements, dict):        # a single statement, not a list
        statements = [statements]

    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]
        if "*" in actions and "*" in resources:
            return True
    return False


@register
def full_admin_policies(session: boto3.Session) -> list[Finding]:
    """Flag customer-managed policies that grant full administrative access.

    CIS 1.16 - avoid attaching policies that allow every action on every
    resource ('*' on '*'); grant least privilege instead.
    """
    iam = session.client("iam")
    findings: list[Finding] = []

    for policy in iam.list_policies(Scope="Local").get("Policies", []):
        version = iam.get_policy_version(
            PolicyArn=policy["Arn"], VersionId=policy["DefaultVersionId"]
        )["PolicyVersion"]["Document"]

        if _grants_full_admin(_load_policy_document(version)):
            findings.append(
                Finding(
                    check_id="iam_full_admin_policy",
                    title="Customer-managed policy grants full admin (Action '*' on Resource '*')",
                    cis_control="CIS 1.16",
                    severity=Severity.CRITICAL,
                    resource=policy["PolicyName"],
                    remediation="Scope the policy to specific actions and "
                                "resources; never allow '*' on both.",
                )
            )

    return findings


@register
def old_access_keys(
    session: boto3.Session,
    max_age_days: int = 90,
    now: datetime | None = None,
) -> list[Finding]:
    """Flag active IAM access keys older than `max_age_days`.

    CIS 1.14 - rotate access keys regularly (90 days). The `now` argument
    defaults to the real current time; tests pass a fixed value so the
    age calculation is deterministic (no time-mocking library needed).
    """
    iam = session.client("iam")
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=max_age_days)
    findings: list[Finding] = []

    for user in iam.list_users().get("Users", []):
        username = user["UserName"]
        for key in iam.list_access_keys(UserName=username).get("AccessKeyMetadata", []):
            created = key["CreateDate"]
            if created < cutoff:
                age_days = (now - created).days
                findings.append(
                    Finding(
                        check_id="iam_old_access_key",
                        title=f"IAM access key is {age_days} days old (older than {max_age_days})",
                        cis_control="CIS 1.14",
                        severity=Severity.MEDIUM,
                        resource=f"{username}/{key['AccessKeyId']}",
                        remediation="Rotate the access key and delete the old one.",
                    )
                )

    return findings