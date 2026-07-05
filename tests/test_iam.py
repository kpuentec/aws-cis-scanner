"""Tests for IAM checks."""
from datetime import datetime, timedelta, timezone

from scanner.checks.iam import (
    full_admin_policies,
    old_access_keys,
    users_without_mfa,
)

ADMIN_DOC = (
    '{"Version":"2012-10-17","Statement":'
    '[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
)
SCOPED_DOC = (
    '{"Version":"2012-10-17","Statement":'
    '[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::my-bucket/*"}]}'
)


# --- users_without_mfa -------------------------------------------------------

def test_flags_console_user_without_mfa(session):
    iam = session.client("iam")
    iam.create_user(UserName="alice")
    iam.create_login_profile(UserName="alice", Password="Sup3rSecret!23")

    findings = users_without_mfa(session)

    assert len(findings) == 1
    assert findings[0].resource == "alice"


def test_ignores_user_with_mfa(session):
    iam = session.client("iam")
    iam.create_user(UserName="bob")
    iam.create_login_profile(UserName="bob", Password="Sup3rSecret!23")
    mfa = iam.create_virtual_mfa_device(VirtualMFADeviceName="bob-mfa")
    iam.enable_mfa_device(
        UserName="bob",
        SerialNumber=mfa["VirtualMFADevice"]["SerialNumber"],
        AuthenticationCode1="123456",
        AuthenticationCode2="234567",
    )

    findings = users_without_mfa(session)

    assert findings == []


def test_ignores_user_without_console_access(session):
    iam = session.client("iam")
    iam.create_user(UserName="carol")  # no login profile -> no console access

    findings = users_without_mfa(session)

    assert findings == []


# --- full_admin_policies -----------------------------------------------------

def test_flags_full_admin_policy(session):
    iam = session.client("iam")
    iam.create_policy(PolicyName="godmode", PolicyDocument=ADMIN_DOC)

    findings = full_admin_policies(session)

    assert len(findings) == 1
    assert findings[0].resource == "godmode"
    assert findings[0].severity.value == "CRITICAL"


def test_ignores_scoped_policy(session):
    iam = session.client("iam")
    iam.create_policy(PolicyName="readonly", PolicyDocument=SCOPED_DOC)

    findings = full_admin_policies(session)

    assert findings == []


# --- old_access_keys ---------------------------------------------------------

def test_flags_old_access_key(session):
    iam = session.client("iam")
    iam.create_user(UserName="dave")
    iam.create_access_key(UserName="dave")

    # Scan as if it's 100 days later than the key's creation.
    future = datetime.now(timezone.utc) + timedelta(days=100)
    findings = old_access_keys(session, now=future)

    assert len(findings) == 1
    assert findings[0].resource.startswith("dave/")


def test_ignores_recent_access_key(session):
    iam = session.client("iam")
    iam.create_user(UserName="erin")
    iam.create_access_key(UserName="erin")

    findings = old_access_keys(session)  # real "now" -> key is brand new

    assert findings == []