"""Tests for S3 checks."""
from scanner.checks.s3 import public_access_block


def _make_bucket(session, name, block=True):
    """Create a bucket, optionally with full Block Public Access enabled."""
    s3 = session.client("s3")
    s3.create_bucket(Bucket=name)
    if block:
        s3.put_public_access_block(
            Bucket=name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )


def test_flags_bucket_without_public_access_block(session):
    _make_bucket(session, "bad-bucket", block=False)

    findings = public_access_block(session)

    assert len(findings) == 1
    assert findings[0].resource == "bad-bucket"
    assert findings[0].check_id == "s3_public_access_block"


def test_ignores_bucket_with_public_access_block(session):
    _make_bucket(session, "good-bucket", block=True)

    findings = public_access_block(session)

    assert findings == []


def test_only_the_bad_bucket_is_flagged(session):
    _make_bucket(session, "good-bucket", block=True)
    _make_bucket(session, "bad-bucket", block=False)

    findings = public_access_block(session)

    assert len(findings) == 1
    assert findings[0].resource == "bad-bucket"