"""Seed a mocked AWS account with deliberately-insecure resources.

Powers `--demo`, so the scanner can be run end to end with no real AWS
account. Every resource here is intentionally broken (except the "secure"
bucket, which proves the scanner produces no false positives).
"""
from __future__ import annotations

import json

import boto3


def seed_demo(session: boto3.Session) -> None:
    _seed_s3(session)
    _seed_iam(session)
    _seed_ec2(session)


def _seed_s3(session: boto3.Session) -> None:
    s3 = session.client("s3")
    # BAD: no Block Public Access configured.
    s3.create_bucket(Bucket="company-public-backups")
    # GOOD: fully locked down -> must NOT be flagged.
    s3.create_bucket(Bucket="company-secure-logs")
    s3.put_public_access_block(
        Bucket="company-secure-logs",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
        },
    )


def _seed_iam(session: boto3.Session) -> None:
    iam = session.client("iam")
    # BAD: console user with no MFA.
    iam.create_user(UserName="dev-intern")
    iam.create_login_profile(UserName="dev-intern", Password="Password123!")
    # BAD: customer-managed full-admin policy.
    iam.create_policy(
        PolicyName="LegacyAdminAccess",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
        }),
    )


def _seed_ec2(session: boto3.Session) -> None:
    ec2 = session.client("ec2")
    vpc = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    # BAD: SSH open to the world.
    web = ec2.create_security_group(GroupName="web-servers", Description="demo", VpcId=vpc)
    ec2.authorize_security_group_ingress(
        GroupId=web["GroupId"],
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
    )
    # BAD: all inbound traffic open.
    legacy = ec2.create_security_group(GroupName="legacy-box", Description="demo", VpcId=vpc)
    ec2.authorize_security_group_ingress(
        GroupId=legacy["GroupId"],
        IpPermissions=[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
    )