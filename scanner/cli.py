"""Command-line entry point for the AWS CIS scanner."""
from __future__ import annotations

import argparse
import os
import sys

import boto3

# Importing the checks package runs each check module, which registers its
# checks via the @register decorator. Without this import, no checks exist.
from . import checks  # noqa: F401  (imported for its registration side effect)
from .models import Finding, Status
from .registry import run_all
from .report import print_table, to_json


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aws-cis-scanner",
        description="Scan an AWS account for CIS misconfigurations.",
    )
    p.add_argument("--output", choices=["table", "json"], default="table",
                   help="output format (default: table)")
    p.add_argument("--profile", default=None, help="AWS profile name to use")
    p.add_argument("--region", default="us-east-1", help="AWS region")
    p.add_argument("--demo", action="store_true",
                   help="scan a mocked account seeded with insecure resources "
                        "(no real AWS account or credentials needed)")
    return p


def _run_demo(region: str) -> list[Finding]:
    """Spin up an in-memory AWS, seed insecure resources, and scan it."""
    from moto import mock_aws
    from .demo import seed_demo

    # Dummy creds so boto3 can sign requests; moto intercepts them anyway.
    os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
    os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
    os.environ.setdefault("AWS_SESSION_TOKEN", "testing")

    with mock_aws():
        session = boto3.Session(region_name=region)
        seed_demo(session)
        return run_all(session)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.demo:
        findings = _run_demo(args.region)
    else:
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
        findings = run_all(session)

    if args.output == "json":
        print(to_json(findings))
    else:
        print_table(findings)

    # Exit non-zero if anything failed, so this can gate a CI pipeline later.
    failed = any(f.status == Status.FAIL for f in findings)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())