"""Command-line entry point for the AWS CIS scanner."""
from __future__ import annotations

import argparse
import sys

import boto3

# Importing the checks package runs each check module, which registers its
# checks via @register. Without this import, no checks exist.
from . import checks  # noqa: F401  (imported for its registration side effect)
from .models import Status
from .registry import run_all
from .report import print_table, to_json


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aws-cis-scanner",
        description="Scan an AWS account for CIS misconfigurations.",
    )
    p.add_argument("--output", choices=["table", "json"], default="table")
    p.add_argument("--profile", default=None, help="AWS profile name to use")
    p.add_argument("--region", default="us-east-1", help="AWS region")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    findings = run_all(session)

    if args.output == "json":
        print(to_json(findings))
    else:
        print_table(findings)

    failed = any(f.status == Status.FAIL for f in findings)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())