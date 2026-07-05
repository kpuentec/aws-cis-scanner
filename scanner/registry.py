"""A tiny registry so checks self-register and the CLI can discover them."""
from __future__ import annotations

from typing import Callable

import boto3

from .models import Finding

CheckFn = Callable[[boto3.Session], list[Finding]]

_CHECKS: list[CheckFn] = []


def register(fn: CheckFn) -> CheckFn:
    """Decorator that adds a check function to the registry."""
    _CHECKS.append(fn)
    return fn


def all_checks() -> list[CheckFn]:
    return list(_CHECKS)


def run_all(session: boto3.Session) -> list[Finding]:
    """Run every registered check and flatten their findings into one list."""
    findings: list[Finding] = []
    for check in _CHECKS:
        findings.extend(check(session))
    return findings