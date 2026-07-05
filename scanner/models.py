"""Core data structures shared by every check in the scanner."""
from __future__ import annotations

from dataclasses import dataclass, asdict
from enum import Enum


class Severity(str, Enum):
    """How serious a finding is."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"


@dataclass
class Finding:
    """The result of one check against one resource."""
    check_id: str          # short stable id, e.g. "s3_public_access_block"
    title: str             # human-readable summary of what's wrong
    cis_control: str       # e.g. "CIS 2.1.5"
    severity: Severity     # how bad it is
    resource: str          # what it's about: bucket name / ARN / SG id
    remediation: str       # one-line fix
    status: Status = Status.FAIL   # a Finding is a problem by default

    def to_dict(self) -> dict:
        """A plain JSON-serializable dict (enums flattened to strings)."""
        data = asdict(self)
        data["severity"] = self.severity.value
        data["status"] = self.status.value
        return data