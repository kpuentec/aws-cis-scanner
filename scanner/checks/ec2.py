"""EC2 / networking misconfiguration checks."""
from __future__ import annotations

import boto3

from ..models import Finding, Severity
from ..registry import register

# Ports that should never be open to the whole internet.
_SENSITIVE_PORTS = {22: "SSH", 3389: "RDP"}

_OPEN_CIDR = "0.0.0.0/0"


def _is_open_to_world(permission: dict) -> bool:
    """True if this ingress rule allows 0.0.0.0/0."""
    return any(r.get("CidrIp") == _OPEN_CIDR for r in permission.get("IpRanges", []))


@register
def sensitive_ports_open(session: boto3.Session) -> list[Finding]:
    """Flag security groups exposing SSH (22) or RDP (3389) to the internet.

    CIS 5.2 - administrative ports must not be open to 0.0.0.0/0.
    """
    ec2 = session.client("ec2")
    findings: list[Finding] = []

    for sg in ec2.describe_security_groups().get("SecurityGroups", []):
        for perm in sg.get("IpPermissions", []):
            if perm.get("IpProtocol") == "-1":
                continue  # "all traffic" is handled by all_traffic_open()
            from_port, to_port = perm.get("FromPort"), perm.get("ToPort")
            if from_port is None or to_port is None or not _is_open_to_world(perm):
                continue
            for port, name in _SENSITIVE_PORTS.items():
                if from_port <= port <= to_port:
                    findings.append(
                        Finding(
                            check_id="ec2_sensitive_port_open",
                            title=f"Security group exposes {name} (port {port}) to 0.0.0.0/0",
                            cis_control="CIS 5.2",
                            severity=Severity.HIGH,
                            resource=sg["GroupId"],
                            remediation=f"Restrict inbound {name} to known IP ranges "
                                        f"instead of 0.0.0.0/0.",
                        )
                    )

    return findings


@register
def all_traffic_open(session: boto3.Session) -> list[Finding]:
    """Flag security groups that allow ALL inbound traffic from the internet.

    CIS 5.2 - a rule permitting every protocol/port from 0.0.0.0/0 is the
    widest-open misconfiguration a group can have.
    """
    ec2 = session.client("ec2")
    findings: list[Finding] = []

    for sg in ec2.describe_security_groups().get("SecurityGroups", []):
        for perm in sg.get("IpPermissions", []):
            if perm.get("IpProtocol") == "-1" and _is_open_to_world(perm):
                findings.append(
                    Finding(
                        check_id="ec2_all_traffic_open",
                        title="Security group allows all inbound traffic from 0.0.0.0/0",
                        cis_control="CIS 5.2",
                        severity=Severity.HIGH,
                        resource=sg["GroupId"],
                        remediation="Remove the all-traffic rule and allow only the "
                                    "specific ports and sources you need.",
                    )
                )
                break  # one finding per group is enough

    return findings