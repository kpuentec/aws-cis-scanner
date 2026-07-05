"""Tests for EC2 security group checks."""
from scanner.checks.ec2 import all_traffic_open, sensitive_ports_open


def _default_vpc(session):
    ec2 = session.client("ec2")
    return ec2.describe_vpcs()["Vpcs"][0]["VpcId"]


def _sg_with_ingress(session, name, permissions):
    ec2 = session.client("ec2")
    sg = ec2.create_security_group(
        GroupName=name, Description="test", VpcId=_default_vpc(session)
    )
    if permissions:
        ec2.authorize_security_group_ingress(GroupId=sg["GroupId"], IpPermissions=permissions)
    return sg["GroupId"]


SSH_OPEN = [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
             "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]
SSH_RESTRICTED = [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                   "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}]
ALL_OPEN = [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]


# --- sensitive_ports_open ----------------------------------------------------

def test_flags_ssh_open_to_world(session):
    sgid = _sg_with_ingress(session, "web", SSH_OPEN)

    findings = sensitive_ports_open(session)

    assert len(findings) == 1
    assert findings[0].resource == sgid
    assert "SSH" in findings[0].title


def test_ignores_ssh_restricted_to_private_range(session):
    _sg_with_ingress(session, "web", SSH_RESTRICTED)

    findings = sensitive_ports_open(session)

    assert findings == []


# --- all_traffic_open --------------------------------------------------------

def test_flags_all_traffic_open(session):
    sgid = _sg_with_ingress(session, "wide", ALL_OPEN)

    findings = all_traffic_open(session)

    assert len(findings) == 1
    assert findings[0].resource == sgid


def test_all_traffic_check_ignores_specific_port_rule(session):
    # An SSH-only rule should NOT trip the all-traffic check.
    _sg_with_ingress(session, "web", SSH_OPEN)

    findings = all_traffic_open(session)

    assert findings == []