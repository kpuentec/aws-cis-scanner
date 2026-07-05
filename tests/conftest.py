"""Shared pytest fixtures: dummy AWS creds + an in-memory moto AWS."""
import os

import boto3
import pytest
from moto import mock_aws

# Dummy creds so a bug can never reach real AWS. Set before any client is made.
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_SESSION_TOKEN", "testing")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")


@pytest.fixture
def session():
    """A boto3 Session wired to moto's in-memory AWS."""
    with mock_aws():
        yield boto3.Session(region_name="us-east-1")