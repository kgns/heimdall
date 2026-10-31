import os

import boto3
import pytest
from moto import mock_aws

os.environ.setdefault("AWS_DEFAULT_REGION", "eu-central-1")


@pytest.fixture
def aws():
    """The incidents table and SSM, mocked."""
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="eu-central-1")
        table = ddb.create_table(
            TableName="heimdall-incidents",
            KeySchema=[
                {"AttributeName": "device", "KeyType": "HASH"},
                {"AttributeName": "incident_id", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "device", "AttributeType": "S"},
                {"AttributeName": "incident_id", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        yield table, boto3.client("ssm", region_name="eu-central-1")
