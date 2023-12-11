import json
import uuid
from decimal import Decimal


def convert_decimals(obj):
    if isinstance(obj, Decimal):
        return str(obj)
    elif isinstance(obj, list):
        return [convert_decimals(item) for item in obj]
    elif isinstance(obj, dict):
        return {key: convert_decimals(value) for key, value in obj.items()}
    else:
        return obj

def gen_arn_simple(
    *,
    resource,
    service,
    account_id=None,
    partition=None,
    region=None,
    resource_name=None,
    aws_managed=None,
    sep="/",
):
    return ":".join(
        [
            "arn",
            partition or self.partition,
            service,
            (region or self.region) if service not in ("iam", "s3") else "",
            (aws_managed or account_id or self.account_id)
            if service not in ("s3",) else "",
            resource if not resource_name else sep.join([resource, resource_name]),
        ]
    )


class Stepfunction:
    """Class to handle Custom Stepfunction methods"""
    def __init__(
        self, 
        session,
        LOGGER
    ):
        self.logger = LOGGER
        self.session = session


    def get_stepfunction_client(self):
        return self.session.client("stepfunctions")

    def invoke_sfn_execution(
        self, 
        sfn_name,
        input: dict,
        execution_name = None):
        try:
            state_machine_arn = gen_arn_simple(service="states",resource_name=sfn_name,resource="stateMachine", sep=":", region=self.session.region_name)
            sfn_client = self.get_stepfunction_client()

            if not execution_name:
                execution_name = str(uuid.uuid4())
            event_body = json.dumps(convert_decimals(input), indent=2)
            response = sfn_client.start_execution(
                        stateMachineArn=state_machine_arn,
                        name=execution_name,
                        input=event_body
                    )
        except Exception as e:
            msg = f"Couldn't invoke stepfunction {sfn_name}, error: {e}."
            self.logger.error(msg)
            raise
        return response, execution_name