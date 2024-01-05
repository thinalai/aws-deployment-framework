#!/usr/bin/env python3
"""
Module gets all SSM parameters from an AWS account in a given parameter path If invoked via CLI
it set writes them to an environement file, when invoked from another python script it returns
a dictionary of the parameters.
"""
import os
import logging as log
import argparse
import boto3

import yaml

log.basicConfig(level=log.INFO, format="[%(levelname)s] %(asctime)s - %(message)s")


DEFAULT_PATH = "/orionadp/platform"
DEFAULT_REGION = "cn-north-1"
DEFAULT_ENV_FILE_PATH = "./.env"
DEFAULT_LOOKUP_ROLE = "adf-codebuild-deployment-account-cdk-ro-role"
# File Paths too config files
COMMON_CONFIG_FILE_PATH = "platform-common-lambda-layer/common.config.global.yml"
COMMON_CONFIG_STAGE_FILE_PATH = "platform-common-lambda-layer/common.config.{org_stage}.yml"
PROJECT_CONFIG_FILE_PATH = "config/config.global.yml"
PROJECT_STAGE_CONFIG_FILE_PATH = "config/config.{org_stage}.yml"


def _paginate(method, **kwargs):
    """Returns a Merged Dictionary of client API responses"""
    client = method.__self__
    paginator = client.get_paginator(method.__name__)
    for page in paginator.paginate(**kwargs).result_key_iters():
        for result in page:
            yield result


def _get_ssm_client(region: str, role_arn: str = None):
    """
     Gets a SSM client.
    :param region: The region.
    :param role_arn: The role arn to assume
    :return: The SSM client.
    """
    if role_arn:
        sts_client = boto3.client("sts")
        assumed_role = sts_client.assume_role(RoleArn=role_arn, RoleSessionName="AssumeRoleSession1")
        credentials = assumed_role["Credentials"]
        session = boto3.session.Session(
            region_name=region,
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
        )
    else:
        session = boto3.session.Session(region_name=region)
    return session.client("ssm", region_name=region)


def _format_role_arn(lookup_account: str, lookup_role_name=None):
    """
    Formats the role arn
    :param lookup_account: The account to lookup
    :param lookup_role_name: The role name
    :return: The formatted role arn
    """
    log.info("building role arn from account %s and role name %s", lookup_account, lookup_role_name)
    return f"arn:aws:iam::{lookup_account}:role/{lookup_role_name or DEFAULT_LOOKUP_ROLE}"


def _format_parameter_name(parameter_name, omit_path_root_name) -> str:
    """
    Formats the parameter name replacing slashes, hypens and dots with
    underscores
    :param parameter_name: The parameter name.
    :return: The formatted parameter name.
    """
    if omit_path_root_name:
        # This will remove the first part of the SSM Parameter from the response
        parameter_name = f"/{'/'.join(parameter_name.split('/')[2:])}"
    translation = str.maketrans("/-.", "___")
    return parameter_name[1:].translate(translation).upper()


def _write_ssm_parameters_to_env_file(ssm_parameters: dict, env_file_path: str = DEFAULT_ENV_FILE_PATH) -> None:
    """
    Writes all SSM parameters to an environment file.
    :param ssm_parameters: The SSM parameters.
    :param env_file_path: The path to the environement file.
    :return: None
    """
    with open(env_file_path, "w", encoding="utf-8") as env_file:
        for parameter_name, parameter_value in ssm_parameters.items():
            log.info("Writing SSM parameter %s to environment file: %s", parameter_name, env_file_path)
            env_file.write(f'export {parameter_name}="{parameter_value}"\n')


def parse_config_parameters(
        org_stage: str,
        project_root_path: str,
        ssm_parameter_paths=None,
        ssm_parameter_names=None,
        lookup_account: str = None,
        lookup_role_name: str = None,
        region: str = DEFAULT_REGION,
        omit_path_root_name: bool = False
        ) -> dict:
    """
    Parses the Config Parameters from the YAML Files.
    The YAML Files are loaded in the following order:
    1. Common Config File
    2. Common Stage Config File
    1. Project Config File
    2. Project Stage Specific Config File
    3. Parameters from SSM
    The YAML Files are loaded into a dictionary.
    The dictionary is then returned.
    :param ssm_parameter_paths: A list of Paths to SSM Parameters.
    :return: A dictionary containing the Config Parameters.
    :rtype: dict
    """
    

    config_dict: dict = {}

    for file_path in (
        COMMON_CONFIG_FILE_PATH,
        COMMON_CONFIG_STAGE_FILE_PATH,
        PROJECT_CONFIG_FILE_PATH,
        PROJECT_STAGE_CONFIG_FILE_PATH
    ):
        config_file_path = os.path.join(project_root_path, file_path.format(org_stage=org_stage))
        if os.path.exists(config_file_path):
            with open(config_file_path, encoding="utf-8") as yaml_file:
                print("Detected Config File: ", config_file_path)
                config_dict.update(yaml.safe_load(yaml_file))
    
    lookup_role_arn = None
    if lookup_account:
        lookup_role_arn = _format_role_arn(lookup_account, lookup_role_name)

    # Add all the Parameters from SSM in the given Paths.
    config_dict.update(
        get_ssm_parameter_dictionary(
            region=region,
            role_arn=lookup_role_arn,
            parameter_names=ssm_parameter_names,
            parameter_paths=ssm_parameter_paths,
            omit_path_root_name=omit_path_root_name
        )
    )
    return config_dict


def get_ssm_paramater_dictionary(
        parameter_names: tuple,
        region: str = None,
        role_arn: str = None,
        parameter_paths: tuple = DEFAULT_PATH) -> dict:
    """
    Deprecated please invoke get_ssm_parameter_dictionary directly
    """
    return get_ssm_parameter_dictionary(
        parameter_names=parameter_names,
        region=region,
        role_arn=role_arn,
        parameter_paths=parameter_paths
    )


def get_ssm_parameter_dictionary(
    parameter_names: tuple,
    region: str = None,
    role_arn: str = None,
    parameter_paths: tuple = DEFAULT_PATH,
    omit_path_root_name: bool = False
) -> dict:
    """
    Given a list of parameter paths, grabs the name and value from each parameter in
    SSM in those paths then returns a dictionary of the parameters.
    :param region: The region.
    :param parameter_path: The path to the parameters.
    :return: The SSM parameters.
    """
    ssm_client = _get_ssm_client(region, role_arn=role_arn)

    parameter_list = []
    # Get the Parameter by Name
    if parameter_names:
        for parameter_name in parameter_names:
            response = ssm_client.get_parameter(Name=parameter_name, WithDecryption=True)
            parameter_list.append(response.get("Parameter"))
    # Get the Parameters by Path
    if parameter_paths:
        for path in parameter_paths:
            parameter_list.extend(
                list(_paginate(ssm_client.get_parameters_by_path, Path=path, Recursive=True))
            )
    return {_format_parameter_name(param["Name"], omit_path_root_name): param["Value"] for param in parameter_list}


def main(
    region: str,
    parameter_paths: tuple,
    parameter_names: tuple,
    role_arn: str,
    lookup_account: str,
    lookup_role_name: str,
    env_file_path: str,
    omit_path_root_name: bool
) -> None:
    """
    Main function takes a list of parameter paths, grabs the name and value from each
    parameter in SSM in those paths then writes them to an file which can be sourced
    to local dev environment or Codebuild Environment.
    :param region: The region to fetch the params.
    :param parameter_path: A tuple of SSM Paths retrieve parameters from recursively.
    :param env_file_path: The path to the environment file which should be generated.
    :param role_arn: The role arn to assume when making cross account lookups.
    :param lookup_account: The lookup account to assume a role into when making cross account lookups.
    :param lookup_role_name: The lookup role name to assume a role into.
    :param omit_path_root_name: If the root name of the path should be omitted.
    :return: None
    """
    if role_arn and lookup_account:
        raise ValueError("Cannot specify both role_arn and lookup_account")
    if lookup_role_name and not lookup_account:
        raise ValueError("Must specify lookup_account when using lookup_role_name")
    if lookup_account:
        role_arn = _format_role_arn(lookup_account, lookup_role_name)

    parameters = get_ssm_parameter_dictionary(
        region=region,
        role_arn=role_arn,
        parameter_paths=parameter_paths,
        parameter_names=parameter_names,
        omit_path_root_name=omit_path_root_name
    )
    _write_ssm_parameters_to_env_file(ssm_parameters=parameters, env_file_path=env_file_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--path",
        action="append",
        help=f"Paths to SSM parameters, can be provided multiple times, default: {DEFAULT_PATH}"
    )
    parser.add_argument(
        "--parameter-name",
        action="append",
        help="Name of specific parameter to fetch, can be provided multiple times, optional"
    )
    parser.add_argument(
        "--region",
        type=str,
        help=f"Region to load parameters, default: {DEFAULT_REGION}",
        default=DEFAULT_REGION
    )
    parser.add_argument(
        "--env-file-path",
        type=str,
        help=f"Path to the environment file, default: {DEFAULT_ENV_FILE_PATH}",
        default=DEFAULT_ENV_FILE_PATH,
    )
    parser.add_argument(
        "--role-arn",
        type=str,
        help="Role arn to assume, default: None"
    )
    parser.add_argument(
        "--lookup-account",
        type=str,
        help="Lookup Account to assume a role into, default: None"
    )
    parser.add_argument(
        "--lookup-role-name",
        type=str,
        help=f"Role arn to assume, default: {DEFAULT_LOOKUP_ROLE}"
    )
    parser.add_argument(
        "--omit-path-root-name",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="""When provided it will omit the first part of the SSM Parameter name from the generated
        environment variable name"""
    )
    args = parser.parse_args()
    if not args.path:
        args.path = [DEFAULT_PATH]

    main(
        region=args.region,
        parameter_paths=args.path,
        parameter_names=args.parameter_name,
        env_file_path=args.env_file_path,
        role_arn=args.role_arn,
        lookup_account=args.lookup_account,
        lookup_role_name=args.lookup_role_name,
        omit_path_root_name=args.omit_path_root_name
    )
