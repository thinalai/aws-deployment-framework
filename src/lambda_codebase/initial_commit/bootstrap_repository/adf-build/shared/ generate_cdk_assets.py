# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""This file is pulled into CodeBuild containers
   and used to build the parameters for cloudformation stacks based on
   the cdk manifest generated by cdk synth v2
"""
import argparse
import json
import os
import shutil
import sys

import boto3
from logger import configure_logger
from parameter_store import ParameterStore
from s3 import S3

logger = configure_logger(__name__)
aws_region_from_env = os.environ.get("AWS_REGION")
# project_name = os.environ.get("ADF_PROJECT_NAME")
project_root = os.path.dirname(__file__)


def load_manifest(file: str) -> dict:
    try:
        with open(f"{file}") as file:
            return json.load(file)
    except FileNotFoundError:
        logger.exception(f"File {file} not found.")
        sys.exit(1)


def load_cdk_manifest(cdk_out_dir: str) -> dict:
    return load_manifest(f"{cdk_out_dir}/manifest.json")


def main(cdk_out_dir: str):
    #s3 = S3(aws_region_from_env, shared_modules_bucket) # TODO: VERIFY if this change didn't break anything!
    s3 = S3(aws_region_from_env, shared_modules_bucket)
    logger.info(f"Region Info - aws_region_from_env: {aws_region_from_env}.")
    logger.info(f"Region Info - Target region: {target_region}.")
    logger.info(f"Uploading manifests to bucket {shared_modules_bucket} with target region {target_region}.")

    manifest = load_cdk_manifest(cdk_out_dir)

    artifacts: dict = manifest.get("artifacts")
    # Not needed here
    del artifacts["Tree"]

    asset_manifests = {
        name: asset_manifest
        for (name, asset_manifest) in artifacts.items()
        if asset_manifest["type"] == "cdk:asset-manifest"
    }

    asset_manifest_name: str
    for asset_manifest_name, asset_manifest_object in asset_manifests.items():
        asset_manifest = load_manifest(
            f"{cdk_out_dir}/{asset_manifest_object['properties']['file']}"
        )
        file_assets = {
            key: value
            for (key, value) in asset_manifest.get("files").items()
            if not value["source"]["path"].endswith(
                "template.json"
            )  # CDKV2 has the template as an asset. we don't need that
        }
        stack_parameters = {}
        if file_assets:
            for file_asset in file_assets.values():
                if file_asset["source"]["packaging"] == "zip":
                    logger.info(f'Zipping asset {file_asset["source"]["path"]}')
                    asset_path = os.path.join(
                        project_root, cdk_out_dir, file_asset["source"]["path"]
                    )
                    file_asset_path = shutil.make_archive(
                        asset_path,
                        "zip",
                        asset_path,
                    )
                    s3_asset_keys = []
                    for destination in file_asset["destinations"]:
                        s3_asset_keys.append(file_asset["destinations"][destination]["objectKey"])
                elif file_asset["source"]["packaging"] == "file":
                    file_asset_path = f'{cdk_out_dir}/{file_asset["source"]["path"]}'
                    s3_asset_keys = []
                    for destination in file_asset["destinations"]:
                        s3_asset_keys.append(file_asset["destinations"][destination]["objectKey"])
                else:
                    logger.error(
                        "Can only handle zip file and file assets. Check asset manifest for others."
                    )
                    sys.exit(2)
                for s3_asset_key in s3_asset_keys:
                    uploaded_asset_path = s3.put_object(
                        s3_asset_key,
                        file_asset_path,
                        style="s3-url",
                        pre_check=True,
                        object_acl="bucket-owner-full-control",
                    )
                    logger.info(f"uploaded to {uploaded_asset_path}")
        else:
            logger.info(f"Manifest {asset_manifest_name} has no file assets.")

        # Always need to have params, even if none are defined
        try:
            os.mkdir(f"{os.getcwd()}/params")
        except FileExistsError:
            logger.info("params folder already exists")

        stack = asset_manifest_name.split(".")[0]

        logger.info(f"CDK V2 does not use parameters for assets. Empty Param file")
        param_file_contents = {"Parameters": stack_parameters}
        logger.info(json.dumps(param_file_contents, indent=4))
        with open(f"params/{stack}.params.json", "w") as param_file:
            json.dump(param_file_contents, param_file)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("cdk_out_dir", help="name of cdk.out directory")
    parser.add_argument(
        "-r",
        "--region",
    )
    args = parser.parse_args()

    parameter_store = ParameterStore(region=aws_region_from_env, role=boto3)
    target_region = args.region if args.region else aws_region_from_env
    shared_modules_bucket = parameter_store.fetch_parameter(
        f"/cross_region/s3_regional_bucket/{target_region}"
    )

    cdk_out_dir = args.cdk_out_dir
    main(cdk_out_dir)
