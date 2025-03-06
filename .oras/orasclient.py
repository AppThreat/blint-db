# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT

import argparse
import os

import oras.client

client = oras.client.OrasClient()

token = os.getenv("GITHUB_TOKEN", "")
username = os.getenv("GITHUB_USERNAME", "")
db_version = os.getenv("BLINT_DB_VERSION", "v1")
client.login(password=token, username=username)

parser = argparse.ArgumentParser(
    prog="orasclient_blintdb",
    description="Helps pushing blint.db into a container and uploading to ghcr.io",
)
parser.add_argument(
    "-p",
    "--pkg-manager",
    dest="pkg",
    help="Package manager",
)
args = vars(parser.parse_args())

if pkg := args.get("pkg", None):
    client.push(
        target=f"ghcr.io/appthreat/blintdb-{pkg}:{db_version}",
        config_path="./.oras/config.json",
        annotation_file="./.oras/annotations.json",
        files=[
            "./blint.db:application/vnd.appthreat.blintdb.layer.v1+tar",
        ],
    )
