# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT

import argparse
import os
from pathlib import Path

import oras.client

client = oras.client.OrasClient()

token = os.getenv("GITHUB_TOKEN", "")
username = os.getenv("GITHUB_USERNAME", "")
db_version = os.getenv("BLINT_DB_VERSION", "v2")
db_file = os.getenv("BLINT_DB_FILE", "./blint.db")
metadata_file = os.getenv("BLINT_DB_METADATA_FILE")
registry = os.getenv("REGISTRY", "ghcr.io")
image_name = os.getenv("IMAGE_NAME", "appthreat/blintdb")
client.login(hostname=registry, password=token, username=username)


def default_metadata_path(db_path: str) -> str:
    path_obj = Path(db_path)
    if path_obj.suffix:
        return str(path_obj.with_suffix(".metadata.json"))
    return str(path_obj.with_name(f"{path_obj.name}.metadata.json"))

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
    files = [
        f"{db_file}:application/vnd.appthreat.blintdb.layer.v1+tar",
    ]
    resolved_metadata_file = metadata_file or default_metadata_path(db_file)
    if Path(resolved_metadata_file).exists():
        files.append(
            f"{resolved_metadata_file}:application/vnd.appthreat.blintdb.metadata.v1+json"
        )
    client.push(
        target=f"{registry}/{image_name}-{pkg}:{db_version}",
        config_path="./.oras/config.json",
        annotation_file="./.oras/annotations.json",
        files=files,
    )
