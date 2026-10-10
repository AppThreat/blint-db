# SPDX-FileCopyrightText: AppThreat <cloud@appthreat.com>
#
# SPDX-License-Identifier: MIT

import argparse
import os
from pathlib import Path

token = os.getenv("GITHUB_TOKEN", "")
username = os.getenv("GITHUB_USERNAME", "")
db_version = os.getenv("BLINT_DB_VERSION", "v4")
db_file = os.getenv("BLINT_DB_FILE", "./blint.db")
metadata_file = os.getenv("BLINT_DB_METADATA_FILE")
registry = os.getenv("REGISTRY", "ghcr.io")
image_name = os.getenv("IMAGE_NAME", "appthreat/blintdb")

DB_LAYER_MEDIA_TYPE = "application/vnd.appthreat.blintdb.layer.v1+tar"
METADATA_LAYER_MEDIA_TYPE = "application/vnd.appthreat.blintdb.metadata.v1+json"


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
        (f"{db_file}", DB_LAYER_MEDIA_TYPE),
    ]
    resolved_metadata_file = metadata_file or default_metadata_path(db_file)
    if Path(resolved_metadata_file).exists():
        files.append((resolved_metadata_file, METADATA_LAYER_MEDIA_TYPE))

    target = f"{registry}/{image_name}-{pkg}:{db_version}"
    if os.getenv("BLINT_DB_ORAS_CLIENT", "stream") == "python":
        # Legacy path: the Python oras client buffers each layer fully in
        # memory before uploading, which OOMs on multi-GB databases.
        import oras.client

        client = oras.client.OrasClient()
        client.login(hostname=registry, password=token, username=username)
        client.push(
            target=target,
            config_path="./.oras/config.json",
            annotation_file="./.oras/annotations.json",
            files=[f"{path}:{media_type}" for path, media_type in files],
        )
    else:
        from blint_db.utils.oci_push import stream_push

        manifest_digest = stream_push(
            target,
            files,
            annotation_file="./.oras/annotations.json",
            username=username,
            password=token,
            insecure=os.getenv("BLINT_DB_ORAS_INSECURE", "") == "1",
        )
        print(f"Pushed {target} ({manifest_digest})")
