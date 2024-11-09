import argparse
import os

import oras.client

client = oras.client.OrasClient()

token = os.getenv("GITHUB_TOKEN", "")
username = os.getenv("GITHUB_USERNAME", "")

client.login(password=token, username=username)

parser = argparse.ArgumentParser(
    prog="orasclient_blintdb",
    description="Helps pushing blint.db into a container and uploading to ghcr.io",
)
parser.add_argument(
    "-p",
    "--pkg-manager",
    dest="pkg",
    help="Path to the CDXGEN bom file (NOT IMPLEMENTED)",
)
args = vars(parser.parse_args())

if pkg := args.get("pkg", None):
    # not using fstring here to make sure value is correct
    # otherwise wrong file may be uploaded
    if pkg == "vcpkg":
        client.push(
            target="ghcr.io/appthreat/blintdb-vcpkg:v0.1",
            config_path="./.oras/config.json",
            annotation_file="./.oras/annotations.json",
            files=[
                "./blint.db:application/vnd.appthreat.blintdb.layer.v1+tar",
            ],
        )
    if pkg == "meson":
        client.push(
            target="ghcr.io/appthreat/blintdb-meson:v0.1",
            config_path="./.oras/config.json",
            annotation_file="./.oras/annotations.json",
            files=[
                "./blint.db:application/vnd.appthreat.blintdb.layer.v1+tar",
            ],
        )
    if pkg == "vcpkg-tst":
        client.push(
            target="ghcr.io/appthreat/blintdb-vcpkg-tst:v0.1",
            config_path="./.oras/config.json",
            annotation_file="./.oras/annotations.json",
            files=[
                "./blint.db:application/vnd.appthreat.blintdb.layer.v1+tar",
            ],
        )
    if pkg == "meson-tst":
        client.push(
            target="ghcr.io/appthreat/blintdb-meson-tst:v0.1",
            config_path="./.oras/config.json",
            annotation_file="./.oras/annotations.json",
            files=[
                "./blint.db:application/vnd.appthreat.blintdb.layer.v1+tar",
            ],
        )
