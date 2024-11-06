import oras.client
import os

client = oras.client.OrasClient()

token = os.getenv("GITHUB_USERNAME", "")
username = os.getenv("GITHUB_USERNAME", "")


client.login(password=token, username=username)

client.push(
    target="ghcr.io/appthreat/blintdb-meson:v0.1",
    config_path="./.oras/config.json",
    annotation_file="./.oras/annotations.json",
    files=[
        "./blint.db:application/vnd.appthreat.blintdb.layer.v1+tar",
    ],
)