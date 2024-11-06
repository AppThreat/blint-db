import oras.client
import os

client = oras.client.OrasClient()

input_value = input().split(";;")

client.login(password=input_value[1], username=input_value[0])

print(os.getcwd())

client.push(
    target="ghcr.io/appthreat/blintdb-meson:v0.1",
    config_path="./.oras/config.json",
    annotation_file="./.oras/annotations.json",
    files=[
        "./blint.db:application/vnd.appthreat.blintdb.layer.v1+tar",
    ],
)