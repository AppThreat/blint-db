import oras.client

client = oras.client.OrasClient()

input_value = input().split(";;")

client.login(password=input_value[1], username=input_value[0])

client.push(
    name="ghcr.io/appthreat/blintdb-meson:v0.1",
    files=[
        ("./.oras/config.json", "application/vnd.oras.config.v1+json"),
        ("./.oras/annotations.json", "application/vnd.oras.annotation.v1+json"),
        ("./blint.db", "application/vnd.appthreat.vdb.layer.v1+tar"),
    ],
)