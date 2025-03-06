# Introduction

[Lima](https://lima-vm.io/) launches Linux virtual machines with automatic file sharing and port forwarding (similar to WSL2).

## Getting Started

Use the below command to install lima and create a vm.

```shell
brew install lima
```

on Linux

Install qemu, qemu-img, qemu-x86 packages.

```shell
curl -LO https://github.com/lima-vm/lima/releases/download/v0.22.0/lima-0.22.0-Linux-x86_64.tar.gz
sudo tar -C /usr/local -xf lima-0.22.0-Linux-x86_64.tar.gz
```

For ubuntu, use the below command.

```shell
limactl start --name=blintdb contrib/blintdb-ubuntu-lima.yaml --tty=false
```

To open a shell to the VM:

```shell
limactl shell blintdb
```

To stop the VM:

```shell
limactl stop blintdb
```

## Troubleshooting

Monitor the installation by tailing the `/var/log/cloud-init-output.log` file.

```shell
limactl shell blintdb sudo tail -f /var/log/cloud-init-output.log
```
