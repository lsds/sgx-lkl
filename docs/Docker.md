# Docker

The SGX-LKL runtime does not have a dependency on Docker. It can be used in many different scenarios and should first and foremost be understood as a command-line tool which runs a program contained in a Linux disk image file according to some configuration.

This document describes how SGX-LKL fits into the Docker ecosystem, covering topics such as conversion of existing Docker images into disk image and configuration files and re-packaging them into regular Docker images for deployment.

## Terminology

**Docker image**: Contents of a filesystem (files, folders, and their metadata) arranged in layers together with default parameters. Typically created with `docker build` from a `Dockerfile` and pushed to a registry like Docker Hub. Note that Docker images have since been standardized as *OCI images* and can now be created and consumed by other tools than Docker.

**Docker container**: An environment bootstrapped from a Docker image for executing processes with configurable isolation and resource limitations. Note that `docker run` is a combination of `docker create` for creating the container from an image, and `docker start` for starting the primary process within the container. Note that Docker containers have since been standardized as *OCI containers* and can now be created and run by other runtimes than Docker.

**Disk image file**: Often just called disk image, a file that contains a bit-for-bit copy of an entire storage device (which may have multiple partitions) or a disk volume (single partition/filesystem). In the context of SGX-LKL, disk images contain a single filesystem (ext4) and are optionally encrypted (dm-crypt) and integrity-protected (dm-integrity/dm-verity). Note that SGX-LKL disk images are standard Linux disk images.

## Conversion of existing Docker images

While disk image files for SGX-LKL can be created in many ways, a convenient method is to take existing Docker images and convert them.

As an example, we use the `python:3-alpine3.10` image from Docker Hub:
```sh
docker pull python:3-alpine3.10
docker run --rm python:3-alpine3.10 python3 -c "print('Hello world!')"
```

SGX-LKL provides tools to convert the Docker image into a disk image and configuration files:
```sh
sgx-lkl-disk create --size=100M --docker=python:3-alpine3.10 python.img
sgx-lkl-cfg create --disk python.img --host-cfg host-cfg.json --app-cfg app-cfg.json
```

Open `app-cfg.json` and adjust the `"args"` field:
```
"args": ["-c", "print('Hello world!')"],
```

We can now run the converted image with SGX-LKL:
```sh
sgx-lkl-run-oe --host-config=host-cfg.json --app-config=app-cfg.json --hw-debug
```

## Re-packaging as Docker image

SGX-LKL together with disk images and configuration files can be run as command-line tool in various environments. In order to run SGX-LKL in environments that require Docker images (like Kubernetes) we need to re-package the disk image, configuration files, and optionally SGX-LKL itself, as Docker image.

Continuing from the previous section we start with three files:
- `python.img`
- `host-cfg.json`
- `app-cfg.json`

Currently, the tooling of SGX-LKL assumes that SGX-LKL is not part of the Docker image but instead mounted into the Docker container from the host. In the same spirit as the Docker runtime, this allows independent updating of SGX-LKL without requiring to rebuild Docker images.

Re-package as Docker image:
```sh
sgx-lkl-docker build --name=python-sgxlkl --host-cfg=host-cfg.json --app-cfg=app-cfg.json
```

Note that the Docker image is minimal and does not contain a Linux distribution.
The entrypoint of the image launches the SGX-LKL runtime with the packaged configuration files.

Run the image with Docker:
```sh
# Adjust /opt/sgx-lkl-debug accordingly, depending on your SGX-LKL installation.
docker run --rm -v /opt/sgx-lkl-debug:/opt/sgx-lkl --device /dev/sgx python-sgxlkl --hw-debug
```

Note that `/opt/sgx-lkl-debug` must be a self-contained installation in order to be mountable. This is the case when installing SGX-LKL from the Debian packages. When building from source, after `make install`, you need to run `tools/make_self_contained.sh` to make the installation self-contained.

## Deployment to Kubernetes

TBD:
- Networking
- SGX-LKL daemonset
