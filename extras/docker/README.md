# Docker images

This directory contains a sample Dockerfile to build quiche.

## How to build

In order to build the Docker images, simply run the following command in this directory:

```
$ make all
```

## How to test

In order to test the Docker images, simply run the following command in this directory:

```
$ make test
```

# Docker Hub Repositories

You can find the quiche Docker images on the following Docker Hub repositories:

- [cloudflare/quiche](https://hub.docker.com/repository/docker/cloudflare/quiche)
- [cloudflare/quiche-qns](https://hub.docker.com/repository/docker/cloudflare/quiche-qns)

Tag `latest` will be updated when quiche master branch updates.

## cloudflare/quiche

This includes an example server and client installed in /usr/local/bin.

## cloudflare/quiche-qns

Docker files for https://github.com/marten-seemann/quic-interop-runner
