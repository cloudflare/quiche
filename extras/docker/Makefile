#
# Simple Makefile for building docker images
#
QNSDIR    = ./qns
DOCKER    = docker

BASE_REPO = cloudflare/quiche
BASE_TAG  = latest

QNS_REPO  = cloudflare/quiche-qns
QNS_TAG   = latest

BUILD_TAG = base-build

.PHONY: build base qns test publish clean

all: build base qns

# build quiche only
build: Dockerfile
	$(DOCKER) build --target build -t $(BASE_REPO):$(BUILD_TAG) .

# run cargo test
test: build
	$(DOCKER) run --rm -w /build/quiche $(BASE_REPO):$(BUILD_TAG) cargo test

# build base image
base: Dockerfile
	$(DOCKER) build --target quiche-base -t $(BASE_REPO):$(BASE_TAG) .

# build qns image
qns: Dockerfile qns/run_endpoint.sh
	$(DOCKER) build --target quiche-qns -t $(QNS_REPO):$(QNS_TAG) .

test: base

publish: base qns
	$(DOCKER) push $(BASE_REPO):$(BASE_TAG)
	$(DOCKER) push $(QNS_REPO):$(QNS_TAG)

clean:
	@for id in `$(DOCKER) images -q $(BASE_REPO)` `$(DOCKER) images -q $(QNS_REPO)`; do \
		echo ">> Removing $$id"; \
		$(DOCKER) rmi -f $$id; \
	done
