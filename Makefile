DOCKER    = docker

BASE_REPO = cloudflare/quiche
BASE_TAG  = latest

QNS_REPO  = cloudflare/quiche-qns
QNS_TAG   = latest

docker-build: docker-base docker-qns

# build quiche-apps only
.PHONY: build-apps
build-apps:
	cargo build --manifest-path tools/apps/Cargo.toml

# build base image
.PHONY: docker-base
docker-base: build-apps Dockerfile
	$(DOCKER) build --target quiche-base -t $(BASE_REPO):$(BASE_TAG) .

# build qns image
.PHONY: docker-qns
docker-qns: build-apps Dockerfile tools/qns/run_endpoint.sh
	$(DOCKER) build --target quiche-qns -t $(QNS_REPO):$(QNS_TAG) .

.PHONY: docker-publish
docker-publish:
	$(DOCKER) push $(BASE_REPO):$(BASE_TAG)
	$(DOCKER) push $(QNS_REPO):$(QNS_TAG)

.PHONY: clean
clean:
	@for id in `$(DOCKER) images -q $(BASE_REPO)` `$(DOCKER) images -q $(QNS_REPO)`; do \
		echo ">> Removing $$id"; \
		$(DOCKER) rmi -f $$id; \
	done
