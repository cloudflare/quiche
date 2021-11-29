DOCKER    = docker

BASE_REPO = cloudflare/quiche
BASE_TAG  = latest

QNS_REPO  = cloudflare/quiche-qns
QNS_TAG   = latest

FUZZ_REPO = mayhem.cloudflare-security.com:5000/protocols/quiche-libfuzzer
FUZZ_TAG  = latest

docker-build: docker-base docker-qns

# build quiche-apps only
.PHONY: build-apps
build-apps:
	cargo build --package=quiche_apps

# build base image
.PHONY: docker-base
docker-base: Dockerfile
	$(DOCKER) build --target quiche-base -t $(BASE_REPO):$(BASE_TAG) .

# build qns image
.PHONY: docker-qns
docker-qns: Dockerfile apps/run_endpoint.sh
	$(DOCKER) build --target quiche-qns -t $(QNS_REPO):$(QNS_TAG) .

.PHONY: docker-publish
docker-publish:
	$(DOCKER) push $(BASE_REPO):$(BASE_TAG)
	$(DOCKER) push $(QNS_REPO):$(QNS_TAG)

# build fuzzers
.PHONY: build-fuzz
build-fuzz:
	cargo +nightly fuzz build --release packet_recv_client
	cargo +nightly fuzz build --release packet_recv_server
	cargo +nightly fuzz build --release qpack_decode

# build fuzzing image
.PHONY: docker-fuzz
docker-fuzz: build-fuzz
	$(DOCKER) build --tag $(FUZZ_REPO):$(FUZZ_TAG) fuzz

.PHONY: docker-fuzz-publish
docker-fuzz-publish:
	$(DOCKER) push $(FUZZ_REPO):$(FUZZ_TAG)

.PHONY: clean
clean:
	@for id in `$(DOCKER) images -q $(BASE_REPO)` `$(DOCKER) images -q $(QNS_REPO)` `$(DOCKER) images -q $(FUZZ_REPO)`; do \
		echo ">> Removing $$id"; \
		$(DOCKER) rmi -f $$id; \
	done
