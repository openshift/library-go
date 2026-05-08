# KMSv2 health-monitor KIND harness. Disposable.
#
# All targets should be run from the library-go module root:
#   make -C examples/kms-health-kind kind-verify

CLUSTER ?= kms-health-claude
IMAGE_FAKE_PLUGIN ?= kms-health-kind-fake-plugin:dev
IMAGE_MONITOR ?= kms-health-kind-monitor:dev
CTX := kind-$(CLUSTER)
NODE := $(CLUSTER)-control-plane
FAKE_POD := kms-fake-plugin-$(NODE)

# Dockerfile build context = library-go module root (need vendor/, go.mod).
REPO_ROOT := $(shell cd ../.. && pwd -P)
HARNESS_DIR := $(shell pwd -P)

.PHONY: build-images
build-images:
	docker build -t $(IMAGE_FAKE_PLUGIN) \
		-f $(HARNESS_DIR)/Dockerfile.fake-plugin \
		$(REPO_ROOT)
	docker build -t $(IMAGE_MONITOR) \
		-f $(HARNESS_DIR)/Dockerfile.monitor \
		$(REPO_ROOT)

.PHONY: kind-up
kind-up:
	CLUSTER=$(CLUSTER) $(HARNESS_DIR)/bin/up.sh

.PHONY: kind-down
kind-down:
	CLUSTER=$(CLUSTER) $(HARNESS_DIR)/bin/down.sh

## Distroless fake-plugin has no touch/rm; flip via node /tmp (bind-mounted
## to /var/run/kmsplugin-fake/ in both pods).
.PHONY: flip-unhealthy
flip-unhealthy:
	docker exec $(NODE) touch /tmp/kms-unhealthy

.PHONY: flip-healthy
flip-healthy:
	docker exec $(NODE) rm -f /tmp/kms-unhealthy

## Drift check: diff output against monitor-deployment.yaml's container block.
.PHONY: render-container
render-container:
	go run $(REPO_ROOT)/examples/kms-health-kind/cmd/render-container \
		--kms-plugin-name=fake \
		--image=$(IMAGE_MONITOR) \
		--command=/usr/bin/kms-health-monitor \
		--probe-interval=2s \
		--probe-interval-unhealthy=1s \
		--probe-timeout=1s \
		--write-timeout=5s \
		--configmap-namespace=kms-health-test

.PHONY: verify
verify:
	CLUSTER=$(CLUSTER) $(HARNESS_DIR)/verify.sh

.PHONY: kind-verify
kind-verify: build-images kind-up verify
	@echo ""
	@echo "================================================="
	@echo "  kind-verify PASSED on cluster ${CLUSTER}"
	@echo "  tear down with:  make kind-down"
	@echo "================================================="

.PHONY: cm
cm:
	kubectl --context $(CTX) -n kms-health-test get cm kms-health-fake -o yaml
