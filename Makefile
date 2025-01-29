all: build
.PHONY: all

# All the go packages (e.g. for verfy)
GO_PACKAGES :=./pkg/...
# Packages to be compiled
GO_BUILD_PACKAGES :=$(GO_PACKAGES)
# Do not auto-expand packages for libraries or it would compile them separately
GO_BUILD_PACKAGES_EXPANDED :=$(GO_BUILD_PACKAGES)

include $(addprefix ./vendor/github.com/openshift/build-machinery-go/make/, \
	golang.mk \
	targets/openshift/deps.mk \
)

.PHONY: update-podnetworkconnectivitychecks
update: update-podnetworkconnectivitychecks
update-podnetworkconnectivitychecks:
	$(MAKE) -C pkg/operator/connectivitycheckcontroller update

.PHONY: verify-podnetworkconnectivitychecks
verify: verify-podnetworkconnectivitychecks
verify-podnetworkconnectivitychecks:
	$(MAKE) -C pkg/operator/connectivitycheckcontroller verify

test-e2e-encryption: GO_TEST_PACKAGES :=./test/e2e-encryption/...
.PHONY: test-e2e-encryption

test-e2e-monitoring: GO_TEST_PACKAGES :=./test/e2e-monitoring/...
test-e2e-monitoring: GO_TEST_FLAGS += -v
test-e2e-monitoring: test-unit
.PHONY: test-e2e-monitoring
