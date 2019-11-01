all: build
.PHONY: all

GO_BUILD_PACKAGES :=./cmd/migrator
GO_TEST_PACKAGES :=./pkg/...

include $(addprefix ./vendor/github.com/openshift/library-go/alpha-build-machinery/make/, \
	golang.mk \
	targets/openshift/images.mk \
)

IMAGE_REGISTRY :=registry.svc.ci.openshift.org
$(call build-image,migrator,$(IMAGE_REGISTRY)/ocp/4.3:migrator,./images/ci/Dockerfile,.)

