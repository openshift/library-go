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
	targets/openshift/bindata.mk \
)

$(call add-bindata,backingresources,./pkg/operator/staticpod/controller/backingresource/manifests/...,bindata,bindata,./pkg/operator/staticpod/controller/backingresource/bindata/bindata.go)
$(call add-bindata,monitoring,./pkg/operator/staticpod/controller/monitoring/manifests/...,bindata,bindata,./pkg/operator/staticpod/controller/monitoring/bindata/bindata.go)
$(call add-bindata,installer,./pkg/operator/staticpod/controller/installer/manifests/...,bindata,bindata,./pkg/operator/staticpod/controller/installer/bindata/bindata.go)
$(call add-bindata,staticpod,./pkg/operator/staticpod/controller/prune/manifests/...,bindata,bindata,./pkg/operator/staticpod/controller/prune/bindata/bindata.go)
$(call add-bindata,auditpolicies,./pkg/operator/apiserver/audit/manifests/...,bindata,bindata,./pkg/operator/apiserver/audit/bindata/bindata.go)
$(call add-bindata,podnetworkconnectivitychecks,pkg/operator/connectivitycheckcontroller/manifests/...,bindata,bindata,pkg/operator/connectivitycheckcontroller/bindata/bindata.go)

pkg/operator/connectivitycheckcontroller/manifests/controlplane.operator.openshift.io_podnetworkconnectivitychecks.yaml: vendor/github.com/openshift/api/operatorcontrolplane/v1alpha1/0000_10-pod-network-connectivity-check.crd.yaml
	mkdir -p $$(dirname $@)
	cp $< $@

update-bindata-podnetworkconnectivitychecks: pkg/operator/connectivitycheckcontroller/manifests/controlplane.operator.openshift.io_podnetworkconnectivitychecks.yaml

verify-bindata-podnetworkconnectivitychecks-manifests:
	diff -Naup pkg/operator/connectivitycheckcontroller/manifests/controlplane.operator.openshift.io_podnetworkconnectivitychecks.yaml vendor/github.com/openshift/api/operatorcontrolplane/v1alpha1/0000_10-pod-network-connectivity-check.crd.yaml
.PHONY: verify-bindata-podnetworkconnectivitychecks-manifests

verify-bindata-podnetworkconnectivitychecks: verify-bindata-podnetworkconnectivitychecks-manifests

test-e2e-encryption: GO_TEST_PACKAGES :=./test/e2e-encryption/...
.PHONY: test-e2e-encryption
