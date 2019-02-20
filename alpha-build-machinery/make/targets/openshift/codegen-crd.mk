self_dir := $(dir $(lastword $(MAKEFILE_LIST)))

CODEGEN_CRD ?=go run $(shell realpath $(self_dir)/../../../cmd/crd-schema-gen/main.go)
CODEGEN_CRD_APIS_WILDCARD ?="*"
CODEGEN_CRD_MANIFESTS_DIR ?=manifests

CODEGEN_CRD_API_PACKAGE ?=$(error CODEGEN_CRD_API_PACKAGE is required)
CODEGEN_CRD_OUTPUT_BASE ?=$(error CODEGEN_CRD_OUTPUT_BASE is required)

define run-codegen-crd
$(CODEGEN_CRD) \
	--api-dirs="$(CODEGEN_CRD_API_PACKAGE)" \
	--apis="$(CODEGEN_CRD_APIS_WILDCARD)" \
	--manifests-dir="$(CODEGEN_CRD_MANIFESTS_DIR)" \
	--output-dir="$(CODEGEN_CRD_OUTPUT_BASE)" \
    $1
endef


verify-codegen-crd:
	$(call run-codegen-crd,--verify-only)
.PHONY: verify-codegen

verify-generated: verify-codegen-crd
.PHONY: verify-generated


update-codegen-crd:
	$(call run-codegen-crd)
.PHONY: update-codegen-crd

update-generated: update-codegen-crd
.PHONY: update-generated
