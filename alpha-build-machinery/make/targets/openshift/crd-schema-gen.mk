CRD_SCHEMA_GEN_VERSION ?=v0.2.1
CRD_SCHEMA_GEN_APIS ?=$(error CRD_SCHEMA_GEN_APIS is required) 
CRD_SCHEMA_GEN_TEMP ?=_output/tools/src/sigs.k8s.io/controller-tools
CRD_SCHEMA_GEN_OUTPUT ?=./manifests

crd-schema-gen:
	if [ ! -d $(CRD_SCHEMA_GEN_TEMP) ]; then \
		mkdir -p $(CRD_SCHEMA_GEN_TEMP); \
		git clone -b $(CRD_SCHEMA_GEN_VERSION) --single-branch --depth 1 https://github.com/kubernetes-sigs/controller-tools.git $(CRD_SCHEMA_GEN_TEMP); \
		mkdir -p $(CRD_SCHEMA_GEN_TEMP)/bin; \
		export GOPATH=$(shell pwd)/_output/tools/ && export GOBIN=$(shell pwd)/_output/tools/bin/ && cd $(CRD_SCHEMA_GEN_TEMP) && export GO111MODULE=on && go mod vendor && go install -mod=vendor ./cmd/controller-gen/...; \
	fi
.PHONY: crd-schema-gen

update-codegen-crds: crd-schema-gen
	./_output/tools/bin/controller-gen \
		schemapatch:manifests=./manifests \
		output:dir=$(CRD_SCHEMA_GEN_OUTPUT) \
		paths="$(subst $() $(),;,$(CRD_SCHEMA_GEN_APIS))"
.PHONY: update-codegen-crds

# crd-schema-update-with-patch should be used for repos with yaml patches. It calls update-codegen-crds then applies any patches after first copying any patch files to the output directory (to ensure that verify works since that target runs in a temp dir). It depends on the `yq` tool to merge yaml
crd-schema-update-with-patch: update-codegen-crds
	if [ ! -f ./_output/tools/bin/yq ]; then \
		curl -f -L -o ./_output/tools/bin/yq https://github.com/mikefarah/yq/releases/download/2.4.0/yq_$(shell uname -s | tr A-Z a-z)_amd64 && chmod +x ./_output/tools/bin/yq; \
	fi
	if [ $(CRD_SCHEMA_GEN_OUTPUT) != "./manifests" ]; then \
		cp -n ./manifests/*.crd.yaml-merge-patch $(CRD_SCHEMA_GEN_OUTPUT)/.; \
	fi
	set -euo pipefail && for p in $(CRD_SCHEMA_GEN_OUTPUT)/*.crd.yaml-merge-patch; do ./_output/tools/bin/yq m -i "$${p%%.crd.yaml-merge-patch}.crd.yaml" "$$p"; done
.PHONY: crd-schema-patch

verify-codegen-crds: CRD_SCHEMA_GEN_OUTPUT :=$(shell mktemp -d)
verify-codegen-crds: crd-schema-update-with-patch
	diff -Naup ./manifests $(CRD_SCHEMA_GEN_OUTPUT)
.PHONY: verify-codegen-crds
