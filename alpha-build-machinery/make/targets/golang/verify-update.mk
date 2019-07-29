self_dir :=$(dir $(lastword $(MAKEFILE_LIST)))

go_files_count :=$(words $(GO_FILES))

GOSEC_GOPATH :=$(shell mktemp -d)

verify-gofmt:
	$(info Running `$(GOFMT) $(GOFMT_FLAGS)` on $(go_files_count) file(s).)
	@TMP=$$( mktemp ); \
	$(GOFMT) $(GOFMT_FLAGS) $(GO_FILES) | tee $${TMP}; \
	if [ -s $${TMP} ]; then \
		echo "$@ failed - please run \`make update-gofmt\`"; \
		exit 1; \
	fi;
.PHONY: verify-gofmt

update-gofmt:
	$(info Running `$(GOFMT) $(GOFMT_FLAGS) -w` on $(go_files_count) file(s).)
	@$(GOFMT) $(GOFMT_FLAGS) -w $(GO_FILES)
.PHONY: update-gofmt


verify-govet:
	$(GO) vet $(GO_PACKAGES)
.PHONY: verify-govet

verify-golint:
	$(GOLINT) $(GO_PACKAGES)
.PHONY: verify-govet

verify-gosec: update-gosec
ifeq (, $(shell which $(GOSEC) 2>/dev/null))
	$(GOSEC_GOPATH)/bin/$(GOSEC) \
		-severity $(GOSEC_SEVERITY) -confidence $(GOSEC_CONFIDENCE) \
		-exclude $(GOSEC_EXCLUDE) \
		-quiet $(GO_PACKAGES)
else
	$(GOSEC) \
		-severity $(GOSEC_SEVERITY) -confidence $(GOSEC_CONFIDENCE) \
		-exclude $(GOSEC_EXCLUDE) \
		-quiet $(GO_PACKAGES)
endif
.PHONY: verify-gosec

update-gosec:
ifeq (, $(shell which $(GOSEC) 2>/dev/null))
	GOPATH=$(GOSEC_GOPATH) GOBIN=$(GOSEC_GOPATH)/bin GO111MODULE=on go get github.com/securego/gosec/cmd/gosec@4b59c948083cd711b6a8aac8f32721b164899f57
endif
.PHONY: update-gosec


# We need to be careful to expand all the paths before any include is done
# or self_dir could be modified for the next include by the included file.
# Also doing this at the end of the file allows us to use self_dir before it could be modified.
include $(addprefix $(self_dir), \
	../../lib/golang.mk \
)
