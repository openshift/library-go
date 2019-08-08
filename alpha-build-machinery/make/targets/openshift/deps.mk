self_dir :=$(dir $(lastword $(MAKEFILE_LIST)))
scripts_dir :=$(self_dir)/../../../scripts

# We need to force localle so different envs sort files the same way for recursive traversals
deps_diff :=LC_COLLATE=C diff --no-dereference -N

define force-symlink
	ln -sfn '$(1)' '$(2)'

endef

define k8s-symlink-staging
	$(foreach \
		repo, \
		$(shell find ./vendor/k8s.io/kubernetes/staging/src/k8s.io/ -mindepth 1 -maxdepth 1 -type d -printf '%P\n' | LC_COLLATE=C sort -h), \
		$(call force-symlink,kubernetes/staging/src/k8s.io/$(repo),./vendor/k8s.io/$(repo)) \
	)
endef

update-deps:
	$(scripts_dir)/$@.sh
	$(call k8s-symlink-staging)
.PHONY: update-deps

# $1 - temporary directory to restore vendor dependencies from glide.lock
define restore-deps
	ln -s $(abspath ./) "$(1)"/current
	cp -R -H ./ "$(1)"/updated
	$(RM) -r "$(1)"/updated/vendor
	cd "$(1)"/updated && glide install --strip-vendor && find ./vendor -name '.hg_archival.txt' -delete
	cd "$(1)" && $(deps_diff) -r {current,updated}/vendor/ > updated/glide.diff || true
	$(call k8s-symlink-staging)
endef

verify-deps: tmp_dir:=$(shell mktemp -d)
verify-deps:
	$(call restore-deps,$(tmp_dir))
	@echo $(deps_diff) '$(tmp_dir)'/{current,updated}/glide.diff
	@     $(deps_diff) '$(tmp_dir)'/{current,updated}/glide.diff || ( \
		echo "ERROR: Content of 'vendor/' directory doesn't match 'glide.lock' and the overrides in 'glide.diff'!" && \
		echo "If this is an intentional change (a carry patch) please update the 'glide.diff' using 'make update-deps-overrides'." && \
		exit 1 \
	)
.PHONY: verify-deps

update-deps-overrides: tmp_dir:=$(shell mktemp -d)
update-deps-overrides:
	$(call restore-deps,$(tmp_dir))
	cp "$(tmp_dir)"/{updated,current}/glide.diff
.PHONY: update-deps-overrides
