CONTAINERIZE_RUNTIME ?=$(shell command -v podman || command -v docker || echo 'failed_to_detect_container_runtime')
CONTAINERIZE_RUNOPTS ?=-i -t --rm

define containerized-target-internal
$(1)-containerized: CONTAINERIZE_IMAGE:=$(2)
$(1)-containerized: CONTAINERIZE_MOUNTOPTS:=-v '$(shell pwd)/:$(3)/'
$(1)-containerized:
	'$$(CONTAINERIZE_RUNTIME)' run $$(CONTAINERIZE_RUNOPTS) $$(CONTAINERIZE_MOUNTOPTS) '$$(CONTAINERIZE_IMAGE)' bash -c "$(MAKE) -C '$(3)' '$(1)' MAKEFLAGS:=$$(MAKEFLAGS)"
.PHONY: $(1)-containerized

endef

# $1 - image
# $2 - targets (separated-by-space)
# $3 - srcdir
define containerize-targets
$(foreach t,$(1),$(eval $(call containerized-target-internal,$(t),$(2),$(3))))
endef
