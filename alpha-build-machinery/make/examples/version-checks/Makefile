include $(addprefix ../../, \
	lib/version.mk \
)

PROGRAM_NAME :=go

REQUIRED_VERSION :=1.12.5

CURRENT_VERSION :=1.13.1

all:
	@echo "version is correct"
.PHONY: all

$(call require_minimal_version,$(PROGRAM_NAME),REQUIRED_VERSION,$(CURRENT_VERSION))
