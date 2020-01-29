missing_shellstatus_message :=Your make version "$(MAKE_VERSION)" doesn't support `.SHELLSTATUS`. `.SHELLSTATUS` requires GNU make >= 4.2.

$(shell true)
ifndef .SHELLSTATUS
ifndef IGNORE_SUBSHELL_EXITCODES
$(error $(missing_shellstatus_message) To force running it without `.SHELLSTATUS` use `make IGNORE_SUBSHELL_EXITCODES=yes` or set it as environment variable `export IGNORE_SUBSHELL_EXITCODES=yes`)
else
ifndef ignore_subshell_exitcodes_warning_shown
$(warning $(missing_shellstatus_message) Overriden by setting IGNORE_SUBSHELL_EXITCODES variable.)
ignore_subshell_exitcodes_warning_shown :=yes
endif
endif
endif

define error_if_shell_failed
$(if $(filter $(.SHELLSTATUS),0),,$(error $(1)))
endef
