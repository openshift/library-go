self_dir :=$(dir $(lastword $(MAKEFILE_LIST)))
scripts_dir :=$(self_dir)/../../../scripts

update-deps:
	$(scripts_dir)/$@.sh
.PHONY: update-deps
