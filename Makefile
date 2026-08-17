# cosmo — common tasks. `make help` lists them.
.DEFAULT_GOAL := help

.PHONY: help install uninstall deb test plugin-check

help:  ## show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

install:  ## install cosmo into a local venv + put it on PATH (no root)
	./scripts/install.sh

uninstall:  ## remove the local venv install
	./scripts/install.sh --uninstall

deb:  ## build a self-contained .deb into dist/
	./packaging/build-deb.sh

test:  ## run the hermetic test suite
	PYTHONPATH=src python3 -m pytest -q

plugin-check:  ## fail if the Claude Code plugin surface is out of date
	PYTHONPATH=src python3 -m cosmo plugin check --root .
