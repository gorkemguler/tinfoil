# tinfoil - no build step, just the useful commands in one place.

PYTHON ?= python3

.PHONY: help test audit json gif clean

help:
	@echo 'make test   - run the unit tests'
	@echo 'make audit  - audit this machine, showing skipped checks'
	@echo 'make json   - write report.json'
	@echo 'make gif    - re-record the README recordings (needs vhs)'

test:
	$(PYTHON) -m unittest -v test_tinfoil

audit:
	$(PYTHON) tinfoil.py --all

json:
	$(PYTHON) tinfoil.py --json > report.json
	@echo 'wrote report.json'

# Regenerate assets/demo.gif and assets/ci.gif. Run from the repository root:
# the tapes invoke ./tinfoil.py by relative path. See scripts/render-gif.sh for
# why the encode is done there rather than by vhs itself.
gif:
	./scripts/render-gif.sh assets/demo.tape
	./scripts/render-gif.sh assets/ci.tape

clean:
	rm -rf __pycache__ report.json
