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
# the tapes invoke ./tinfoil.py by relative path.
gif:
	@command -v vhs >/dev/null 2>&1 || { \
	  echo 'vhs not found. Install it with:'; \
	  echo '  brew install vhs'; \
	  echo '  go install github.com/charmbracelet/vhs@latest'; \
	  exit 1; }
	vhs assets/demo.tape
	vhs assets/ci.tape
	@echo 'wrote assets/demo.gif and assets/ci.gif'

clean:
	rm -rf __pycache__ report.json
