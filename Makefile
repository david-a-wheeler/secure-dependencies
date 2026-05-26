# makefile to perform CI/CD process
# Each validation target has a corresponding job in
# .github/workflows/ci.yml. When adding a new validation target,
# add a corresponding job there too.

PYTHON ?= python3

# Default - validate in many different ways to detect problems
all: test syntax_valid typecheck lint emdash validate_skill
	@echo Verification complete

test:
	@echo "Running unit and integration tests..."
	$(PYTHON) -m unittest discover -s scripts/tests -b

syntax_valid:
	@echo "Checking Python syntax of scripts:"
	$(PYTHON) -m py_compile scripts/*.py
	@echo 'OK'

typecheck:
	@echo "Type-checking Python scripts with pyright:"
	@if command -v pyright > /dev/null 2>&1; then \
            set -x; \
	    pyright; \
	else \
	    echo 'SKIPPED: pyright not found'; \
	fi
	@echo 'OK'

lint:
	@echo "Linting Python scripts with ruff:"
	@if command -v ruff > /dev/null 2>&1; then \
            set -x; \
	    ruff check scripts/; \
	else \
	    echo 'SKIPPED: ruff not found'; \
	fi
	@echo 'OK'

emdash:
	@echo "Checking for em or en dashes:"
	@if find . \
	    -path ./.git -prune -o \
	    -path ./scripts/temp -prune -o \
	    -path '*/__pycache__' -prune -o \
	    -name ',*' -prune -o \
	    -type f -exec grep -HInF \
	        -e "$$(printf '\342\200\224')" \
	        -e "$$(printf '\342\200\223')" {} +; \
	then \
	    echo "FAILED: em or en dashes found (see above)"; \
	    exit 1; \
	fi
	@echo 'OK'

validate_skill:
	@echo "Validating SKILL.md frontmatter:"
	$(PYTHON) scripts/validate_skill.py
	@echo 'OK'

.PHONY: all test syntax_valid typecheck lint emdash validate_skill
