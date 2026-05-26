PYTHON ?= python3

all: test syntax_valid typecheck lint emdash validate
	@echo Verification complete

test:
	$(PYTHON) -m unittest discover -s scripts/tests -v

syntax_valid:
	@echo "Checking Python syntax of scripts:"
	$(PYTHON) -m py_compile scripts/*.py
	@echo 'OK, no syntax errors found'

typecheck:
	@echo "Type-checking Python scripts with pyright:"
	@if command -v pyright > /dev/null 2>&1; then \
	    pyright; \
	    echo 'OK, no type errors found'; \
	else \
	    echo 'WARNING: pyright not found; skipping (install: pip install pyright)'; \
	fi

lint:
	@echo "Linting Python scripts with ruff:"
	@if command -v ruff > /dev/null 2>&1; then \
	    ruff check scripts/; \
	    echo 'OK, no lint errors found'; \
	else \
	    echo 'WARNING: ruff not found; skipping (install: pip install ruff)'; \
	fi

emdash:
	@echo "Finding lines in textual format files with em or en dashes:"
	@! find . \
	    -path ./.git -prune -o \
	    -path ./scripts/temp -prune -o \
	    -path '*/__pycache__' -prune -o \
	    -name ',*' -prune -o \
	    -type f -print0 | xargs -0 grep -HInF \
	        -e "$$(printf '\342\200\224')" \
	        -e "$$(printf '\342\200\223')"
	@echo 'OK, no issues found'

validate:
	@echo "Validating SKILL.md frontmatter:"
	$(PYTHON) scripts/validate_skill.py

.PHONY: all test syntax_valid typecheck lint emdash validate
