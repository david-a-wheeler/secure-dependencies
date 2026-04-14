PYTHON ?= python3

all: test syntax_valid emdash
	@echo Verification complete

test:
	$(PYTHON) -m unittest discover -s references/scripts/tests -v

syntax_valid:
	@echo "Checking Python syntax of scripts:"
	$(PYTHON) -m py_compile references/scripts/*.py
	@echo 'OK, no syntax errors found'

emdash:
	@echo "Finding lines in textual format files with em or en dashes:"
	@! find . \
	    -path ./.git -prune -o \
	    -path ./references/scripts/temp -prune -o \
	    -path '*/__pycache__' -prune -o \
	    -type f -print0 | xargs -0 grep -HInF \
	        -e "$$(printf '\342\200\224')" \
	        -e "$$(printf '\342\200\223')"
	@echo 'OK, no issues found'

.PHONY: all test syntax_valid emdash
