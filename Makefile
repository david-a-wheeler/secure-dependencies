.PHONY: all test emdash

all: test emdash
	@echo Verification complete

test:
	python3 -m unittest discover -s references/scripts/tests -v

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
