.PHONY: convert check lint test datasets

convert:  ## regenerate converted/ from sigma/
	python -m dwellwatch.convert

check:    ## fail if converted/ is out of date
	python -m dwellwatch.convert --check

lint:
	ruff check
	shellcheck datasets/fetch.sh

test:
	pytest

datasets: ## fetch the replay datasets
	datasets/fetch.sh
