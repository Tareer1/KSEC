.PHONY: test smoke run init install clean

test:
	PYTHONPATH=src python3 -m unittest discover -s tests -v

smoke:
	bash scripts/smoke.sh

run:
	PYTHONPATH=src python3 -m ksec

init:
	PYTHONPATH=src python3 -m ksec init

install:
	pip install -e .

clean:
	find . -name '__pycache__' -type d -exec rm -rf {} +
	rm -rf .pytest_cache build dist *.egg-info