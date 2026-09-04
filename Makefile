.PHONY: test smoke qa run init install clean

test:
	PYTHONPATH=src python3 -m unittest discover -s tests -v

smoke:
	bash scripts/smoke.sh

qa:
	python3 scripts/qa_checks.py

run:
	PYTHONPATH=src python3 -m ksec

init:
	PYTHONPATH=src python3 -m ksec init

install:
	pip install -e .

clean:
	find . -name '__pycache__' -type d -exec rm -rf {} +
	rm -rf .pytest_cache build dist *.egg-info