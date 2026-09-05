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
	bash install.sh   # one-command installer: venv + editable install + ksec on PATH

clean:
	find . -name '__pycache__' -type d -exec rm -rf {} +
	rm -rf .pytest_cache build dist *.egg-info