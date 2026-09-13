.PHONY: help install install-dev test test-gui lint run gui clean docker-build

PY ?= .venv/bin/python
PIP ?= .venv/bin/pip

help:
	@echo "install      create venv and install the package + GUI"
	@echo "test         run the test suite (headless)"
	@echo "run          list all CLI tools"
	@echo "gui          launch the desktop app"
	@echo "clean        remove caches"

install:
	python3 -m venv .venv
	$(PIP) install --upgrade pip
	$(PIP) install -e '.[gui,dev]'

test:
	QT_QPA_PLATFORM=offscreen $(PY) -m pytest -q

run:
	.venv/bin/sec-toolkit list

gui:
	.venv/bin/sec-toolkit-gui

docker-build:
	docker build -t sec-toolkit:lab .

clean:
	rm -rf .pytest_cache build dist *.egg-info
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +