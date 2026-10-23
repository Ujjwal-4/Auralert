.PHONY: dev test lint install

install:
	pip install -e ".[dev]"

dev:
	uvicorn auralert.app:app --host 127.0.0.1 --port 8000 --reload

test:
	pytest tests -v

lint:
	ruff check .
	ruff format --check .
