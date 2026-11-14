PYTHON ?= .venv\Scripts\python.exe

.PHONY: install test up down compose-check

install:
	$(PYTHON) -m pip install -r requirements.txt

test:
	$(PYTHON) -m pytest -q

down:
	docker compose down -v

up:
	docker compose up --build

compose-check:
	docker compose config --quiet
