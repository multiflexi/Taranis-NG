.ONESHELL:

deps: dependencies
deps-dev: dependencies-dev
deps-basic-dev: deps deps-dev
deps-all: deps deps-dev playwright-install

html-lint: djlint
type-check: mypy
ruff-format-check: ruff-check-format
ruff-all: ruff-check-format ruff-lint
lint: djlint ruff-all pylint mypy

dirs:
	-mkdir reports
	-mkdir archive
	-mkdir archive/unsuccessful
	-mkdir archive/successful
	-mkdir archive/idea
	-mkdir archive/logs

dependencies:
	export POETRY_VIRTUALENVS_IN_PROJECT=true && poetry install --no-root --without dev

dependencies-dev:
	export POETRY_VIRTUALENVS_IN_PROJECT=true && poetry install --only dev --no-root

playwright-install:
	poetry run playwright install chromium --with-deps

playwright-codegen:
	poetry run playwright codegen localhost:5000

upgrade:
	git stash
	git pull
	make deps
	git stash pop
	systemctl reload apache2

test:
	poetry run pytest

ruff-lint:
	poetry run ruff check lib

ruff-lint-fix:
	poetry run ruff check lib --fix

ruff-check-format:
	poetry run ruff format lib --check

ruff-format:
	poetry run ruff format lib

pylint:
	poetry run pylint lib -j`nproc`

djlint:
	poetry run djlint lib/web/**/*.html

djlint-check:
	poetry run djlint lib/web/**/*.html --check

djlint-format:
	poetry run djlint lib/web/**/*.html --reformat

mypy:
	poetry run mypy lib

process-incoming:
	PYTHONPATH=. poetry run python3 lib/report/process_incoming.py --debug

rescan:
	PYTHONPATH=. poetry run python3 lib/event/rescan.py --debug

web-launch:
	PYTHONPATH=. poetry run python3 lib/web/app.py
