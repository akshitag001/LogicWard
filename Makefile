.PHONY: test lint doctest screenshots snapshots demo

test:
	pytest -q

lint:
	ruff check logicward tests

doctest:
	pytest --doctest-modules logicward/engine -q

# Needs: pip install -e ".[dev]" ; playwright install chromium ; ffmpeg on PATH
screenshots:
	python scripts/capture_screenshots.py

snapshots:
	python scripts/code_snapshots.py

demo:
	python -m logicward demo
