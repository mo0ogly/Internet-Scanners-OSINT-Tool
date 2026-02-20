.PHONY: install test lint lint-fix clean menu gui gui-mx docker-build docker-run docker-menu

install:
	pip install -e ".[dev]"

test:
	pytest tests/ -v --cov=. --cov-report=term-missing

lint:
	ruff check .

lint-fix:
	ruff check --fix .

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	rm -rf .coverage htmlcov *.egg-info dist build

menu:
	python3 menu.py

gui:
	python3 gui_scanner.py

gui-mx:
	python3 gui_Reverse_MX_Lookup_Tool.py

docker-build:
	docker build -t internet-scanners-osint .

docker-run:
	docker run --rm -v "$$(pwd)/results:/app/results" internet-scanners-osint scanner --run

docker-menu:
	docker run --rm -it -v "$$(pwd)/results:/app/results" internet-scanners-osint menu
