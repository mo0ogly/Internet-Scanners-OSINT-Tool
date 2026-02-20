.PHONY: install test lint lint-fix clean docker-build docker-run

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

docker-build:
	docker build -t internet-scanners-osint .

docker-run:
	docker run --rm -v "$$(pwd)/results:/app/results" internet-scanners-osint scanner --run
