.PHONY: run test lint format clean

run:
	uvicorn mcp_auth_test_server.app:app --reload --port 8765

test:
	pytest tests/ -v

test-e2e:
	pytest tests/test_e2e.py -v

lint:
	ruff check src/ tests/

format:
	ruff format src/ tests/

check: lint test

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	rm -rf .pytest_cache .ruff_cache *.egg-info
