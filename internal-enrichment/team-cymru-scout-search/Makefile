.PHONY: help install clean run docker-build docker-up docker-down

help:
	@echo "Available targets:"
	@echo "  install      - Install dependencies"
	@echo "  run          - Run the connector"
	@echo "  clean        - Clean up temporary files"
	@echo "  docker-build - Build Docker image"
	@echo "  docker-up    - Start with docker-compose"
	@echo "  docker-down  - Stop docker-compose"

install:
	pip install -r requirements.txt

run:
	python -m src.scout_search_connector.main

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete

docker-build:
	docker build -t scout-search-connector .

docker-up:
	docker-compose up -d

docker-down:
	docker-compose down
