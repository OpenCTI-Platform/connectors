#!/bin/bash

echo "Running code quality checks..."

# Navigate to the source directory
cd socradar/src/lib

# Run flake8
echo "Running flake8..."
flake8 --ignore=E,W .

# Run black
echo "Running black..."
black .

# Run isort
echo "Running isort..."
isort --profile black .

echo "Checks complete!"
