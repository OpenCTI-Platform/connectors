init:
	echo "Installing requirements..."
	pip install -r requirements.txt
	pip install --upgrade --no-deps -r requirements-overrides.txt

test:
	echo "Launching tests suite..."
	pytest

.PHONY: init test
