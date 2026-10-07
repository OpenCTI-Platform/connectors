include .env
export

CONNECTOR_DIR := ../external-import/$(CONNECTOR_NAME)
IMAGE := current-connector:local

.PHONY: build dev

build:
ifndef CONNECTOR_NAME
	$(error CONNECTOR_NAME is not set in .env)
endif
	@test -f $(CONNECTOR_DIR)/Dockerfile || \
		{ echo "No Dockerfile in $(CONNECTOR_DIR)"; exit 1; }
	docker build -t $(IMAGE) -f $(CONNECTOR_DIR)/Dockerfile $(CONNECTOR_DIR)

dev: build
	docker compose run --rm --build dev-connector

clean:
	docker compose down --rmi local --volumes --remove-orphans