FROM python:3.12-alpine

# Set working directory inside container
WORKDIR /opt/opencti-connector-whoisfreaks

# Install system runtime/build dependencies needed by pycti and stix2
# hadolint ignore=DL3003
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev

# Install Python package dependencies
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

# Copy source code
COPY src ./src

# Run the connector directly via Python
ENTRYPOINT ["python3", "/opt/opencti-connector-whoisfreaks/src/main.py"]