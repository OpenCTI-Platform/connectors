FROM python:3.12-alpine

# Install necessary packages
RUN apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev

# Copy the connector files
COPY src /opt/connector
WORKDIR /opt/connector

# Install Python dependencies
RUN pip3 install --no-cache-dir -r /opt/connector/requirements.txt

# Entrypoint
ENTRYPOINT ["python3", "main.py"]
