FROM python:3.12-alpine

# Set working directory
WORKDIR /opt/opencti-connector-team-cymru-scout

# Copy requirements
COPY src/requirements.txt .

# Install dependencies
RUN apk --no-cache add git build-base libmagic libffi-dev && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

# Copy the connector
COPY src .

CMD ["python", "main.py"]