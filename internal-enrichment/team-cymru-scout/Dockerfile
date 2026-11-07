FROM python:3.12-alpine

# Set working directory
WORKDIR /opt/opencti-connector-team-cymru-scout

# Copy requirements
COPY requirements.txt .

# Install dependencies
RUN apk --no-cache upgrade && \
    apk --no-cache add git build-base libffi-dev && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base libffi-dev

# Copy the connector
COPY src .

CMD ["python", "main.py"]