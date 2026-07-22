FROM python:3.11-slim

# Set working directory inside container
WORKDIR /opt/opencti-connector-whoisfreaks

# Install system runtime dependencies needed by pycti and stix2
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Install Python package dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code and entrypoint
COPY src ./src
COPY entrypoint.sh .

# Ensure entrypoint is executable
RUN chmod +x entrypoint.sh

# Run startup script
ENTRYPOINT ["/bin/sh", "./entrypoint.sh"]