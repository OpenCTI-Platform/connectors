FROM python:3.12-bookworm

# Set environment variable
ENV CONNECTOR_TYPE=INTERNAL_ENRICHMENT

# Where to install Playwright browsers
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

# Set working directory
WORKDIR /opt/opencti-connector-import-external-reference

# Copy connector source
COPY src /opt/opencti-connector-import-external-reference

# Update and install system dependencies
RUN apt-get update && \
    apt-get upgrade --install-recommends --with-new-pkgs -y

# Install Python dependencies
RUN pip3 install --no-cache-dir -r requirements.txt

# Install Playwright and its dependencies
RUN playwright install chromium --with-deps --only-shell

# Clean up unnecessary files
RUN apt-get clean && rm -rf /var/lib/apt/lists/* && \
    rm -rf /root/.cache && \
    find . -type d -name __pycache__ -exec rm -rf {} + && \
    find . -type f -name '*.pyc' -delete

# Copy entrypoint
COPY --chmod=0755 entrypoint.sh /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
