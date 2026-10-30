FROM current-connector:local

# Build context is ../external-import/${CONNECTOR_NAME}, not this folder.
ARG CONNECTOR_NAME

# Add symlink to /opt/src to allow proper linking of the test-requirements.txt while inside the container
RUN ln -s /opt/opencti-connector-${CONNECTOR_NAME} /opt/src

# Install the whole /tests folder. To allow running tests from the container
COPY tests /opt/tests
WORKDIR /opt
RUN apk --no-cache add git build-base && pip install -r tests/test-requirements.txt

# Create a non-root user to run the connector and avoid permission issues when mounting volumes
RUN addgroup -g 1000 developer && \
    adduser -D -u 1000 -G developer developer

USER developer
