FROM python:3.12-alpine AS base


# Install Python modules
# hadolint ignore=DL3003
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev && \
    pip3 install --no-cache-dir --upgrade pip


FROM base AS package
# Copy the package
COPY tenable_security_center /opt/tenable_security_center
COPY pyproject.toml /opt/pyproject.toml

RUN cd /opt/ && \
    pip3 install --no-cache-dir . && \
    apk del git build-base && \
    rm /opt/pyproject.toml && \
    rm -rf /opt/tenable_security_center

FROM package AS app
# Copy the app
COPY app.py /opt/app.py    
# This connector has no src/ to carry a version stamp, so it is copied straight
# to the entry script's directory. The `[n]` makes the copy optional: the stamp
# is written by the CI and is absent from local builds, and a plain COPY would
# fail there. Do not "fix" it into a literal filename.
COPY .connector_version.jso[n] /opt/

# Run the app
CMD ["python3", "/opt/app.py"]
