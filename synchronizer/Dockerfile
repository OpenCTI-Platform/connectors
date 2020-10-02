FROM python:3.8-alpine

# Copy the worker
COPY src /opt/opencti-connector-synchronizer

# Install Python modules
# hadolint ignore=DL3003
RUN apk --no-cache add git build-base libmagic

RUN echo https://conoria.gitlab.io/alpine-pandoc/ >> /etc/apk/repositories &&\
  echo "@testing http://nl.alpinelinux.org/alpine/edge/testing" >> /etc/apk/repositories &&\
  apk add --no-cache cmark@testing pandoc pandoc-citeproc

RUN cd /opt/opencti-connector-tanium && \
    pip3 install --no-cache-dir git+https://github.com/OpenCTI-Platform/client-python@master && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]