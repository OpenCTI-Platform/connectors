ARG PYTHON_VERSION=3.12.9
FROM python:${PYTHON_VERSION}-alpine

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

WORKDIR /app

RUN apk add --no-cache libmagic

COPY src/requirements.txt requirements.txt

RUN apk add --no-cache --virtual .build-deps build-base libffi-dev git && \
    python -m pip install --no-cache-dir -r requirements.txt && \
    apk del .build-deps

COPY src .

CMD ["python", "main.py"]
