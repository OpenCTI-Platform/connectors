FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y libmagic-dev

COPY socradar.py .
COPY config.yml .

RUN pip install pycti requests pandas pyyaml

CMD ["python", "socradar.py"]
