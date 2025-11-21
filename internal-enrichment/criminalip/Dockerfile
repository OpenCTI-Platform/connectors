FROM python:3.11-slim

WORKDIR /app

# 시스템 의존성 설치 (python-magic 요구)
RUN apt-get update && apt-get install -y libmagic1 && rm -rf /var/lib/apt/lists/*

COPY src/requirements.txt ./requirements.txt

# Python 패키지 설치
RUN pip install pycti
RUN pip install --no-cache-dir -r requirements.txt

COPY src ./src
COPY entrypoint.sh ./entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Optional: default command; override in docker-compose if needed
CMD ["/app/entrypoint.sh"]

