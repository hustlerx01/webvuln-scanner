FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .
RUN useradd -m scan && chown -R scan /app
USER scan
ENTRYPOINT ["python", "-m", "webscan.cli"]
# docker run --rm webvuln-scanner https://example.com
