FROM python:3.12-slim
LABEL org.opencontainers.image.source="https://github.com/batrapulkit/squidbrake" \
      org.opencontainers.image.description="Squidbrake: brakes for your AI agents" \
      org.opencontainers.image.licenses="Apache-2.0"

ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    IN_DOCKER=1 HOST=0.0.0.0 PORT=8080 WORKERS=1 FORWARDED_ALLOW_IPS=*
WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

# Every module server.py imports (tests/test_packaging.py checks this list), plus the shipped-rules fingerprints
COPY server.py commands.py taint.py verify.py pilot.py evidence.py lockdown.py rules.yaml rules.shipped dashboard.html approve.html ./
COPY squidbrake/__init__.py squidbrake/__init__.py
RUN useradd -r -u 10001 gateway && mkdir -p /app/data && chown -R gateway /app/data
USER gateway

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "import urllib.request,os; urllib.request.urlopen(f'http://127.0.0.1:{os.environ[\"PORT\"]}/health', timeout=4)"

# Keys and the database live in /app/data; the first start creates the keys and prints them once.
CMD ["python", "server.py", "run"]
