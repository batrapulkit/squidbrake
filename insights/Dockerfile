FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 INSIGHTS_DB=/data/insights.db
WORKDIR /app
RUN pip install "fastapi>=0.110" "uvicorn>=0.29" "pydantic>=2"
COPY app.py admin.html start.html team.html get.html install.ps1 install.sh ./
RUN useradd -r -u 10002 insights && mkdir -p /data && chown insights /data
USER insights
EXPOSE 8090
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8090/health', timeout=4)"
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8090", "--proxy-headers", "--forwarded-allow-ips", "*"]
