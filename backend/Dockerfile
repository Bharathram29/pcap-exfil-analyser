FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Create non-root user for container execution
RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser

COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY app ./app
COPY rules ./rules

RUN mkdir -p /app/data/uploads /app/data/analyses /app/reports && \
    chown -R appuser:appgroup /app

USER appuser

ENV PCAP_ANALYSER_ENVIRONMENT=production \
    PCAP_ANALYSER_JSON_LOGS=true \
    PCAP_ANALYSER_REPORTS_DIR=/app/reports

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health')" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
