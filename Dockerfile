FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

# Mise à jour des paquets système vulnérables détectés par Trivy
RUN apt-get update \
    && apt-get install -y --no-install-recommends apt libapt-pkg7.0 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd --system --uid 10001 appuser
COPY src ./src
RUN mkdir -p /data && chown -R appuser:appuser /app /data
USER 10001:10001
ENV DATABASE_PATH=/data/securebank.db VULNERABLE_DEMO=0
EXPOSE 5000
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--access-logfile", "-", "--error-logfile", "-", "src.app:app"]
