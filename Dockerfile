FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Mise à jour des paquets Debian
RUN apt-get update \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/*

# Installation des dépendances Python
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --system --uid 10001 appuser

# Copie du code source
COPY src ./src

# Permissions
RUN mkdir -p /data \
    && chown -R appuser:appuser /app /data

USER 10001:10001

ENV DATABASE_PATH=/data/securebank.db \
    VULNERABLE_DEMO=0

EXPOSE 5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--access-logfile", "-", "--error-logfile", "-", "src.app:app"]
