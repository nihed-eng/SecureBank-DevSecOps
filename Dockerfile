FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd --system --uid 10001 appuser
COPY src ./src
RUN mkdir -p /data && chown -R appuser:appuser /app /data
USER 10001:10001
ENV DATABASE_PATH=/data/securebank.db VULNERABLE_DEMO=0
EXPOSE 5000
CMD ["python", "-m", "flask", "--app", "src.app:app", "run", "--host=0.0.0.0", "--port=5000"]
