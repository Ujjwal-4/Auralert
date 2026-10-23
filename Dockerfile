FROM python:3.11-slim

# Prevent Python from writing bytecode and buffer stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000 \
    HOST=0.0.0.0

WORKDIR /app

# Install curl for container healthchecks
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root application user
RUN groupadd -g 1000 scamshield && \
    useradd -u 1000 -g scamshield -m -s /bin/bash scamshield

# Install python dependencies first for efficient caching
COPY pyproject.toml .
RUN pip install --no-cache-dir .

# Copy application code, data, and web UI
COPY src/ /app/src/
COPY data/ /app/data/
COPY web/ /app/web/

# Ensure application directories are owned by non-root user
RUN mkdir -p /app/data && chown -R scamshield:scamshield /app

USER scamshield

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://127.0.0.1:${PORT}/healthz || exit 1

CMD ["sh", "-c", "uvicorn scamshield.app:app --host 0.0.0.0 --port ${PORT}"]
