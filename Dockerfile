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
RUN groupadd -g 1000 auralert && \
    useradd -u 1000 -g auralert -m -s /bin/bash auralert

# Copy application files needed for installation
COPY pyproject.toml README.md ./
COPY src/ ./src/
COPY data/ ./data/
COPY web/ ./web/

# Install python dependencies and package
RUN pip install --no-cache-dir .

# Ensure application directories are owned by non-root user
RUN mkdir -p /app/data && chown -R auralert:auralert /app

USER auralert

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://127.0.0.1:${PORT}/healthz || exit 1

CMD ["sh", "-c", "uvicorn auralert.app:app --host 0.0.0.0 --port ${PORT}"]
