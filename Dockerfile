FROM python:3.11-slim AS base

RUN apt-get update && apt-get install -y --no-install-recommends \
    aircrack-ng nmap curl \
    libpango-1.0-0 libpangoft2-1.0-0 libcairo2 libgdk-pixbuf-2.0-0 libffi-dev shared-mime-info fonts-dejavu-core && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml poetry.lock ./
RUN pip install --no-cache-dir poetry==1.8.2
RUN poetry config virtualenvs.create false && poetry install --only main --no-interaction --no-ansi

COPY . .
RUN useradd -m -s /bin/bash sharingan && \
    chown -R sharingan:sharingan /app && \
    chmod +x scripts/run_scan.py

USER sharingan
ENV PYTHONPATH=/app/src
ENV PYTHONUNBUFFERED=1
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD python scripts/run_scan.py --help || exit 1
CMD ["python", "scripts/run_scan.py", "--help"]