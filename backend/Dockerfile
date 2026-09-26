# Multi-stage build for AI Governance API
FROM python:3.11-slim AS base

WORKDIR /app

# System dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    python3-dev \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Upgrade pip and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Download spaCy model for PII detection
RUN python -m spacy download en_core_web_sm

# Copy source
COPY . .

# Create __init__.py files for packages
RUN touch core/__init__.py api/__init__.py api/v1/__init__.py \
    security/__init__.py governance/__init__.py compliance/__init__.py \
    models/__init__.py models/db/__init__.py models/schemas/__init__.py \
    tasks/__init__.py

EXPOSE 8000

CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}"]
