# Use Python 3.9 as base image
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install system dependencies required for Scapy
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    iputils-ping \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Install poetry
RUN pip install poetry==1.8.3

# Copy project files
COPY pyproject.toml poetry.lock ./
COPY README.md ./
COPY src/ ./src/

# Configure poetry to not create virtual environment inside container
RUN poetry config virtualenvs.create false

# Install dependencies
RUN poetry install --no-dev --no-interaction

# Set entrypoint
ENTRYPOINT ["python", "-m", "network_scanner.main"]