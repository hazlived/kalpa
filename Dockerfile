# KALPA: Causal Cyber Reasoning System (AI Kavach)
# Production Containerization Environment

FROM python:3.11-slim-bullseye

# Install system dependencies, C/C++ compilers, and build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    clang \
    make \
    git \
    curl \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install python dependencies
COPY requirements.txt pyproject.toml /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy KALPA project source code
COPY . /app

# Ensure shell entrypoints are executable
RUN chmod +x run_kalpa.sh

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV KALPA_ENV=production

# Default entrypoint
ENTRYPOINT ["python", "run_kalpa.py"]
CMD ["--target", "targets/vulnerable_service"]
