FROM python:3.10-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    docker.io \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install OWASP ZAP
RUN docker pull owasp/zap2docker-stable

# Install Nuclei
RUN curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
    | grep "browser_download_url.*linux_amd64.zip" \
    | cut -d '"' -f 4 \
    | wget -i - && \
    unzip nuclei-*-linux_amd64.zip && \
    mv nuclei /usr/local/bin/ && \
    rm nuclei-*-linux_amd64.zip

# Install Dependency-Check
RUN wget https://github.com/jeremy-lin/dependency-check/releases/download/v6.5.3/dependency-check-6.5.3-release.zip && \
    unzip dependency-check-6.5.3-release.zip -d dependency-check && \
    rm dependency-check-6.5.3-release.zip

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Set environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["python3", "security_cli.py"]
