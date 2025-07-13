# Use an official minimal Python image
FROM python:3.11-slim

# Set secure and useful environment variables
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/home/appuser/.local/bin:$PATH" \
    CA_CERT_PATH=appFlask/certs/ecdsa01RootCaCert.pem \
    CA_KEY_PATH=appFlask/certs/ecdsa01RootCaKey.pem

# Install only required system dependencies and remove build tools afterward
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    libssl-dev \
    build-essential \
    && apt-get purge -y --auto-remove gcc build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user for security
RUN adduser --disabled-password --gecos "" appuser

# Set the working directory and assign ownership to the non-root user
WORKDIR /app
RUN chown appuser:appuser /app

# Copy only requirements first to leverage Docker layer caching
COPY --chown=appuser:appuser requirements.txt .

# Install Python dependencies
RUN pip install --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Copy application code with correct ownership
COPY --chown=appuser:appuser appFlask ./appFlask

# Switch to non-root user
USER appuser

# Expose Flask default port
EXPOSE 5000

# Use exec form for better signal handling and process management
ENTRYPOINT ["/usr/local/bin/python3", "appFlask/testToken.py"]