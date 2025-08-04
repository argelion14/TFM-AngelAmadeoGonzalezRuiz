# Use an official minimal Python image
FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/home/appuser/.local/bin:/usr/bin:$PATH"

# Install required system dependencies including OpenSSL
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    libssl-dev \
    openssl \
    build-essential \
    && apt-get purge -y --auto-remove gcc build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user for security
RUN adduser --disabled-password --gecos "" appuser

# Set the working directory and assign ownership
WORKDIR /app
COPY --chown=appuser:appuser requirements.txt ./

# Install Python dependencies
RUN pip install --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY --chown=appuser:appuser appFlask/ appFlask/

# Switch to non-root user
USER appuser

EXPOSE 5000

# Change the entrypoint to start Flask app (ajústalo a tu script principal si es necesario)
ENTRYPOINT ["/usr/local/bin/python3", "appFlask/testToken.py"]