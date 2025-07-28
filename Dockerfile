# Use an official minimal Python image
FROM python:3.11-slim

# Set secure and useful environment variables
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

# Set the working directory and assign ownership to the non-root user
WORKDIR /app
RUN chown appuser:appuser /app

# Copy only requirements first to leverage Docker layer caching
COPY --chown=appuser:appuser requirements.txt .

# Install Python dependencies
RUN pip install --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Switch to non-root user
USER appuser

# Expose Flask default port
EXPOSE 5000

# Use exec form for better signal handling and process management
ENTRYPOINT ["/usr/local/bin/python3", "appFlask/testToken.py"]