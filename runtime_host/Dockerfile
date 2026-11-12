# Image for running the Runtime Host API. In production the API is intended to
# run as a systemd service on the dedicated Runtime Host VM (so it can use that
# VM's Docker daemon without a container owning the socket). This image is used
# for development/testing and for API-only deployments.
FROM python:3.11-slim-bookworm

WORKDIR /app

# Install the Docker CLI only; the daemon belongs to the VM, never the image.
RUN apt-get update && apt-get install -y --no-install-recommends \
    docker.io \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ ./app/

# Create data directory
RUN mkdir -p /var/lib/runtime_host

# Runtime Host listens on 8443 (mTLS)
EXPOSE 8443

# Start the service
CMD ["python", "-m", "uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8443"]
