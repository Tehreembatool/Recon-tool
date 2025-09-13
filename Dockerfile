# Dockerfile for Recon Tool (GUI)
FROM python:3.11-slim

# Install dependencies
RUN apt-get update && \
    apt-get install -y tk whois && \
    rm -rf /var/lib/apt/lists/*

# Set workdir
WORKDIR /app

# Copy files
COPY . /app

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Set display for X11 forwarding (for GUI)
ENV DISPLAY=:0

# Default command
CMD ["python", "task1.py"]
