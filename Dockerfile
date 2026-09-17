# Lightweight Python 3 Alpine base image (~50MB)
FROM python:3.12-alpine

# Set working directory
WORKDIR /app

# Install optional qrcode library for terminal banner QR generation
RUN pip install --no-cache-dir qrcode

# Create directory for persistent uploads & notes
RUN mkdir -p /app/uploads

# Copy application scripts
COPY server.py port_scanner.py ./

# Environment defaults
ENV PORT=8080 \
    UPLOAD_DIR=/app/uploads \
    BIND_HOST=0.0.0.0 \
    PYTHONUNBUFFERED=1

# Expose default HTTP port
EXPOSE 8080

# Expose volume mount point for file storage & notes persistence
VOLUME ["/app/uploads"]

# Healthcheck to verify the server is responding to HTTP requests
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:' + '${PORT:-8080}' + '/api/files', timeout=3)" || exit 1

# Start the LAN file transfer server
ENTRYPOINT ["python", "server.py"]
CMD []
