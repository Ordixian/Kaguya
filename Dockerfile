FROM python:3.12-slim

LABEL org.opencontainers.image.title="CyberSentinel" \
      org.opencontainers.image.description="Open-source security monitoring" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /app

# iproute2 gives `ss` for the network collector's fallback path
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY cybersentinel ./cybersentinel
COPY config ./config

EXPOSE 8787
VOLUME ["/app/data"]

# Bind to all interfaces inside the container; map the port on the host.
ENV CS_API_HOST=0.0.0.0
CMD ["python", "-m", "cybersentinel", "run"]
