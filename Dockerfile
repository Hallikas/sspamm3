# Build stage
FROM python:3.9-slim AS builder
COPY requirements.txt .
RUN apt-get update && apt-get install -y --no-install-recommends \
    libmilter-dev \
    gcc \
    libc6-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --user --no-cache-dir -r requirements.txt

# Final stage
FROM python:3.9-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    libmilter-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /data
COPY --from=builder /root/.local/lib/python3.9/site-packages /usr/local/lib/python3.9/site-packages
COPY sspamm3.py .
COPY sspamm3.conf.example ./sspamm3.conf
VOLUME /data
EXPOSE 8890
CMD ["python3", "sspamm3.py", "--config", "/app/sspamm3.conf"]
