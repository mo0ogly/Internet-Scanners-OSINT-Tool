FROM python:3.12-slim

LABEL maintainer="Fabrice Pizzi <https://github.com/mo0ogly>"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN useradd --create-home --no-log-init appuser

COPY --chown=appuser:appuser internet_scanner.py cli_Reverse_MX_Lookup_Tool.py ./
COPY --chown=appuser:appuser samples/ samples/

RUN mkdir -p /app/results /app/logs && chown -R appuser:appuser /app

USER appuser

VOLUME ["/app/results", "/app/logs"]

ENTRYPOINT ["python3", "internet_scanner.py"]
