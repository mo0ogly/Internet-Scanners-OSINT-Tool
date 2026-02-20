FROM python:3.12-slim

LABEL maintainer="Fabrice Pizzi <https://github.com/mo0ogly>"

WORKDIR /app

RUN useradd --create-home --no-log-init appuser && \
    mkdir -p /app/results /app/logs && \
    chown -R appuser:appuser /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY internet_scanner.py cli_Reverse_MX_Lookup_Tool.py ./
COPY samples/ samples/

USER appuser

VOLUME ["/app/results", "/app/logs"]

ENTRYPOINT ["python3", "internet_scanner.py"]
