FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY internet_scanner.py cli_Reverse_MX_Lookup_Tool.py ./
COPY config/ config/
COPY samples/ samples/

RUN useradd --create-home appuser
USER appuser

ENTRYPOINT ["python3", "internet_scanner.py"]
