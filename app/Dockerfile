FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /srv

COPY app/requirements.txt app/requirements.txt
RUN pip install --no-cache-dir -r app/requirements.txt

COPY app/ app/
COPY telemetry/ telemetry/
COPY data/ data/
COPY scripts/ scripts/
COPY scenarios/ scenarios/

RUN useradd --create-home lab && mkdir -p data/out && chown lab data/out
USER lab

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
