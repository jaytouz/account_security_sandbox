FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /srv

COPY review/requirements.txt review/requirements.txt
RUN pip install --no-cache-dir -r review/requirements.txt

COPY review/ review/

RUN useradd --create-home lab
USER lab

EXPOSE 8501
CMD ["streamlit", "run", "review/dashboard.py", \
     "--server.address=0.0.0.0", "--server.port=8501", "--server.headless=true", \
     "--browser.gatherUsageStats=false", "--client.toolbarMode=minimal"]
