FROM python:3.11-slim

WORKDIR /app

COPY app.py /app/app.py

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=5050 \
    DATABASE_PATH=/data/proplan.sqlite

EXPOSE 5050

VOLUME ["/data"]

CMD ["python", "app.py"]
