# LogicWard — single-machine simulation lab (SOC dashboard + red-team console)
FROM python:3.12-slim

WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir -e ".[prod]"

# 8080 = SOC dashboard + ingest, 9090 = red-team console
EXPOSE 8080 9090
ENV LOGICWARD_EMBED_PLANT=1 \
    LOGICWARD_MULTISITE=1 \
    LOGICWARD_INGEST_HOST=0.0.0.0 \n    LOGICWARD_CONSOLE_BIND=0.0.0.0

CMD ["python", "-m", "logicward", "demo"]
