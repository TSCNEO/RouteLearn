FROM node:22-bookworm-slim AS frontend
WORKDIR /build/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 ROUTELEARN_DATA_DIR=/data
RUN apt-get update && apt-get install -y --no-install-recommends libpcap0.8 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src/ ./src/
COPY migrations/ ./migrations/
COPY alembic.ini ./
COPY --from=frontend /build/src/routelearn/static/ ./src/routelearn/static/
RUN pip install --no-cache-dir . && mkdir -p /data
EXPOSE 8080
VOLUME /data
ENTRYPOINT ["routelearn"]
CMD ["server"]
