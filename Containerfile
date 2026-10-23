FROM node:24-alpine AS frontend-build

WORKDIR /build/frontend
COPY frontend/package*.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM python:3.13-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DATA_DIR=/data \
    STATIC_DIR=/app/static

WORKDIR /app
COPY backend/requirements.txt ./requirements.txt
RUN pip install -r requirements.txt
COPY backend/spamkiller ./spamkiller
COPY --from=frontend-build /build/frontend/dist ./static

VOLUME ["/data"]
EXPOSE 8080
CMD ["uvicorn", "spamkiller.main:app", "--host", "0.0.0.0", "--port", "8080"]
