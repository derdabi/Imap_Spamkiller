FROM node:20-alpine AS frontend-build

WORKDIR /build/frontend
COPY frontend/package*.json ./
RUN npm install -g npm@11.6.2 \
    && npm --version \
    && ls -la \
    && (npm ci || (cat /root/.npm/_logs/*-debug-0.log && exit 1))
COPY frontend/ ./
RUN npm run build

FROM python:3.13-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATA_DIR=/data \
    STATIC_DIR=/app/static

WORKDIR /app
COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/spamkiller ./spamkiller
COPY --from=frontend-build /build/frontend/dist ./static

EXPOSE 8080
CMD ["uvicorn", "spamkiller.main:app", "--host", "0.0.0.0", "--port", "8080"]
