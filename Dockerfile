# ==============================================================================
# Detection Engineering Platform — Multi-Stage Production Dockerfile
# Stage 1: Build the Svelte 5 + Tailwind CSS SPA
# Stage 2: Python 3.11 slim runtime serving FastAPI CQRS engine & static SPA
# ==============================================================================

# ── Stage 1: Frontend Build ──────────────────────────────────────────────────
FROM node:20-alpine AS frontend-builder
WORKDIR /app/ui

# Install dependencies
COPY ui/package*.json ./
RUN npm install

# Copy frontend source and build production bundle into /app/ui/dist
COPY ui/ ./
RUN npm run build

# ── Stage 2: Runtime ─────────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8001

WORKDIR /app

# Install lightweight system utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    make \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code and assets
COPY api/ /app/api/
COPY rules/ /app/rules/
COPY scripts/ /app/scripts/
COPY tests/ /app/tests/
COPY docs/ /app/docs/
COPY runbooks/ /app/runbooks/
COPY emulation/ /app/emulation/
COPY converted/ /app/converted/
COPY Makefile /app/Makefile
COPY UI_plan.md /app/UI_plan.md
COPY PROJECT_PLAN.md /app/PROJECT_PLAN.md
COPY README.md /app/README.md

# Copy compiled frontend from Stage 1 into /app/ui/dist (auto-mounted by FastAPI)
COPY --from=frontend-builder /app/ui/dist /app/ui/dist

# Expose API and UI port
EXPOSE 8001

# Health check endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8001/api/health || exit 1

# Start the unified FastAPI + Svelte production server
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8001"]
