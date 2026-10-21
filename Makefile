# Detection Engineering Lab — Unified Makefile
# Usage: make dev      (starts both API and UI dev servers)
#        make api      (API only)
#        make ui       (UI dev server only)
#        make build    (production build)
#        make test     (run full test suite)
#        make replay   (run replay engine)

PYTHON := python3
UVICORN := python3 -m uvicorn
NPM := npm

API_HOST := 127.0.0.1
API_PORT := 8001
UI_PORT  := 5173

.PHONY: all dev api ui build test replay sync-status clean help

all: help

## Start API (FastAPI + SQLite + file watcher)
api:
	@echo "[API] Starting FastAPI on http://$(API_HOST):$(API_PORT)"
	$(UVICORN) api.main:app --host $(API_HOST) --port $(API_PORT) --reload

## Start UI dev server (Vite + Svelte 5, proxies /api to FastAPI)
ui:
	@echo "[UI] Starting Vite dev server on http://localhost:$(UI_PORT)"
	cd ui && $(NPM) run dev

## Start both (requires two terminals — use 'make api' + 'make ui' concurrently)
dev:
	@echo "Run in two separate terminals:"
	@echo "  Terminal 1: make api"
	@echo "  Terminal 2: make ui"
	@echo ""
	@echo "Or with a process manager:"
	@echo "  npx concurrently \"make api\" \"make ui\""

## Production build (builds Svelte SPA into ui/dist/, served by FastAPI)
build:
	@echo "[BUILD] Building Svelte production bundle..."
	cd ui && $(NPM) run build
	@echo "[BUILD] Starting FastAPI (serves ui/dist/ at /)"
	$(UVICORN) api.main:app --host $(API_HOST) --port $(API_PORT)

## Run full test suite (detection fixtures + FastAPI unit/integration tests)
test:
	@echo "[TEST] Running full pytest suite (detections + API)..."
	$(PYTHON) -m pytest tests/ -v --no-header --tb=short

## Run detection rules regression test suite
test-detections:
	@echo "[TEST] Running Sigma detection regression suite..."
	$(PYTHON) -m pytest tests/test_detections.py -v --no-header --tb=short

## Run FastAPI backend unit/integration test suite
test-api:
	@echo "[TEST] Running FastAPI backend integration suite..."
	$(PYTHON) -m pytest tests/test_api.py -v --no-header --tb=short

## Run log replay engine against all rules
replay:
	@echo "[REPLAY] Running replay engine..."
	$(PYTHON) scripts/replay_logs.py --type all --verbose

## Run local CI pipeline (pytest detections + API tests + replay + svelte-check + UI build)
ci:
	@echo "[CI] 1. Running Sigma detection regression test suite..."
	$(PYTHON) -m pytest tests/test_detections.py -v --no-header --tb=short
	@echo "[CI] 2. Running FastAPI REST + CQRS integration test suite..."
	$(PYTHON) -m pytest tests/test_api.py -v --no-header --tb=short
	@echo "[CI] 3. Running log replay regression test engine..."
	$(PYTHON) scripts/replay_logs.py --type all --verbose
	@echo "[CI] 4. Verifying UI TypeScript diagnostics and production build..."
	cd ui && npx svelte-check && $(NPM) run build
	@echo "[CI] Complete pipeline passed with 100% success!"

## Reset and rebuild database read model from YAML
reset-db:
	@echo "[DB] Removing existing SQLite database..."
	rm -f api/detection_lab.db* detection_lab.db*
	@echo "[DB] Rebuilding SQLite read model from YAML files..."
	$(PYTHON) -c "import sys; sys.path.insert(0, '.'); from pathlib import Path; from api.models.db import create_tables; from api.core.reconciler import full_reconciliation; create_tables(); r = full_reconciliation(Path('rules/sigma'), Path('docs/bypass_log.md'), True); print(f'Done: {r}')"


## Convert Sigma rules to all target formats
convert:
	@echo "[CONVERT] Converting Sigma rules across all platforms..."
	$(PYTHON) scripts/convert_sigma.py \
		--input rules/sigma/ \
		--wazuh rules/wazuh/ \
		--kql converted/kql/ \
		--splunk converted/splunk/ \
		--production

## Check DB sync status
sync-status:
	@echo "[SYNC] Checking database sync status..."
	$(PYTHON) -c "import sys; sys.path.insert(0, '.'); from sqlalchemy import text; from api.models.db import engine; c = engine.connect(); n = c.execute(text('SELECT COUNT(*) FROM rules')).scalar(); s = c.execute(text(\"SELECT COUNT(*) FROM rules WHERE sync_status='synced'\")).scalar(); e = c.execute(text(\"SELECT COUNT(*) FROM rules WHERE sync_status='error'\")).scalar(); c.close(); print(f'Rules: {n} total, {s} synced, {e} errors')"


## Rebuild SQLite read model from YAML files
rebuild-db:
	@echo "[DB] Rebuilding SQLite read model from YAML files..."
	$(PYTHON) -c "\
import sys; sys.path.insert(0, '.'); \
from pathlib import Path; \
from api.models.db import create_tables; \
from api.core.reconciler import full_reconciliation; \
create_tables(); \
r = full_reconciliation(Path('rules/sigma'), Path('docs/bypass_log.md'), True); \
print(f'Done: {r}') \
"

## Install Python dependencies
install-python:
	pip install fastapi uvicorn sqlalchemy aiosqlite watchdog pyyaml pytest jinja2

## Install Node dependencies
install-node:
	cd ui && $(NPM) install

## Full install
install: install-python install-node

## Clean generated files (not source files)
clean:
	rm -f detection_lab.db
	rm -rf ui/dist
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

## Build Docker container image
docker-build:
	@echo "[DOCKER] Building production container image..."
	docker compose build

## Start containerized platform in background
docker-up:
	@echo "[DOCKER] Launching containerized Detection Engineering Platform on http://localhost:8001..."
	docker compose up -d

## Stop containerized platform
docker-down:
	@echo "[DOCKER] Stopping containerized Detection Engineering Platform..."
	docker compose down

help:
	@echo ""
	@echo "Detection Engineering Lab — Commands"
	@echo "════════════════════════════════════"
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  /'
	@echo ""
