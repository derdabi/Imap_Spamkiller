# AGENTS.md

## Project Shape
- React/Vite frontend lives in `frontend`; FastAPI backend lives in `backend/spamkiller`.
- Backend entrypoint is `spamkiller.main:app`; worker entrypoint is `python -m spamkiller.worker`.
- Scanner uses `DATA_DIR/scan.lock` to prevent concurrent scans; stale threshold is 6 hours.
- Docker Compose runs `app`, `worker`, `rspamd`, and `redis`; app and worker share the same image and `/data` volume.

## Commands
- Backend tests (from `backend/`): `python -m unittest discover -s tests`
- Focused backend test (from `backend/`): `python -m unittest tests.test_imap_paths.ScanLockTests`
- Frontend typecheck/build: `npm --prefix frontend run build`
- Local Windows dev: `./start-debug.ps1`; use `-SkipInstall` after first setup.
- Debug URLs from `start-debug.ps1`: backend `127.0.0.1:8080`, frontend `127.0.0.1:5173`; Vite proxies `/api` to backend.
- Docker deploy: `docker compose up -d --build`; `./update-docker.ps1` also works but currently requires a `.env` file.

## Env And Data
- `APP_SECRET` is optional; if unset or blank, the app creates/reuses `DATA_DIR/app_secret`.
- Losing `DATA_DIR/app_secret` or changing `APP_SECRET` makes saved credentials unreadable; use the UI reset credentials flow.
- `docker-compose.yml` uses named volumes; a local `docker-compose.override.yml` (git-ignored) can switch them to bind mounts. Local debug uses `.debug-data`.
- Do not edit generated/runtime artifacts: `.venv`, `frontend/node_modules`, `frontend/dist`, `frontend/tsconfig.tsbuildinfo`, `__pycache__`, `.debug-data/spamkiller.db`.

## Verification
- Run `python -m unittest discover -s tests` from `backend/` after backend changes.
- Run `npm --prefix frontend run build` after frontend changes.
- There is no repo CI, lint, formatter, pre-commit, or codegen config currently present.

## Behavior To Preserve
- IMAP scanning uses `BODY.PEEK[]`; do not mark messages read while scanning.
- Spam handling is quarantine-first; auto-delete only applies to old quarantined records.
- Duplicate scan detection keys on `source_folder` plus `uidvalidity:uid`.
- Restore and auto-delete locate mail by `Message-ID`; messages without it may require manual handling.
- Optional LLM classification is only for uncertain Rspamd scores; email content must remain treated as untrusted data.
