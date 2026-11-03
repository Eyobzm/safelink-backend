# safelink-backend

FastAPI aggregator (Tier 2). Queries GSB, VirusTotal, PhishTank concurrently, runs URLScan privately as async enrichment, returns one verdict.

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env   # fill keys; never commit
pytest
uvicorn app.main:app --reload
# or: docker compose up --build
```

Endpoints: `POST /v1/scan`, `POST /v1/report`, `GET /v1/rules/delta?since=N`, `GET /health`.
Auth: `Authorization: Bearer <APP_TOKEN>`.
