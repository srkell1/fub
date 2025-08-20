# FUB ↔ Cal — Production Web App

Two-way sync between **Follow Up Boss** and **Cal.com** with secure webhooks, idempotency (pairings), retries + DLQ, logging, and location→event type mapping (with labels).

## Quick start
```bash
cd server
cp .env.example .env   # fill in your keys/secrets
npm i
npm start              # http://localhost:8787/admin
```

## Webhooks
- FUB → `https://YOUR-HOST/webhooks/fub` (appointmentsCreated/Updated/Deleted)
- Cal → `https://YOUR-HOST/webhooks/cal` (set your webhook secret and copy to CAL_WEBHOOK_SECRET)

## Deploy tips
- Render/Railway: root `/server`, start `node index.js`, add a disk and set `DB_PATH=/data/data.db`.
- Set env: `FUB_API_KEY`, `CAL_API_KEY`, `CAL_API_VERSION=2024-08-13`, `CAL_WEBHOOK_SECRET`, optional `FUB_WEBHOOK_SECRET`.
- Optional Basic Auth: `BASIC_AUTH_USER` + `BASIC_AUTH_PASS` for `/admin` & `/api`.
- Admin dashboard is at `/admin` (served from the server).

## Mapping
Edit via the admin UI (Location → Event Type). The server includes common defaults and a small synonym list (etob/eto→etobicokeoffice, gmeet/gm→googlemeet).

## Updates & cancels
- From FUB: creates/updates Cal booking. (Updates implemented as cancel+recreate for consistency).  
- From Cal: reschedules/cancels update FUB.

## Notes
- Node 18+ (uses global `fetch`).  
- SQLite WAL mode for durability.  
- Retry backoff/Jitter controlled by env (`MAX_RETRIES`, `BACKOFF_BASE_MS`).  
