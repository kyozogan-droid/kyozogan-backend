# Deploying the Genius Mirage backend

## What changed to make this deployable at all

The project as originally built would not have worked on Render (or most
real hosts):

| Problem | Why it matters | Fix |
|---|---|---|
| `SECRET_KEY` hardcoded in `settings.py` | Ships in the repo — anyone with the source can forge sessions/tokens | Reads from `SECRET_KEY` env var, dev-only fallback preserved for local use |
| `DEBUG = True` hardcoded | Leaks stack traces/settings to anyone if left on in production | Reads from `DEBUG` env var (defaults `True` to match old local behavior — **set `DEBUG=False` in production**) |
| SQLite as the only database | Render's disk isn't guaranteed to persist across deploys/restarts, and can't be shared across more than one instance — you'd lose data on every redeploy | Reads `DATABASE_URL` (Postgres) if set, falls back to SQLite for local dev |
| No production WSGI server | `manage.py runserver` is single-threaded, auto-reloading, and explicitly documented by Django as dev-only | `gunicorn` + `Procfile`/`build.sh` |
| No static file serving story | Django doesn't serve its own static files (admin/Jazzmin CSS/JS) in production | `whitenoise` middleware + `collectstatic` in the build step |

All of the above were tested locally end-to-end (migrations, `collectstatic`,
the full test suite, and a manual check that `DATABASE_URL` correctly
resolves to Postgres when set). What was **not** tested is an actual deploy
to a live Render account — I don't have one available. Treat `render.yaml`
as a correct-per-current-docs starting point, not a guarantee; validate it
with `render blueprints validate` before relying on it.

## Two ways to deploy

### Option A — Blueprint (`render.yaml`)
From the repo root: Render Dashboard -> "New +" -> "Blueprint" -> select
this repo. It provisions the Postgres database, the Django backend, and the
universal proxy sidecar together. See the comments in `render.yaml` for the
handful of things you still set manually (site credentials, `GROQ_API_KEY`).

### Option B — Manual web service
1. Create a Postgres database on Render, copy its connection string.
2. Create a Web Service pointing at `backend/` as the root directory.
3. Build command: `./build.sh`
4. Start command: `gunicorn geniusmirage.wsgi:application --bind 0.0.0.0:$PORT --workers 3 --timeout 60`
5. Environment variables: `SECRET_KEY` (generate one), `DEBUG=False`,
   `DATABASE_URL` (from step 1), optionally `GROQ_API_KEY`.

## Things worth knowing operationally (not code problems — deployment realities)

- **Free-tier cold starts.** Render's free instances spin down after 15
  minutes of inactivity; the next request takes 30-60s to wake back up.
  The SDKs and universal proxy default to a **400ms** evaluation timeout
  and fail open (forward the request unevaluated) if Genius Mirage doesn't
  answer in time — so during a cold start, traffic passes through
  *without* detection rather than blocking. That's the right trade-off for
  uptime, but it means a free-tier backend effectively has no protection
  for the first request or so after idling. Use a paid "always on" plan
  for the backend if you want consistent coverage, or raise
  `GM_EVAL_TIMEOUT_MS` with the understanding that a slow eval now risks
  slowing down real user requests too.
- **The universal proxy has the same cold-start exposure** if you deploy
  it on Render's free tier fronting an app that's also cold — the proxy's
  own `GM_FORWARD_TIMEOUT_S` (30s) is generous enough to survive an
  upstream cold start, but your users will feel that latency.
- **GROQ_API_KEY is optional but recommended.** Without it, Tier 3 uses a
  heuristic fallback (request velocity + technique count) rather than AI
  judgment on borderline sessions — functional, just less nuanced.
