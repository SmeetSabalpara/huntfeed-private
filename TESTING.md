# Smoke test notes

Checked locally in the creation environment:

1. `python -m py_compile app.py` — passed.
2. `node --check static/app.js` and `node --check static/sw.js` — passed.
3. Module imported with substitutes for unavailable `feedparser`, `pywebpush`, and `python-dotenv` dependencies. SQLite initialization, VAPID key generation, IOC literal-evidence filter, missing-key behavior, and insecure URL rejection — passed.
4. FastAPI TestClient with local dependency substitutes: UI, session login/logout protection, feeds API, config API, Web App Manifest and service worker endpoints — passed.

**Not verified here:** installing actual runtime dependencies in this container (internet-restricted), live RSS fetch, OpenAI API parsing, real Web Push subscription and delivery, an HTTPS deployment, or iOS/Android home-screen installation.

On a normal machine, install requirements and optionally `pytest`, then run `python -m pytest -q`. For full integration, deploy over HTTPS, enable push on a phone, press **Send test push**, and **Analyze URL** with a known public technical report.
