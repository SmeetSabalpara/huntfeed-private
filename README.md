# HuntFeed Phone — RSS + AI threat-hunting notifications

**Android + Railway beginner instructions:** [SETUP_ANDROID_RAILWAY.md](SETUP_ANDROID_RAILWAY.md). This Railway-ready edition accepts the provider-assigned `PORT`, adds a public `/health` endpoint, and checks browser request origins correctly behind an HTTPS reverse proxy.

**What it is:** A small private, phone-installable web app (PWA) that collects cybersecurity RSS/Atom feeds and Google Alerts RSS, explains new incidents with AI, extracts source-evidenced IOCs, suggests *draft* Elastic Security KQL hunts, and sends Web Push notifications to your phone. No Telegram or Inoreader required.

**Important:** This package is **source code, not a deployed phone app**. A server must run it continuously over HTTPS for automatic checks and phone push. ChatGPT cannot install this onto your phone or keep the server running for you. It is a **single-user starter**, not a hardened multi-tenant SOC product. The AI API and a continuously running host may cost money.

## Features

- Mobile dashboard: latest reports, severity, searchable reports, original links and sources.
- Sources: SANS ISC full-text diary, CISA Alerts, The Hacker News (preloaded). Add other RSS or **Google Alerts RSS** links in the Feeds tab.
- Checks feeds every **15 minutes** by default; configurable in `.env`. Delay also depends on publisher update times and network/API processing.
- New feed items are analyzed by the OpenAI API using structured output, with a beginner-friendly explanation, attack sequence, affected versions, source-evidenced IOCs, limitations and Elastic ECS KQL hunting suggestions.
- AI-indicated IOCs are retained **only if their exact value is present in the fetched article text and the model's quoted evidence**. This reduces hallucinated indicators but does not validate authenticity, attribution, or maliciousness. KQL is **unvalidated analyst guidance**.
- Push notifications via Web Push to a subscribed phone. Tapping opens the full analysis in HuntFeed. Default pushes only for AI-relevant high/critical reports; set `PUSH_MIN_SEVERITY=info` for all relevant reports.
- Local SQLite archive and installed-phone support. One backend worker; persistent storage.
- Manual "Analyze URL" for a researcher report right away; useful for testing and analyzing historical posts.
- Initial RSS scan marks existing items as **baseline** and **does not auto-analyze/notify** old posts (to avoid an immediate notification storm). New posts thereafter are analyzed.

## Setup in 4 steps

### 1. Set secrets

Copy `.env.example` to `.env`. Replace all `REPLACE_*` strings. Use a **long, unique** `APP_PASSWORD` and a random `SESSION_SECRET` (for example, generate one with `python -c "import secrets; print(secrets.token_urlsafe(48))"`). Set:

- `OPENAI_API_KEY`: from your OpenAI API account. **ChatGPT Plus is not an API subscription**. API usage is billed separately. Keep the key server-side, never paste it into this app or into a chat.
- `VAPID_EMAIL`: your own email address for the Web Push protocol contact claim.
- `POLL_MINUTES`: polling interval (minimum 5).
- `PUSH_MIN_SEVERITY`: `info`, `low`, `medium`, `high` (default), or `critical`.
- `MAX_AI_PER_POLL`: max new articles to analyze per scan, default 6 (limits cost). Unprocessed ones remain in a local queue for subsequent scans.

For your first test on your computer, `localhost` is sufficient to open the UI. **For the phone's push notifications you must put the server behind public or otherwise phone-accessible HTTPS**; Apple iOS also requires installing the web app to the home screen.

### 2. Run the backend (Docker recommended)

From the folder containing `docker-compose.yml`:

```bash
cp .env.example .env
# Edit .env with the credentials described above
docker compose up -d --build
docker compose logs -f --tail=100
```

The container binds to **127.0.0.1:8000**, not directly to the public internet. On the server, visit `http://localhost:8000` to test the sign-in page. Your persistent app state is in `./data` on the host; **back this up**. Leave exactly **one application worker/instance** running; multiple replicas will poll and process duplicate jobs.

#### Without Docker (Python 3.11+)

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
cp .env.example .env
# Edit .env
uvicorn app:app --host 127.0.0.1 --port 8000 --workers 1
```

### 3. Put it behind HTTPS (necessary for phone push)

Use a private VPS or a trusted container host with persistent disk, a domain name, and HTTPS. With Caddy installed and a domain `intel.example.com` that points to your server, place in `/etc/caddy/Caddyfile`:

```caddyfile
intel.example.com {
    reverse_proxy 127.0.0.1:8000
}
```

Reload Caddy following its installation instructions. Caddy can obtain a public HTTPS certificate automatically when DNS/ports are correctly configured. The app's sign-in password protects feed content and settings; still prefer a private VPN or other access restriction when feasible. Don't expose port 8000 directly.

**Alternative deployment:** Any always-on service with HTTPS and a **persistent writable volume**. Avoid a free instance that sleeps or erases local storage. Do not use multiple replicas or auto-scaling without changing the job scheduler and SQLite design.

### 4. Install on your phone

- **Android:** Open `https://intel.example.com` in Chrome → menu → **Install app** / **Add to Home screen** → open HuntFeed → sign in → **Settings & Push** → **Enable phone notifications** → allow permission → **Send test push**.
- **iPhone (iOS 16.4+):** Open your HTTPS URL in **Safari** → Share → **Add to Home Screen** → launch HuntFeed from the Home Screen → sign in → **Settings & Push** → **Enable phone notifications** → allow permission → **Send test push**. iPhone Web Push permission is supported for Home Screen web apps, not simply a regular browser tab.

Notifications can be affected by browser/OS permissions and power/network policies. Push messages show priority, title, number of IOCs/hunts. **Tap a notification to view the entire AI explanation, IOCs with evidence, and KQL.**

## Add Google Alerts and more researchers

1. Open [Google Alerts](https://www.google.com/alerts), create a keyword search.
2. **Show options → Deliver to → RSS feed**. Save the alert, then copy the RSS feed URL from its RSS icon.
3. In HuntFeed → **Feeds** → enter a name and paste the RSS URL.
4. Repeat for original research RSS feeds. If a site has no RSS, Google Alerts can provide partial coverage, but it can miss posts and be delayed.

A suggested high-signal alert is: `"malicious VS Code extension" OR "trojanized extension" OR "Open VSX malware"`. Consider additional searches for actively exploited CVEs, malicious npm/PyPI packages, ransomware intrusion write-ups, and cloud identity attacks. You can add/remove sources from your phone.

## What happens when a new report appears?

1. Background scan finds a new item and deduplicates by its feed entry ID or URL, within that feed.
2. Fetches the original public HTTPS article when accessible; falls back to the RSS summary if access is blocked.
3. Sends extracted public text (up to 17,000 characters) to OpenAI for analysis. **Do not submit confidential organizational data.**
4. Structured AI output includes source claims, education, IOCs with evidence, limitations, and KQL proposals.
5. IOCs that do not occur in source text and model evidence are discarded.
6. AI-relevant reports above your configured severity threshold trigger phone push; all reports remain in the dashboard.

If content is too sparse, the analysis may be incomplete. If a report contains no IOCs, the app should not invent them. It **does not query your SIEM or verify exposure or compromise**. It prepares a suggested hunt for your manual investigation.

## Security and operating limitations

- **Single-user proof of concept.** It has cookie login, a server-side API key, same-site cookies, basic host URL filtering, and size/time limits. Before company-wide deployment, add SSO, stronger CSRF protection, audit logs, rate limiting, network egress allowlists, a production scheduler/queue, account separation, and a real database.
- It attempts to reject private/localhost feed URLs, but **DNS rebinding and other SSRF bypasses are possible** without network-layer egress controls. Only subscribe to trusted public sources, and restrict backend network egress.
- Sources can publish malicious or inaccurate content; the AI treats the report as data, but prompt injection and erroneous output remain risks.
- Google Alerts may have delays and RSS sources can omit full text. This is **near-real-time polling**, not immediate event-driven detection.
- Duplicate reporting from different feeds may appear twice; v1 deduplication is within each feed, not cross-source.
- `MAX_AI_PER_POLL` throttles analysis, but you should additionally set API budgets in your provider account.
- It stores URLs, analysis, authenticated sessions, and push subscription endpoints locally. Don't publish the SQLite file or `data/vapid_private.pem`.
- **No automatic blocking or rule deployment.** Human validation is necessary before KQL gets used operationally.
- Monitoring is only active **while the backend is running**. A phone-only PWA cannot continuously fetch RSS and call an AI API after it is closed.

## Diagnostics

- **Login works, no reports:** Wait for first scan, choose Check feeds, look for feed errors under Feeds. Initial results are baselined; new posts are processed automatically. Use Settings → Analyze URL for immediate analysis of an existing post.
- **No AI analysis:** Check `OPENAI_API_KEY`, OpenAI API billing, and container logs. A ChatGPT subscription does not include API usage.
- **No push:** Verify HTTPS, VAPID_EMAIL, notification permission, install-to-home-screen on iOS, and Send test push. Check server logs for subscription errors.
- **No updates on phone:** Make sure the server is not sleeping and persistent storage is mounted. Check logs for RSS errors or rate limits.
- **Duplicate headlines:** Overlapping sources can repeat the same story. Consider choosing fewer sources or implementing cross-feed fingerprinting.

## Verification

Static Python/JavaScript syntax can be checked without contacting the internet. Full end-to-end RSS/API/phone push tests require network access, dependencies, a valid API key, an HTTPS deployment, and an actual device. This package has not been deployed into your phone or connected to your accounts.
