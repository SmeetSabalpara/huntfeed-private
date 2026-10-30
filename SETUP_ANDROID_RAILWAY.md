# HuntFeed on Android — beginner deployment guide (Railway + GitHub)

This is a single-user **prototype** with a phone-installable web app, not a Play Store APK. The backend must run continuously for RSS checks and push. It analyzes public threat reports; do not upload private company data. AI-suggested KQL and IOCs require human verification before SOC use.

## A. Accounts and prerequisites

- Laptop or desktop, Android phone with current Chrome.
- GitHub account (github.com), Railway account (railway.com), OpenAI API account (platform.openai.com).
- Railway may charge for a continuously running app; OpenAI API is billed separately from ChatGPT subscriptions.

## B. Upload HuntFeed code to GitHub

1. On your **computer**, extract `huntfeed-android-railway-ready.zip` to a folder.
2. Visit https://github.com/new, enter repository name `huntfeed-private`, choose **Private**, and create the repository. An empty repository is easiest.
3. In the repo click **uploading an existing file** or **Add file → Upload files**. Drag the **contents** of the unzipped `huntfeed_railway` folder, including the `static` directory, to the upload page. The `Dockerfile`, `app.py`, and `requirements.txt` must appear in the repository **root**, not in a nested folder. GitHub accepts file or folder drag-and-drop.
4. Commit the upload. You may omit `tests` if needed, but retain the `static` folder. If your operating system hides dotfiles, this is okay; the `.env.example` and `.dockerignore` files are optional for Railway deployment.
5. **NEVER commit a `.env` file, real passwords, or an OpenAI API key.**

## C. Create an OpenAI API key

1. Visit https://platform.openai.com/ and configure API billing separately from ChatGPT.
2. In the project selector, create a project called **HuntFeed** (if your account allows it).
3. Open your project → **API keys** → **Create new secret key**. Save the secret in a password manager. Never paste it in GitHub or chat.
4. Open project **Limits** and set a modest monthly spend limit and alerts; turn on **Enforce a hard limit** if available. Hard-limit enforcement can lag slightly.
5. Leave the default model as `gpt-5-mini`, which supports structured responses used by this app.

## D. Deploy the backend on Railway

1. Open https://railway.com/ → **New Project** → **Deploy from GitHub repo**. Authorize your GitHub account, select the **private** `huntfeed-private` repo.
2. Railway should detect `Dockerfile`. If your repo contains an extra folder, set **Service → Settings → Root Directory** to that folder, but placing the files at root is simpler.
3. In Railway, select your HuntFeed **Service → Variables**. Add **one variable at a time** using the names and values below. These are *not* source-code files:

   | Variable | Value |
   |---|---|
   | `APP_PASSWORD` | Your own long unique password (suggest 20+ random characters) |
   | `SESSION_SECRET` | Random secret at least 48 characters, generated locally or by your password manager |
   | `OPENAI_API_KEY` | The API secret key from OpenAI |
   | `OPENAI_MODEL` | `gpt-5-mini` |
   | `VAPID_EMAIL` | A valid email address you control; e.g., `you@yourdomain.com` (Web Push contact claim) |
   | `DATA_DIR` | `/data` |
   | `POLL_MINUTES` | `15` |
   | `MAX_AI_PER_POLL` | `3` to begin with, to limit spending |
   | `PUSH_MIN_SEVERITY` | `high` (or `info` for every AI-relevant article) |

   Optional `PORT` can be omitted: the Railway-ready Dockerfile honors Railway's assigned port. Do **not** copy `REPLACE_*` placeholder strings.

4. Select the service → **Settings / Volumes** or the project canvas's **New Volume** action. **Attach a persistent volume with mount path `/data`** to the HuntFeed service. **Do not skip this:** it stores the SQLite database and Web Push signing key. Without persistent storage, a restart loses reports and breaks registered push subscriptions.
5. Set the service to **one replica** and do not enable application sleep / scale-to-zero; the poller runs inside the web process. A volume may cause a deployment/restart.
6. Review and **Deploy** your staged settings. Open **Deployments / Logs** and look for Uvicorn startup rather than errors. The service listens on the Railway-provided port.
7. Go to service **Settings → Networking → Public Networking → Generate Domain**. Railway gives you a public HTTPS URL like `https://huntfeed-production.up.railway.app`. You don't need to buy a domain. If Railway asks for a target port, choose the port shown for your app; the service listens on `PORT` provided by Railway.
8. Visit `https://YOUR-APP-DOMAIN/health`. It should display `{"ok":true}`. Visit `https://YOUR-APP-DOMAIN/` to reach the login page.

**Common mistake:** uploading the ZIP file itself into GitHub does *not* deploy the app. You must upload the **extracted project files**.

## E. Install on Android

1. On Android, open **Chrome**, type the HTTPS address from Railway, and log in using `APP_PASSWORD` (not your Railway or Google password).
2. Tap Chrome's **⋮** menu → **Install app** or **Install and create shortcut**, then confirm.
3. Open the new **HuntFeed** icon from your phone's home screen.
4. Open **Settings & Push** → **Enable phone notifications**, and tap **Allow** when Android asks.
5. Tap **Send test push**. You should see a notification, which you can tap to reopen HuntFeed.
6. If no alert arrives: check Android **Settings → Apps → HuntFeed (or Chrome) → Notifications → Allow**, disable aggressive battery restrictions for Chrome/HuntFeed if applicable, and inspect the Railway **Logs** for `Web push error`.

Notifications use the Web Push protocol and are delivered even if the app is not open, provided the server is running and your phone/browser permits notification delivery. The sender **cannot guarantee** instant delivery; network and platform restrictions can delay it.

## F. Add RSS and Google Alerts

1. HuntFeed already includes 3 example feeds. Open **Feeds** to inspect them and remove any that error or are irrelevant.
2. Add original-research **HTTPS** RSS/Atom URLs from trusted websites. The app only accepts HTTPS URLs.
3. To include Google Alerts: open https://www.google.com/alerts on your Google account, create your search → **Show options → Deliver to → RSS feed** → create it → copy the generated RSS feed URL → add it in HuntFeed → **Feeds**.
4. Feeds will be checked roughly every 15 minutes. The **first** successful scan records current posts as a baseline (does not notify on existing articles). Future posts get analyzed as capacity allows.
5. To test AI **immediately**, open **Settings & Push → Analyze a report right now**, paste the public URL of a technical research article, and click **Fetch and analyze**. Confirm you get an explanation, IOC evidence, and KQL suggestions (where the report provides enough data).
6. `PUSH_MIN_SEVERITY=high` only notifies AI-relevant high/critical reports. To receive notifications for all AI-relevant analyzed articles, edit that Railway variable to `info` and deploy the staged change. This may create a lot of notifications and API costs.

## G. Troubleshooting

| Symptom | What to check |
|---|---|
| Build failed | `Dockerfile` and `requirements.txt` at repository root; inspect Railway build log |
| App won't open | The generated domain targets the port shown by Railway; visit `/health`; inspect logs |
| Login seems accepted but next action says 401/403 | Chrome cookies allowed, HTTPS, matching host; use this Railway-ready package with proxy Origin handling fix |
| Nothing in Latest | First scan only baselines current items; click `Check feeds` later or `Analyze a report right now` |
| No AI explanation | OpenAI billing + key and `OPENAI_MODEL`; examine logs and article error |
| Test push requested but no notification | Check permission and VAPID email; check logs for delivery errors; ensure `/data` volume is retained |
| Feeds show error | Confirm RSS/Atom URL is available via public HTTPS, not a webpage URL |
| Missing older articles | V1 has no bulk backfill; Analyze URL manually; first run intentionally baselines older posts |
| Too many alerts/cost | Set `PUSH_MIN_SEVERITY=high`, reduce number of feeds and `MAX_AI_PER_POLL` |

## H. Security and limitations

- **Private repo ≠ private website.** The HTTPS URL remains publicly accessible behind a single password. Keep it strong and don't share the URL unnecessarily.
- This is a personal proof of concept: it lacks SSO, mature brute-force protection, full SSRF protection, an external scheduler, extensive auditing, and org-grade controls.
- The crawler processes *public article content*; AI outputs are not validated fact or tested detection rules. Audit KQL and IOC claims before use.
- Allowing arbitrary URLs from the admin dashboard can introduce server-side fetch risk. Add only trusted sources, and keep any future enterprise installation isolated with outbound network filtering.
- Do not store confidential SOC logs or company credentials in this prototype.
- **Back up the `/data` volume.** It contains the `huntfeed.sqlite3` archive and `vapid_private.pem`. Losing the signing key requires enabling push again on your phone.
- Cloud hosting costs and OpenAI API usage are separate. `MAX_AI_PER_POLL` limits how many reports are analyzed in one polling pass, but does **not** impose a firm monthly spending cap.
