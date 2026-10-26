# Ouranos OS

## The Operating System for the Agentic Economy

Ouranos OS is the control plane for a world where software agents work alongside people. It gives every agent a clear identity, an immutable audit trail, and a human approval boundary for high-impact actions.

## The problem

Billions of AI agents will be deployed without identity, audit trails, or security. This is a **$1T problem**: enterprises cannot safely delegate meaningful work when they cannot prove who acted, what happened, or where a human was in control.

## The solution

Ouranos OS makes enterprise AI adoption safe and compliant through:

- **Agent Identity & Permissions** — define who an agent is and what it can do.
- **Immutable Audit Logging** — create a durable operational record of every decision.
- **Human Approval Queues** — stop sensitive actions until a responsible person approves them.

This repository is a self-contained MVP that simulates a multi-agent workflow and exposes its live audit trail in an investor-facing command center.

## Tech stack

- FastAPI and Pydantic
- Uvicorn
- Vanilla HTML, CSS, and JavaScript
- In-memory audit ledger for the MVP

## Roadmap

- **v0.1.0** ✅ Core Agent Wrapper & Audit Log (this MVP)
- **v0.2.0** ✅ Multi-Agent Workflows with CrewAI/LangGraph
- **v0.3.0** ✅ Credential Proxy, policy enforcement, and masked vault telemetry
- **v1.0.0** ⏳ Marketplace for Pre-Built Agents

## Run locally

Requirements: Python 3.10 or newer. The regular mission workflow remains simulated. The AI chat uses Gemini Flash with Google Search grounding for current answers and source citations. The email panel can send real email through Resend after setup and explicit approval.

In PowerShell, run these commands from the project root:

```powershell
cd backend
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

Keep that terminal open while using the app. Open `frontend/dashboard.html` in your browser. The dashboard connects to `http://localhost:8000/api/v1`. The API's interactive documentation is at `http://localhost:8000/docs`.

### Investor preview without API credentials

To show the dashboard without running the backend or configuring Gemini, open `frontend/dashboard.html?demo=1` in your browser. This browser-only preview displays sample telemetry and generates clearly labelled simulated chat replies and mission events; it does not contact the backend, search the web, or send email. For GitHub Pages, enable Pages for the repository and open the published `frontend/dashboard.html?demo=1` URL. This is a presentation preview, not a live service.

### Configure integrations from the dashboard

Start the backend locally and open the dashboard. On startup, the backend prints a **local integration setup token** in the terminal. Copy it into the Integrations panel to authorize setting provider keys from the dashboard. The token is regenerated whenever the backend restarts unless `OURANOS_SETUP_TOKEN` is set in the server environment.

Create a Gemini API key in [Google AI Studio](https://aistudio.google.com/apikey), enter it in the dashboard, then select **Save integrations on backend**. Ouranos uses Google's Gemini Interactions API with the `gemini-3.8-flash` model and Google Search; no separate web-search key is needed. You may also enter a Resend API key for email; Resend additionally requires a sender address and a comma-separated allowlist. Blank fields leave existing settings unchanged.

If chat reports that Google needs a valid API key, create or copy a Gemini API key in Google AI Studio and replace the value in the **Gemini API key** field. The Gemini key is different from the local integration setup token. Paste only the key (no quotes or extra text), save integrations, and retry. If the key is restricted in Google Cloud, allow the Generative Language API. The dashboard only reports that a key is saved; Google verifies it when the first chat request is sent.

Credentials are sent directly to the backend and held **in memory only**. They are not returned to the browser, persisted to disk, or included in the GitHub repository; restarting the backend clears dashboard-entered keys. The setup token is not a substitute for full user authentication.

To test the assistant, ask a non-sensitive question in **Ouranos AI chat**. Conversation history stays in the browser tab and the most recent turns are sent to Gemini for context. Gemini can search Google and return source links; verify important claims against those sources. To test email, fill in **Send a real email** and submit it. Open **Human approval**, review the exact recipient, subject, and message, then approve to send. Rejecting a draft does not send anything. Resend must permit the chosen sender/recipient; begin with your own verified address. Do not search private information or use real customer data in this prototype.

If PowerShell prevents virtual-environment activation, run the installer and server directly:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

To deploy a mission, enter a directive and select **Deploy Agents**. The API responds immediately with a task ID while the simulated workforce writes seven events to the audit trail, pausing between each event. The Email-Agent is intentionally blocked pending human approval.

## Publish the code on GitHub

The repository can be stored on GitHub independently from where the app runs. From the project root, create an empty GitHub repository, then run:

```powershell
git init -b main
git add .
git commit -m "Prepare Ouranos OS MVP"
git remote add origin https://github.com/YOUR-USERNAME/ouranos-os.git
git push -u origin main
```

Replace `YOUR-USERNAME` with your GitHub username. If Git is already initialized, skip `git init -b main`; if a remote already exists, update it with `git remote set-url origin https://github.com/YOUR-USERNAME/ouranos-os.git`.

### Deploy a live demo

GitHub Pages only serves static files; it does not run this FastAPI backend. You can use Pages for the dashboard, but the API must also be hosted by a Python-capable service. After deploying the backend, update the `API_BASE` value in `frontend/dashboard.html` from `http://localhost:8000/api/v1` to your backend's public URL, and configure the backend's CORS allowed origins to your Pages URL before publishing.

This code is an early, in-memory demo, not a production service: data resets when the backend restarts, the API currently has no authentication, and its CORS policy is open. Do not expose it to real users or connect real credentials until authentication, persistent storage, restricted CORS, and production security controls are in place. The vault values in this MVP are simulated.

Dashboard credential setup, live research, and live email are for local prototyping only until the API has authentication, rate limits, and request protections. Keep Uvicorn bound to `127.0.0.1`; do not deploy publicly with provider credentials yet.

## API

- `GET /api/v1/health` — availability and UTC timestamp.
- `POST /api/v1/task` — accepts `{ "prompt": "...", "user_id": "..." }` and starts a background workflow.
- `GET /api/v1/audit-log` — returns all audit events and their count.
- `POST /api/v1/proxy/{action}` — evaluates and executes an agent action without exposing credentials.
- `GET /api/v1/vault` — returns masked credential vault status and usage telemetry.
- `GET /api/v1/approvals` — returns pending human approval requests.
- `POST /api/v1/approve/{approval_id}` and `/api/v1/reject/{approval_id}` — resolve queued requests.
- `GET /api/v1/email/status` and `POST /api/v1/email/draft` — check the server-side Resend setup and queue an allowlisted message for approval.
- `GET /api/v1/integrations/status` and `POST /api/v1/integrations/config` — inspect integration readiness and configure credentials with the local setup token.
- `POST /api/v1/chat` — send recent conversation turns to Gemini Flash with Google Search grounding and receive an answer with cited sources.

## Founder

**Emmanuel Samuel Ojima** — building the foundation for the next industrial revolution.

## License

Apache 2.0. See [`LICENSE`](LICENSE) when distributing the full project.
