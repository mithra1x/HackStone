# Real-Time File Integrity Monitoring (FIM) MVP

This repo contains a minimal, governance-aware FIM agent plus a tiny HTTP feed and Streamlit UI for visualizing events.

## Components
- `fim_agent.py`: builds a secure baseline for one directory, detects create/modify/delete via polling, emits JSONL events with MITRE context, hash deltas, and an integrity chain.
- `server.py`: exposes the last N events on `http://127.0.0.1:8000/events` so the UI can consume them.
- `app.py`: Streamlit dashboard that renders KPIs, a table, and a timeline for ingested events.

## Quick start
1. **Install dependencies** (Streamlit UI is optional for headless agents):
   ```bash
   pip install -r requirements.txt
   ```
2. **Run the monitor** against a directory:
   ```bash
   python fim_agent.py /path/to/watch --baseline baseline.json --log events.log --interval 2
   ```
   - Hidden files/dirs are skipped to reduce PII risk; pass `--include-hidden` to opt in.
   - The agent prints live alerts and appends JSONL events to `events.log` with a tamper-evident chain.
3. **Serve the feed** (from another terminal):
   ```bash
   python server.py
   ```
4. **Launch the dashboard** (optional):
   ```bash
   streamlit run app.py
   ```
   - The left hamburger menu mirrors an enterprise layout (Overview, Investment Portfolio, Liquidity/Risk Management, Reports, Administration) so you can jump straight to KPIs, hot assets, or export views with minimal clicks.

## Event format
Each log entry is a JSON object containing:
- `timestamp` (UTC ISO8601)
- `event_type` (`create`, `modify`, `delete`)
- `file_path`, `hash_before`, `hash_after`
- `mitre_technique` (loosely aligned to Tampering/Indicator Removal)
- `reason` (why it matters), `ai_risk_score`, `user`, `process_name`, `host`, `site`
- `integrity_chain` (SHA-256 chain of the previous hash + current payload)

## Security and governance notes
- Hidden paths are ignored by default to minimize accidental monitoring of personal data.
- Hash-only storage means file contents are never persisted by the agent.
- Integrity chaining makes log tampering evident; keep `events.log` on protected storage for stronger guarantees.
- Use `--baseline` and `--log` paths on encrypted disks if monitoring regulated environments.

## Interpreting output
- Sudden `delete` events map to MITRE `T1070` (indicator removal) and should be triaged.
- `modify` events map to `T1565` (data manipulation) and often indicate tampering.
- `create` events map to `T1059` (execution/scripting artifacts) and may precede payload staging.

## Minimal alerting
The agent prints `[ALERT] <TYPE> <file> @ <ts> (MITRE <code>)` to stdout for quick triage. Pair with systemd or another supervisor to ship stdout to your SIEM.

## Timeline view
`app.py` shows the last 12 events in chronological order with MITRE badges and risk coloring, giving an analyst-friendly sequence of actions.

## Graceful shutdown
Press `Ctrl+C` or send SIGTERM to persist the latest baseline and exit cleanly.
