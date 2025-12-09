# Real-Time File Integrity Monitoring (FIM)

This project ships a minimal, dependency-light File Integrity Monitoring service with a React UI delivered via CDN builds. It watches a single directory, builds a SHA-256 baseline, and streams create/modify/delete events with MITRE-aligned context.

## Features
- Monitors the `watched/` directory (recursive) for create, modify, and delete events
- Builds and persists a secure baseline to `data/baseline.json`
- Governance-aware filter that skips paths containing `personal`, `private`, `secret`, or `pii`
- JSONL audit log at `logs/fim.log` to maintain log integrity
- Real-time event feed via Server-Sent Events (SSE) consumed by a lightweight React front-end
- Quick baseline rebuild endpoint and button for trusted maintenance windows

## Running the system
No package installs are required. Everything uses Node.js core modules and CDN React builds.

```bash
# Start the server
node server/index.js
# Open http://localhost:3000 in a browser to view the dashboard.
```

The server will create missing folders (`watched/`, `logs/`, `data/`, `public/`) on boot. An initial baseline is stored at `data/baseline.json`.

### Triggering events
- **Create**: `echo "note" > watched/new.txt`
- **Modify**: `echo "change" >> watched/critical.txt`
- **Delete**: `rm watched/new.txt`

Events will appear instantly in the UI timeline with hashes, MITRE references, and severity labels.

### API surface
- `GET /api/events` — latest timeline data and baseline size
- `POST /api/rebuild` — rebuild baseline from current disk state (use after trusted maintenance)
- `GET /api/config` — view watch path and governance filter in effect
- `GET /stream` — SSE endpoint used by the UI for live updates

## Security and governance notes
- The watcher ignores file paths containing `personal`, `private`, `secret`, or `pii` to avoid personal data.
- Log entries append to `logs/fim.log` in JSON Lines format to preserve ordering and integrity.
- MITRE ATT&CK-inspired metadata is attached to each event to aid investigation.

## Front-end
The UI is served from `public/` and uses React (UMD) and Babel from CDNs. Styles live in `public/styles.css`. No build step is required.
