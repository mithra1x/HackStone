"""
A minimal real-time File Integrity Monitoring (FIM) agent.

- Builds a secure baseline of file hashes for a single directory
- Detects create/modify/delete events via lightweight polling
- Logs structured JSON lines with timestamps, MITRE context, and hash deltas
- Adds an integrity chain to make tampering evident
- Avoids traversing hidden files/directories by default to reduce PII risk
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from hashlib import sha256
from typing import Dict, Iterable, Iterator, List, Optional, Set, Tuple

# --------------------------------------------------------------------------------------
# Data structures
# --------------------------------------------------------------------------------------


@dataclass
class FileState:
    path: str
    hash: str
    mtime: float


@dataclass
class FIMEvent:
    event_id: str
    timestamp: str
    event_type: str
    file_path: str
    hash_before: str
    hash_after: str
    ai_risk_score: int
    mitre_technique: str
    user: str
    process_name: str
    host: str
    site: str
    reason: str
    integrity_chain: str


# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------


def hash_file(path: str) -> str:
    """Return the SHA-256 hash hex digest for a file."""
    h = sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def iter_files(directory: str, exclude_hidden: bool = True) -> Iterator[str]:
    """Yield all files under a directory, skipping hidden entries when requested."""
    for root, dirs, files in os.walk(directory):
        if exclude_hidden:
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            files = [f for f in files if not f.startswith(".")]
        for name in files:
            yield os.path.join(root, name)


def load_baseline(baseline_path: str) -> Dict[str, FileState]:
    if not os.path.exists(baseline_path):
        return {}
    with open(baseline_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return {
        path: FileState(path=path, hash=entry["hash"], mtime=entry["mtime"])
        for path, entry in data.items()
    }


def save_baseline(states: Dict[str, FileState], baseline_path: str) -> None:
    payload = {path: {"hash": fs.hash, "mtime": fs.mtime} for path, fs in states.items()}
    with open(baseline_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def build_initial_baseline(directory: str, baseline_path: str, exclude_hidden: bool = True) -> Dict[str, FileState]:
    states: Dict[str, FileState] = {}
    for path in iter_files(directory, exclude_hidden=exclude_hidden):
        try:
            states[path] = FileState(path=path, hash=hash_file(path), mtime=os.path.getmtime(path))
        except OSError:
            continue
    save_baseline(states, baseline_path)
    return states


# --------------------------------------------------------------------------------------
# Event logging with integrity chaining
# --------------------------------------------------------------------------------------


class EventLogger:
    def __init__(self, log_path: str):
        self.log_path = log_path
        self.last_chain_hash = self._load_last_chain()

    def _load_last_chain(self) -> str:
        if not os.path.exists(self.log_path):
            return ""
        try:
            with open(self.log_path, "rb") as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                f.seek(max(size - 4096, 0))
                lines = f.read().splitlines()
            for line in reversed(lines):
                if line.strip():
                    event = json.loads(line)
                    return event.get("integrity_chain", "")
        except Exception:
            return ""
        return ""

    def _next_chain(self, event: Dict) -> str:
        event_bytes = json.dumps(event, sort_keys=True).encode("utf-8")
        return sha256(self.last_chain_hash.encode("utf-8") + event_bytes).hexdigest()

    def log(self, event: FIMEvent) -> None:
        payload = asdict(event)
        payload["integrity_chain"] = self._next_chain(payload)
        self.last_chain_hash = payload["integrity_chain"]
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload) + "\n")
        print(f"[ALERT] {event.event_type.upper()} {event.file_path} @ {event.timestamp} (MITRE {event.mitre_technique})")


# --------------------------------------------------------------------------------------
# Monitoring logic
# --------------------------------------------------------------------------------------


MITRE_MAP = {
    "create": "T1059",  # Execution / script that drops files
    "modify": "T1565",  # Data Manipulation
    "delete": "T1070",  # Indicator Removal
}

RISK_MAP = {"create": 40, "modify": 60, "delete": 70}


class FIMMonitor:
    def __init__(
        self,
        directory: str,
        baseline_path: str,
        log_path: str,
        poll_interval: float = 2.0,
        exclude_hidden: bool = True,
        host: str = "localhost",
        site: str = "production",
    ):
        self.directory = os.path.abspath(directory)
        self.baseline_path = baseline_path
        self.log_path = log_path
        self.poll_interval = poll_interval
        self.exclude_hidden = exclude_hidden
        self.host = host
        self.site = site
        self.logger = EventLogger(log_path)
        self.states: Dict[str, FileState] = {}

    def _timestamp(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _make_event(
        self,
        event_type: str,
        path: str,
        old_hash: str,
        new_hash: str,
        reason: str,
    ) -> FIMEvent:
        return FIMEvent(
            event_id=str(uuid.uuid4()),
            timestamp=self._timestamp(),
            event_type=event_type,
            file_path=path,
            hash_before=old_hash,
            hash_after=new_hash,
            ai_risk_score=RISK_MAP.get(event_type, 30),
            mitre_technique=MITRE_MAP.get(event_type, "T0000"),
            user=os.getenv("USER", "unknown"),
            process_name=os.path.basename(sys.argv[0]) or "fim_agent",
            host=self.host,
            site=self.site,
            reason=reason,
            integrity_chain="",
        )

    def load_or_build_baseline(self) -> None:
        if os.path.exists(self.baseline_path):
            self.states = load_baseline(self.baseline_path)
        else:
            self.states = build_initial_baseline(self.directory, self.baseline_path, exclude_hidden=self.exclude_hidden)
        print(f"Baseline ready for {len(self.states)} files under {self.directory}")

    def _current_snapshot(self) -> Dict[str, FileState]:
        snapshot: Dict[str, FileState] = {}
        for path in iter_files(self.directory, exclude_hidden=self.exclude_hidden):
            try:
                snapshot[path] = FileState(path=path, hash=hash_file(path), mtime=os.path.getmtime(path))
            except OSError:
                continue
        return snapshot

    def _detect_changes(self, snapshot: Dict[str, FileState]) -> List[FIMEvent]:
        events: List[FIMEvent] = []
        prev_paths: Set[str] = set(self.states.keys())
        current_paths: Set[str] = set(snapshot.keys())

        created = current_paths - prev_paths
        deleted = prev_paths - current_paths
        maybe_modified = current_paths & prev_paths

        for path in created:
            fs = snapshot[path]
            events.append(
                self._make_event(
                    "create",
                    path,
                    old_hash="-",
                    new_hash=fs.hash,
                    reason="New file observed; validate change control.",
                )
            )

        for path in deleted:
            old = self.states[path]
            events.append(
                self._make_event(
                    "delete",
                    path,
                    old_hash=old.hash,
                    new_hash="-",
                    reason="File removed; check for indicator removal or cleanup.",
                )
            )

        for path in maybe_modified:
            old = self.states[path]
            new = snapshot[path]
            if old.hash != new.hash:
                events.append(
                    self._make_event(
                        "modify",
                        path,
                        old_hash=old.hash,
                        new_hash=new.hash,
                        reason="Hash drift detected; confirm authorized change.",
                    )
                )
        return events

    def _handle_events(self, events: Iterable[FIMEvent]) -> None:
        for event in events:
            self.logger.log(event)

    def run(self) -> None:
        self.load_or_build_baseline()

        def stop_handler(signum, frame):  # noqa: ANN001
            print("Stopping monitor...")
            save_baseline(self.states, self.baseline_path)
            sys.exit(0)

        signal.signal(signal.SIGINT, stop_handler)
        signal.signal(signal.SIGTERM, stop_handler)

        while True:
            snapshot = self._current_snapshot()
            events = self._detect_changes(snapshot)
            if events:
                self._handle_events(events)
                self.states = snapshot
                save_baseline(self.states, self.baseline_path)
            time.sleep(self.poll_interval)


# --------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Lightweight real-time FIM monitor")
    parser.add_argument("directory", help="Directory to monitor")
    parser.add_argument("--baseline", default="baseline.json", help="Path to baseline file")
    parser.add_argument("--log", default="events.log", help="Path to JSONL event log")
    parser.add_argument("--interval", type=float, default=2.0, help="Polling interval in seconds")
    parser.add_argument("--include-hidden", action="store_true", help="Include hidden files (may risk PII)")
    parser.add_argument("--host", default="localhost", help="Host label for emitted events")
    parser.add_argument("--site", default="production", help="Site/region label for emitted events")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> None:
    args = parse_args(argv)
    monitor = FIMMonitor(
        directory=args.directory,
        baseline_path=args.baseline,
        log_path=args.log,
        poll_interval=args.interval,
        exclude_hidden=not args.include_hidden,
        host=args.host,
        site=args.site,
    )
    monitor.run()


if __name__ == "__main__":
    main()
