import json
import logging
import os
import signal
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from .hackstone_client import HackstoneClient


@dataclass
class AgentConfig:
    hackstone_base_url: str
    ingest_path: str = "/api/agent/events"
    agent_id: str = "unknown-agent"
    batch_size: int = 50
    send_interval_seconds: int = 5
    max_queue_size: int = 10000


def load_config(config_path: str | Path) -> AgentConfig:
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Agent config not found: {config_path}")
    with path.open("r", encoding="utf-8") as fp:
        raw = json.load(fp)
    return AgentConfig(
        hackstone_base_url=raw.get("hackstone_base_url", "http://localhost:3000"),
        ingest_path=raw.get("ingest_path", "/api/agent/events"),
        agent_id=raw.get("agent_id") or os.uname().nodename,
        batch_size=int(raw.get("batch_size", 50)),
        send_interval_seconds=int(raw.get("send_interval_seconds", 5)),
        max_queue_size=int(raw.get("max_queue_size", 10000)),
    )


def to_hackstone_event(local_event: Dict[str, Any], cfg: AgentConfig) -> Dict[str, Any]:
    action_map = {
        "created": "create",
        "create": "create",
        "modified": "modify",
        "modify": "modify",
        "deleted": "delete",
        "delete": "delete",
    }

    action = local_event.get("action") or local_event.get("event_type")
    normalized_action = action_map.get(str(action).lower(), "modify")

    return {
        "agent_id": cfg.agent_id,
        "path": local_event.get("path") or local_event.get("file_path"),
        "action": normalized_action,
        "timestamp": local_event.get("timestamp"),
        "size": local_event.get("size"),
        "hash": local_event.get("hash"),
        "prev_hash": local_event.get("prev_hash"),
        "user": local_event.get("user"),
        "uid": local_event.get("uid"),
        "gid": local_event.get("gid"),
        "mode": local_event.get("mode"),
        "extra": local_event.get("extra", {}),
    }


class FIMAgent:
    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self.client = HackstoneClient(
            base_url=config.hackstone_base_url,
            ingest_path=config.ingest_path,
            batch_size=config.batch_size,
            send_interval_seconds=config.send_interval_seconds,
            max_queue_size=config.max_queue_size,
        )
        self._stop_event = threading.Event()

    def start(self) -> None:
        logging.info("Starting FIM Agent for HackStone (agent_id=%s)", self.config.agent_id)
        self.client.start()
        self._install_signal_handlers()
        self._run_main_loop()

    def _install_signal_handlers(self) -> None:
        signal.signal(signal.SIGINT, self._graceful_shutdown)
        signal.signal(signal.SIGTERM, self._graceful_shutdown)

    def _graceful_shutdown(self, signum: int, frame: Optional[Any]) -> None:
        logging.info("Received signal %s; shutting down", signum)
        self._stop_event.set()

    def handle_local_event(self, local_event: Dict[str, Any]) -> None:
        mapped = to_hackstone_event(local_event, self.config)
        self.client.enqueue(mapped)

    def _run_main_loop(self) -> None:
        # Placeholder loop: integrate with the existing filesystem watcher.
        # Replace the sleep loop with hooks into the real event source.
        while not self._stop_event.is_set():
            time.sleep(0.5)
        self.client.stop(flush=True)


def main(argv: list[str]) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    config_path = os.environ.get("AGENT_CONFIG", "config/agent_config.json")
    try:
        cfg = load_config(config_path)
    except Exception as exc:
        logging.error("Failed to load agent config from %s: %s", config_path, exc)
        return 1

    agent = FIMAgent(cfg)
    try:
        agent.start()
    except KeyboardInterrupt:
        logging.info("Interrupted; stopping agent")
        agent.client.stop(flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

