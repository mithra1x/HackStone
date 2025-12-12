import logging
import queue
import threading
from typing import Any, Dict, Iterable, List, Optional

import requests


class HackstoneClient:
    """HTTP client that batches and ships events to HackStone."""

    def __init__(
        self,
        *,
        base_url: str,
        ingest_path: str = "/api/agent/events",
        batch_size: int = 50,
        send_interval_seconds: int = 5,
        max_queue_size: int = 10000,
        session: Optional[requests.Session] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.ingest_path = ingest_path if ingest_path.startswith("/") else f"/{ingest_path}"
        self.batch_size = max(1, batch_size)
        self.send_interval_seconds = max(1, send_interval_seconds)
        self.max_queue_size = max_queue_size
        self.session = session or requests.Session()

        self._queue: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=max_queue_size)
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._run, name="hackstone-sender", daemon=True)

    def start(self) -> None:
        logging.info(
            "HackStone client starting: url=%s%s batch_size=%s interval=%ss",
            self.base_url,
            self.ingest_path,
            self.batch_size,
            self.send_interval_seconds,
        )
        if not self._thread.is_alive():
            self._thread.start()

    def stop(self, flush: bool = True, timeout: float = 5.0) -> None:
        logging.info("HackStone client stopping (flush=%s)", flush)
        self._stop_event.set()
        if flush:
            self._flush()
        self._thread.join(timeout=timeout)

    def enqueue(self, event: Dict[str, Any]) -> None:
        if self._queue.full():
            try:
                dropped = self._queue.get_nowait()
                logging.warning("HackStone queue full (%s); dropping oldest event for %s", self.max_queue_size, dropped.get("path"))
            except queue.Empty:
                pass
        self._queue.put_nowait(event)

    def _run(self) -> None:
        while not self._stop_event.is_set():
            self._flush()
            self._stop_event.wait(self.send_interval_seconds)
        self._flush()

    def _dequeue_batch(self) -> List[Dict[str, Any]]:
        events: List[Dict[str, Any]] = []
        while len(events) < self.batch_size:
            try:
                events.append(self._queue.get_nowait())
            except queue.Empty:
                break
        return events

    def _flush(self) -> None:
        batch = self._dequeue_batch()
        if not batch:
            return

        payload: Iterable[Dict[str, Any]] | Dict[str, Any]
        if len(batch) == 1:
            payload = batch[0]
        else:
            payload = batch

        url = f"{self.base_url}{self.ingest_path}"
        try:
            response = self.session.post(url, json=payload, timeout=10)
            if response.status_code >= 200 and response.status_code < 300:
                logging.info("Sent %s event(s) to HackStone", len(batch))
            else:
                logging.error(
                    "Failed to send events to HackStone: status=%s body=%s", response.status_code, self._safe_body(response)
                )
                for evt in batch:
                    self.enqueue(evt)
        except Exception as exc:  # broad exception to keep agent alive
            logging.error("Error sending events to HackStone: %s", exc)
            for evt in batch:
                self.enqueue(evt)

    @staticmethod
    def _safe_body(response: requests.Response) -> str:
        try:
            return response.text
        except Exception:
            return "<unavailable>"

