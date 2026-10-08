"""
Every decision, as it happens, to a SIEM: Splunk (HTTP Event Collector), Datadog (logs intake), or any HTTP endpoint
that takes JSON. Set it in the dashboard (Settings → Send to your SIEM) or with SIEM_URL / SIEM_TOKEN / SIEM_FORMAT.

Sent in the background, in batches, so a slow or down SIEM never slows an agent. What's sent is what the dashboard
shows: who, which tool, the decision and why, and the call's input as stored (secrets already redacted), cut to 500
characters. If the SIEM refuses or can't be reached, the batch is dropped and the gateway log says so; the audit trail
in the gateway's own database is the record that counts.
"""
from __future__ import annotations

import json
import logging
import queue
import threading
import time
from typing import Callable

import httpx

log = logging.getLogger("gateway.siem")
BATCH, EVERY = 100, 2.0


def body_and_headers(fmt: str, token: str, items: list[dict]) -> tuple[bytes, dict]:
    if fmt == "splunk":                 # HEC: one JSON object per event, back to back
        body = "\n".join(json.dumps({"time": i["epoch"], "sourcetype": "squidbrake", "source": "squidbrake",
                                     "event": {k: v for k, v in i.items() if k != "epoch"}}) for i in items)
        return body.encode(), {"Authorization": f"Splunk {token}", "Content-Type": "application/json"}
    if fmt == "datadog":                # logs intake v2: a JSON array
        body = [{"ddsource": "squidbrake", "service": "squidbrake", "ddtags": f"decision:{i.get('decision')}",
                 "message": f"{i.get('agent')} {i.get('tool')}: {i.get('decision')} ({i.get('rule_id') or 'default'})",
                 **{k: v for k, v in i.items() if k != "epoch"}} for i in items]
        return json.dumps(body).encode(), {"DD-API-KEY": token, "Content-Type": "application/json"}
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return json.dumps([{k: v for k, v in i.items() if k != "epoch"} for i in items]).encode(), headers


class Forwarder:
    def __init__(self, settings: Callable[[], dict]):
        self._settings = settings
        self._q: queue.Queue = queue.Queue(maxsize=10000)
        self._thread: threading.Thread | None = None
        self._cfg: tuple[float, dict] = (0.0, {})
        self.sent = self.dropped = 0

    def _config(self) -> dict:
        at, cfg = self._cfg
        if time.monotonic() - at > 5:                       # settings are read at most every 5 seconds
            cfg = self._settings()
            self._cfg = (time.monotonic(), cfg)
        return cfg

    def emit(self, item: dict) -> None:
        """Queue one record if a SIEM is set. Never blocks, never raises."""
        try:
            if not self._config().get("siem_url"):
                return
            if self._thread is None or not self._thread.is_alive():
                self._thread = threading.Thread(target=self._run, daemon=True, name="siem")
                self._thread.start()
            self._q.put_nowait({**item, "epoch": time.time()})
        except queue.Full:
            self.dropped += 1
        except Exception:
            log.exception("SIEM: couldn't queue a record")

    def _run(self) -> None:
        while True:
            items = [self._q.get()]
            end = time.monotonic() + EVERY
            while len(items) < BATCH and time.monotonic() < end:
                try:
                    items.append(self._q.get(timeout=max(0.0, end - time.monotonic())))
                except queue.Empty:
                    break
            self.flush(items)

    def flush(self, items: list[dict]) -> bool:
        cfg = self._config()
        if not cfg.get("siem_url"):
            return False
        body, headers = body_and_headers(cfg.get("siem_format") or "json", cfg.get("siem_token") or "", items)
        try:
            httpx.post(cfg["siem_url"], content=body, headers=headers, timeout=10).raise_for_status()
            self.sent += len(items)
            return True
        except Exception as e:
            self.dropped += len(items)
            log.warning("SIEM: %d records not delivered to %s (%s)", len(items), cfg["siem_url"], e)
            return False
