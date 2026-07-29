"""Structured assessment logging: human-readable console + JSON Lines."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from .model import utcnow_iso

LEVELS = {"DEBUG": 10, "INFO": 20, "WARN": 30, "ERROR": 40}


class AssessmentLogger:
    def __init__(self, run_id: str, log_path: Path | None = None, jsonl_path: Path | None = None, level: str = "INFO"):
        self.run_id = run_id
        self.level = LEVELS.get(level.upper(), 20)
        self.log_path = log_path
        self.jsonl_path = jsonl_path
        self._log_handle = open(log_path, "a", encoding="utf-8") if log_path else None
        self._jsonl_handle = open(jsonl_path, "a", encoding="utf-8") if jsonl_path else None

    def _emit(self, level: str, component: str, message: str, **fields) -> None:
        if LEVELS.get(level, 20) < self.level:
            return
        ts = utcnow_iso()
        line = f"{ts} [{level:<5}] {component}: {message}"
        stream = sys.stderr if level in ("WARN", "ERROR") else sys.stdout
        print(line, file=stream)
        if self._log_handle:
            self._log_handle.write(line + "\n")
            self._log_handle.flush()
        if self._jsonl_handle:
            record = {
                "ts": ts,
                "runId": self.run_id,
                "level": level,
                "component": component,
                "message": message,
                **fields,
            }
            self._jsonl_handle.write(json.dumps(record) + "\n")
            self._jsonl_handle.flush()

    def debug(self, component: str, message: str, **fields) -> None:
        self._emit("DEBUG", component, message, **fields)

    def info(self, component: str, message: str, **fields) -> None:
        self._emit("INFO", component, message, **fields)

    def warn(self, component: str, message: str, **fields) -> None:
        self._emit("WARN", component, message, **fields)

    def error(self, component: str, message: str, **fields) -> None:
        self._emit("ERROR", component, message, **fields)

    def close(self) -> None:
        for handle in (self._log_handle, self._jsonl_handle):
            if handle:
                handle.close()
