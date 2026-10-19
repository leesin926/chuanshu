"""Rotating file logging for the desktop app."""

from __future__ import annotations

import logging
import logging.handlers
import sys

from app.paths import is_frozen, logs_dir

LOG_NAME = "app.log"
_format = "%(asctime)s %(levelname)-7s [%(name)s] %(message)s"
_log_path = None


def setup_logging(level: int = logging.DEBUG) -> None:
    global _log_path
    root = logging.getLogger()
    root.setLevel(level)
    for handler in list(root.handlers):
        root.removeHandler(handler)

    directory = logs_dir()
    directory.mkdir(parents=True, exist_ok=True)
    _log_path = directory / LOG_NAME

    file_handler = logging.handlers.RotatingFileHandler(
        _log_path, maxBytes=1_000_000, backupCount=5, encoding="utf-8"
    )
    file_handler.setLevel(level)
    file_handler.setFormatter(logging.Formatter(_format))
    root.addHandler(file_handler)

    if not is_frozen():
        console = logging.StreamHandler(sys.stderr)
        console.setLevel(logging.INFO)
        console.setFormatter(logging.Formatter(_format))
        root.addHandler(console)

    logging.getLogger("PySide6").setLevel(logging.INFO)
    logging.info("logging to %s", _log_path)


def log_file() -> str:
    return str(_log_path) if _log_path else str(logs_dir() / LOG_NAME)
