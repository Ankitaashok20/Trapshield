"""
ids/logger.py  –  Structured alert logger.

Each alert is written as a JSON-lines entry so the log is
machine-parseable as well as human-readable.
"""

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path


def setup_logger(log_file: str, level: str = "INFO") -> logging.Logger:
    Path(log_file).parent.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("IDS")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Console handler – human-readable
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter(
        "%(asctime)s  [%(levelname)s]  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))

    # File handler – JSON lines
    fh = logging.FileHandler(log_file)
    fh.setFormatter(logging.Formatter("%(message)s"))

    logger.addHandler(ch)
    logger.addHandler(fh)
    return logger


def log_alert(
    logger: logging.Logger,
    attack_type: str,
    src_ip: str,
    detail: str,
    redirected: bool = False,
) -> None:
    """Emit a structured alert entry."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "attack_type": attack_type,
        "src_ip": src_ip,
        "detail": detail,
        "redirected": redirected,
    }
    # Console shows a clean one-liner; file gets the full JSON record.
    logger.warning(
        "ALERT  type=%-12s  src=%-15s  %s%s",
        attack_type,
        src_ip,
        detail,
        "  [REDIRECTED→honeypot]" if redirected else "",
    )
    # Write JSON to file via DEBUG (file handler captures all levels)
    file_logger = logging.getLogger("IDS.file")
    if not file_logger.handlers:
        fh = logging.FileHandler(logger.handlers[-1].baseFilename)
        fh.setFormatter(logging.Formatter("%(message)s"))
        file_logger.addHandler(fh)
        file_logger.setLevel(logging.DEBUG)
        file_logger.propagate = False
    file_logger.debug(json.dumps(entry))
