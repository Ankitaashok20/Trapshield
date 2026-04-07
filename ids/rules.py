"""
ids/rules.py  –  Stateful detection rules.

Each rule maintains a sliding-window counter keyed by source IP.
Packets are fed in via .check(); when a threshold is crossed the
rule returns an Alert namedtuple.

Rules:
  BruteForceRule  –  counts TCP SYN packets to auth ports in a time window.
  PortScanRule    –  counts distinct destination ports hit from one source IP.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, Optional, Set, Tuple


# ── Alert ─────────────────────────────────────────────────────────────────────

@dataclass
class Alert:
    attack_type: str
    src_ip: str
    detail: str


# ── Sliding-window helper ─────────────────────────────────────────────────────

class _SlidingWindow:
    """Keep timestamps of events in a fixed-duration window."""

    def __init__(self, window_seconds: float):
        self._window = window_seconds
        self._events: Deque[float] = deque()

    def add(self, ts: Optional[float] = None) -> None:
        self._events.append(ts or time.monotonic())
        self._expire()

    def count(self) -> int:
        self._expire()
        return len(self._events)

    def _expire(self) -> None:
        cutoff = time.monotonic() - self._window
        while self._events and self._events[0] < cutoff:
            self._events.popleft()

    def reset(self) -> None:
        self._events.clear()


# ── Brute-Force Rule ──────────────────────────────────────────────────────────

class BruteForceRule:
    """
    Trigger when a single source IP sends more than `threshold` TCP SYN
    packets to any watched port within `window_seconds`.

    Scapy packet fields used:
      pkt[IP].src          – source IP
      pkt[TCP].dport       – destination port
      pkt[TCP].flags       – 'S' (SYN) flag
    """

    def __init__(self, threshold: int, window_seconds: float, watch_ports: list[int]):
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.watch_ports: Set[int] = set(watch_ports)
        # per-IP sliding window
        self._windows: Dict[str, _SlidingWindow] = defaultdict(
            lambda: _SlidingWindow(window_seconds)
        )
        # IPs that have already triggered (avoid alert storm)
        self._alerted: Set[str] = set()

    def check(self, src_ip: str, dst_port: int, flags: str) -> Optional[Alert]:
        # Only care about SYN packets to watched ports
        if dst_port not in self.watch_ports:
            return None
        if "S" not in flags:
            return None

        win = self._windows[src_ip]
        win.add()
        count = win.count()

        if count >= self.threshold and src_ip not in self._alerted:
            self._alerted.add(src_ip)
            return Alert(
                attack_type="BRUTE_FORCE",
                src_ip=src_ip,
                detail=(
                    f"{count} SYN packets to port {dst_port} "
                    f"within {self.window_seconds}s window"
                ),
            )
        return None

    def reset_ip(self, src_ip: str) -> None:
        """Call after redirecting an IP to avoid repeated re-alerting."""
        self._windows[src_ip].reset()
        self._alerted.discard(src_ip)


# ── Port-Scan Rule ────────────────────────────────────────────────────────────

class PortScanRule:
    """
    Trigger when a single source IP contacts more than `threshold` distinct
    destination ports within `window_seconds`.

    Scapy packet fields used:
      pkt[IP].src          – source IP
      pkt[TCP].dport       – destination port
      pkt[TCP].flags       – 'S' flag (when syn_only=True)
    """

    def __init__(self, threshold: int, window_seconds: float, syn_only: bool = True):
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.syn_only = syn_only
        # per-IP: deque of (timestamp, port) tuples
        self._history: Dict[str, Deque[Tuple[float, int]]] = defaultdict(deque)
        self._alerted: Set[str] = set()

    def check(self, src_ip: str, dst_port: int, flags: str) -> Optional[Alert]:
        if self.syn_only and "S" not in flags:
            return None

        now = time.monotonic()
        hist = self._history[src_ip]

        # Expire old entries
        cutoff = now - self.window_seconds
        while hist and hist[0][0] < cutoff:
            hist.popleft()

        # Add current event
        hist.append((now, dst_port))

        # Count distinct ports in window
        distinct_ports = {p for _, p in hist}

        if len(distinct_ports) >= self.threshold and src_ip not in self._alerted:
            self._alerted.add(src_ip)
            ports_str = ", ".join(str(p) for p in sorted(distinct_ports)[:10])
            if len(distinct_ports) > 10:
                ports_str += f" … (+{len(distinct_ports)-10} more)"
            return Alert(
                attack_type="PORT_SCAN",
                src_ip=src_ip,
                detail=(
                    f"{len(distinct_ports)} distinct ports in "
                    f"{self.window_seconds}s — [{ports_str}]"
                ),
            )
        return None

    def reset_ip(self, src_ip: str) -> None:
        self._history[src_ip].clear()
        self._alerted.discard(src_ip)
