"""
ids/redirector.py - iptables-based traffic redirector.

Simple DNAT only. No MASQUERADE, no SNAT, no Docker workarounds.
Cowrie binds to 0.0.0.0:2222.
honeypot_ip in config.yaml must be your LAN IP.
"""

from __future__ import annotations

import logging
import os
import subprocess
import threading
import time
from typing import Dict, Set

logger = logging.getLogger("IDS")

DRY_RUN: bool = os.getenv("DRY_RUN", "0") == "1"


def _run(cmd: list[str]) -> bool:
    if DRY_RUN:
        logger.debug("[DRY-RUN] %s", " ".join(cmd))
        return True
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        return True
    except subprocess.CalledProcessError as exc:
        logger.error("iptables error: %s", exc.stderr.strip())
        return False


def _rule_exists(cmd: list[str]) -> bool:
    if DRY_RUN:
        return False
    result = subprocess.run(cmd, capture_output=True)
    return result.returncode == 0


def _flush_conntrack(ip: str = None) -> None:
    try:
        if ip:
            subprocess.run(["conntrack", "-D", "-s", ip], capture_output=True)
        else:
            subprocess.run(
                ["conntrack", "-D", "-p", "tcp", "--dport", "22"],
                capture_output=True,
            )
    except FileNotFoundError:
        logger.warning("conntrack not found: sudo apt install conntrack")


def _clean_stale_rules(chain: str, honeypot_port: int) -> None:
    logger.info("Cleaning stale IDS rules from previous run...")

    while _rule_exists([
        "iptables", "-t", "nat", "-C", "PREROUTING", "-j", chain
    ]):
        _run(["iptables", "-t", "nat", "-D", "PREROUTING", "-j", chain])

    _run(["iptables", "-t", "nat", "-F", chain])
    _run(["iptables", "-t", "nat", "-X", chain])

    while _rule_exists([
        "iptables", "-C", "INPUT",
        "-p", "tcp", "--dport", str(honeypot_port), "-j", "ACCEPT",
    ]):
        _run([
            "iptables", "-D", "INPUT",
            "-p", "tcp", "--dport", str(honeypot_port), "-j", "ACCEPT",
        ])

    _flush_conntrack()
    logger.info("Stale rules and conntrack entries cleared.")


class Redirector:

    CHAIN = "IDS_REDIRECT"

    def __init__(
        self,
        honeypot_ip: str,
        honeypot_port: int,
        lan_ip: str,
        block_duration: int = 0,
        drop_real_ssh: bool = False,
    ):
        self.honeypot_ip = honeypot_ip
        self.honeypot_port = honeypot_port
        self.lan_ip = lan_ip
        self.block_duration = block_duration
        self.drop_real_ssh = drop_real_ssh

        self._redirected: Dict[str, float] = {}
        self._dropped: Set[str] = set()
        self._lock = threading.Lock()

        _clean_stale_rules(self.CHAIN, self.honeypot_port)
        self._setup_chain()

    def _setup_chain(self) -> None:
        _run(["iptables", "-t", "nat", "-N", self.CHAIN])
        # Append to PREROUTING - no Docker interference workaround
        _run(["iptables", "-t", "nat", "-A", "PREROUTING", "-j", self.CHAIN])
        _run([
            "iptables", "-A", "INPUT",
            "-p", "tcp", "--dport", str(self.honeypot_port), "-j", "ACCEPT",
        ])
        logger.info(
            "iptables chain %s ready | DNAT -> %s:%d",
            self.CHAIN, self.honeypot_ip, self.honeypot_port,
        )

    def teardown(self) -> None:
        for ip in list(self._dropped):
            self._remove_drop_rule(ip)
        _clean_stale_rules(self.CHAIN, self.honeypot_port)
        logger.info("All IDS rules removed cleanly.")

    def redirect(self, src_ip: str) -> bool:
        with self._lock:
            if src_ip in self._redirected:
                return False

            ok = _run([
                "iptables", "-t", "nat", "-A", self.CHAIN,
                "-s", src_ip, "-p", "tcp", "--dport", "22",
                "-j", "DNAT",
                "--to-destination", f"{self.honeypot_ip}:{self.honeypot_port}",
            ])

            if not ok:
                return False

            _flush_conntrack(src_ip)

            self._redirected[src_ip] = time.monotonic()
            logger.info(
                "DNAT added: %s -> port 22 -> %s:%d",
                src_ip, self.honeypot_ip, self.honeypot_port,
            )

            if self.drop_real_ssh:
                self._add_drop_rule(src_ip)

            if self.block_duration > 0:
                t = threading.Timer(
                    self.block_duration, self._expire_redirect, args=(src_ip,)
                )
                t.daemon = True
                t.start()

            return True

    def _add_drop_rule(self, src_ip: str) -> None:
        ok = _run([
            "iptables", "-A", "INPUT",
            "-s", src_ip, "-p", "tcp", "--dport", "22", "-j", "DROP",
        ])
        if ok:
            self._dropped.add(src_ip)

    def _remove_drop_rule(self, src_ip: str) -> None:
        _run([
            "iptables", "-D", "INPUT",
            "-s", src_ip, "-p", "tcp", "--dport", "22", "-j", "DROP",
        ])
        self._dropped.discard(src_ip)

    def _expire_redirect(self, src_ip: str) -> None:
        with self._lock:
            if src_ip not in self._redirected:
                return
            _run([
                "iptables", "-t", "nat", "-D", self.CHAIN,
                "-s", src_ip, "-p", "tcp", "--dport", "22",
                "-j", "DNAT",
                "--to-destination", f"{self.honeypot_ip}:{self.honeypot_port}",
            ])
            del self._redirected[src_ip]
            _flush_conntrack(src_ip)
            if src_ip in self._dropped:
                self._remove_drop_rule(src_ip)
            logger.info("Redirect expired for %s", src_ip)

    def is_redirected(self, src_ip: str) -> bool:
        return src_ip in self._redirected

    @property
    def redirected_ips(self) -> list[str]:
        return list(self._redirected.keys())
