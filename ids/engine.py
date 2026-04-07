"""
ids/engine.py - Core IDS engine.
"""

from __future__ import annotations

import logging
import os
import signal
import subprocess
import sys
from typing import Optional

from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sniff

from .config import load_config
from .logger import log_alert, setup_logger
from .redirector import Redirector
from .rules import BruteForceRule, PortScanRule

logger = logging.getLogger("IDS")


def _enable_ip_forward() -> None:
    if os.getenv("DRY_RUN", "0") == "1":
        logger.debug("[DRY-RUN] would set net.ipv4.ip_forward=1")
        return
    try:
        subprocess.run(
            ["sysctl", "-w", "net.ipv4.ip_forward=1"],
            check=True, capture_output=True,
        )
        logger.info("net.ipv4.ip_forward = 1")
    except subprocess.CalledProcessError as e:
        logger.warning("Could not enable ip_forward: %s", e.stderr.strip())


def _detect_default_interface() -> str:
    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default"], text=True
        )
        parts = out.split()
        if "dev" in parts:
            return parts[parts.index("dev") + 1]
    except Exception:
        pass
    return "eth0"


class IDSEngine:
    def __init__(self, config_path: str = "config.yaml"):
        self.cfg = load_config(config_path)

        log_cfg = self.cfg["logging"]
        self._logger = setup_logger(log_cfg["log_file"], log_cfg["log_level"])

        iface = self.cfg["network"]["interface"]
        if iface.lower() == "auto":
            iface = _detect_default_interface()
            logger.info("Auto-detected interface: %s", iface)
        self._interface = iface

        rules_cfg = self.cfg["rules"]
        bf_cfg = rules_cfg["brute_force"]
        ps_cfg = rules_cfg["port_scan"]

        self.bf_rule: Optional[BruteForceRule] = None
        if bf_cfg["enabled"]:
            self.bf_rule = BruteForceRule(
                threshold=bf_cfg["threshold"],
                window_seconds=bf_cfg["window_seconds"],
                watch_ports=bf_cfg["watch_ports"],
            )

        self.ps_rule: Optional[PortScanRule] = None
        if ps_cfg["enabled"]:
            self.ps_rule = PortScanRule(
                threshold=ps_cfg["threshold"],
                window_seconds=ps_cfg["window_seconds"],
                syn_only=ps_cfg.get("syn_only", True),
            )

        net_cfg = self.cfg["network"]
        resp_cfg = self.cfg["response"]
        self.redirector: Optional[Redirector] = None
        if resp_cfg["redirect_to_honeypot"]:
            _enable_ip_forward()
            self.redirector = Redirector(
                honeypot_ip=net_cfg["honeypot_ip"],
                honeypot_port=net_cfg["honeypot_port"],
                lan_ip=net_cfg["lan_ip"],
                block_duration=resp_cfg["block_duration_seconds"],
                drop_real_ssh=resp_cfg.get("drop_real_ssh", False),
            )

        signal.signal(signal.SIGINT, self._shutdown)
        signal.signal(signal.SIGTERM, self._shutdown)

    def _process_packet(self, pkt) -> None:
        if not (IP in pkt and TCP in pkt):
            return

        src_ip = pkt[IP].src
        dst_port = pkt[TCP].dport
        flags = str(pkt[TCP].flags)

        alerts = []

        if self.bf_rule:
            alert = self.bf_rule.check(src_ip, dst_port, flags)
            if alert:
                alerts.append(alert)

        if self.ps_rule:
            alert = self.ps_rule.check(src_ip, dst_port, flags)
            if alert:
                alerts.append(alert)

        for alert in alerts:
            redirected = False
            if self.redirector:
                redirected = self.redirector.redirect(src_ip)
                if redirected:
                    if self.bf_rule:
                        self.bf_rule.reset_ip(src_ip)
                    if self.ps_rule:
                        self.ps_rule.reset_ip(src_ip)

            log_alert(
                self._logger,
                attack_type=alert.attack_type,
                src_ip=alert.src_ip,
                detail=alert.detail,
                redirected=redirected,
            )

    def start(self) -> None:
        logger.info(
            "IDS started — interface=%s  brute_force=%s  port_scan=%s",
            self._interface,
            "on" if self.bf_rule else "off",
            "on" if self.ps_rule else "off",
        )
        sniff(
            iface=self._interface,
            filter="tcp",
            prn=self._process_packet,
            store=False,
        )

    def _shutdown(self, *_) -> None:
        logger.info("Shutting down IDS...")
        if self.redirector:
            self.redirector.teardown()
        sys.exit(0)
