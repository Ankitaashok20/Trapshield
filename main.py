#!/usr/bin/env python3
"""
main.py  –  Entry point for the rule-based IDS simulation.

Run as root (or with DRY_RUN=1 for testing without iptables):

    sudo python3 main.py
    DRY_RUN=1 python3 main.py          # no iptables changes
    DRY_RUN=1 python3 main.py --config custom.yaml
"""

import argparse
import os
import sys


def main() -> None:
    parser = argparse.ArgumentParser(description="Rule-Based IDS — simulation")
    parser.add_argument(
        "--config",
        default="config.yaml",
        help="Path to config file (default: config.yaml)",
    )
    args = parser.parse_args()

    # Warn if not root and DRY_RUN is not set
    if os.geteuid() != 0 and os.getenv("DRY_RUN", "0") != "1":
        print(
            "[WARNING] Not running as root. iptables redirection will fail.\n"
            "          Set DRY_RUN=1 to simulate without root privileges.\n",
            file=sys.stderr,
        )

    # Import here so Scapy's startup output is deferred past the arg parse
    from ids.engine import IDSEngine

    engine = IDSEngine(config_path=args.config)
    engine.start()


if __name__ == "__main__":
    main()
