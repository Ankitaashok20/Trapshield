# TrapShield — Rule-Based IDS with Honeypot Redirection

A rule-based Intrusion Detection System that detects **brute-force** (Hydra) and **port-scan** (nmap) attacks on a Linux machine and transparently redirects attackers into a **Cowrie SSH honeypot** using `iptables DNAT`.

> **For educational and simulation purposes only. Use only on networks you own or have explicit permission to test.**

---

## How It Works

```
Attacker (friend's machine)
        |
        | SSH brute-force / port scan
        v
Your Machine (port 22)
        |
        | Scapy sniffs TCP packets
        v
   IDS Engine
   ├── BruteForceRule  — N SYN packets to port 22 within T seconds
   └── PortScanRule    — N distinct ports contacted within T seconds
        |
   Attack detected?
   ├── YES → iptables DNAT rule added for attacker's IP
   |          attacker's port 22 traffic → YOUR_LAN_IP:2222
   |          attacker lands in Cowrie fake shell
   └── NO  → keep sniffing
```

---

## Folder Structure

```
TrapShield/
├── config.yaml          ← All tunable parameters (edit this)
├── main.py              ← Entry point
├── requirements.txt
├── ids/
│   ├── __init__.py
│   ├── config.py        ← Config loader
│   ├── engine.py        ← Scapy sniffer + dispatch loop
│   ├── rules.py         ← BruteForceRule, PortScanRule
│   ├── redirector.py    ← iptables DNAT manager
│   └── logger.py        ← JSON-lines alert logger
└── logs/
    └── ids_alerts.log   ← Generated at runtime (JSON lines)
```

---

## Prerequisites

### System packages

```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv
sudo apt install iptables conntrack
sudo apt install fail2ban
```

### Python dependencies

```bash
cd TrapShield
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Step 1 — Install and Configure Cowrie

Cowrie is a medium-interaction SSH honeypot. It must be running on a separate terminal before attacks are tested.

# 🐝 Cowrie Honeypot Setup Guide

This guide explains how to install, configure, and run the Cowrie honeypot on a Linux system.

---


Update your system and install required dependencies:

```bash
sudo apt update
sudo apt install -y git python3-venv python3-pip

#clone cowrie
git clone https://github.com/cowrie/cowrie.git
cd cowrie

#create virtual environment
python3 -m venv cowrie-env
#activate virtual environment
source cowrie-env/bin/activate

pip install -r requirements.txt
#Cowrie configuration
cp etc/cowrie.cfg.dist etc/cowrie.cfg
nano etc/cowrie.cfg
#Search for this part, if this is not the same change to this
listen_endpoints = tcp:2222:interface=0.0.0.0
#start cowrie
cowrie start
#verify
ss -tuln | grep 2222

#To stop Cowrie:

bin/cowrie stop
```

---

## Step 2 — Configure fail2ban (Critical)

By default, fail2ban bans IPs that fail SSH login for **10 minutes**. This causes "connection refused" during testing because the attacker's IP gets banned by fail2ban before the IDS can redirect them to Cowrie.

**Reduce the ban time to 6 seconds for testing:**

```bash
# Backup and open jail config
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
sudo nano /etc/fail2ban/jail.local
```

Find the `[DEFAULT]` section and set:
```ini
[DEFAULT]
bantime = 0.1m
```

Save and reload:
```bash
sudo fail2ban-client reload
```

Verify the new ban time:
```bash
sudo fail2ban-client get sshd bantime
# Should output: 6
```

> Without this step, after the first Hydra attack fail2ban will ban the attacker's IP for 10 minutes. All subsequent attacks will show "connection refused" before the IDS even sees the packets.

---

## Step 3 — Configure TrapShield

Find your LAN IP and interface:
```bash
ip route show default
# Look for: default via ... dev enp2s0f1
# The name after "dev" is your interface

ip addr show enp2s0f1 | grep "inet "
# e.g. inet 10.x.x.x/20 -> your LAN IP is 10.x.x.x
```

Edit `config.yaml`:
```yaml
# Before starting your IDS always check whether your actual interface and LAN-IP matches your config.yaml IP
network:
  interface: "YOUR-INTERFACE-NAME"        # Put your interface name here like enp2s0f1, wlp0s20f3
  lan_ip: "YOUR-LAN-IP"       # Put your LAN IP here
  honeypot_ip: "YOUR-LAN-IP"  # same as your lan_ip
  honeypot_port: 2222

rules:
  brute_force:
    enabled: true
    threshold: 5               # SYN packets before alert
    window_seconds: 30

  port_scan:
    enabled: true
    threshold: 10              # distinct ports before alert
    window_seconds: 10

response:
  redirect_to_honeypot: true
  block_duration_seconds: 0    # 0 = redirect persists until IDS restarts
  drop_real_ssh: false

logging:
  log_file: "logs/ids_alerts.log"
  log_level: "INFO"
```

---

## Step 4 — Run TrapShield

```bash
cd TrapShield


# Clean any stale iptables rules from previous runs (This step is optional, use it only if your get error)
sudo iptables -t nat -F
sudo iptables -t nat -X IDS_REDIRECT 2>/dev/null
sudo iptables -D INPUT -p tcp --dport 2222 -j ACCEPT 2>/dev/null
sudo conntrack -F

# Before Starting IDS verify whether you are in virtual environment or not. If not, run
source venv/bin/activate

# Start IDS (must be root for Scapy + iptables)
sudo venv/bin/python main.py
```

Expected startup output:
```
[INFO]  net.ipv4.ip_forward = 1
[INFO]  Cleaning stale IDS rules from previous run...
[INFO]  Stale rules and conntrack entries cleared.
[INFO]  iptables chain IDS_REDIRECT ready | DNAT -> 10.x.x.x:2222
[INFO]  IDS started — interface=enp2s0f1  brute_force=on  port_scan=on
```

To stop: press **Ctrl-C** — all iptables rules are removed automatically.

---

## Step 5 — Attacker Tests
Note1: After running your attack (brute force or hydra) when your IDS detects the attack run ssh root attack. 
Note2: Before simulating another attack stop your IDS and then Start it
Both machines must be on the same network. Verify connectivity first:
```bash
# From attacker's machine
ping YOUR_LAN_IP
```

### Brute-force attack (Hydra)
```bash
hydra -l root -P password.txt ssh://YOUR_LAN_IP -t 4 -V
# After this run ssh root attack
```

### Port scan (nmap)
```bash
nmap -sS YOUR_LAN_IP
# After this run ssh root attack
```

### After IDS detects the attack

The attacker's SSH connection is silently redirected to Cowrie:
```bash
# Attacker runs this — lands in Cowrie fake shell
ssh root@YOUR_LAN_IP
```

Watch Cowrie receive the attacker:
```bash
tail -f ~/cowrie/var/log/cowrie/cowrie.log
```

Watch IDS alerts:
```bash
tail -f logs/ids_alerts.log
```

---

## Restart Sequence

Every time you restart TrapShield, run this first (but in a virtual environment):

```bash

sudo venv/bin/python main.py
```

---

## Log Format

`logs/ids_alerts.log` — one JSON object per line:

```json
{
  "timestamp": "2026-04-06T07:47:48.485780+00:00",
  "attack_type": "BRUTE_FORCE",
  "src_ip": "10.x.x.x",
  "detail": "5 SYN packets to port 22 within 30s window",
  "redirected": true
}
```

---

---

## Dashboard

Open the trapshield_dashboard.html and load cowrie.json file into it


---

## Troubleshooting

| Problem | Cause | Fix |
|---|---|---|
| `No route to host` | Devices on different networks | Both must be on same WiFi/hotspot |
| `Connection refused` after restart | Stale conntrack entries | Run `sudo conntrack -F` before starting |
| `Connection refused` on second attack | fail2ban banned the IP | Reduce `bantime` to 6 in `jail.local` |
| IDS detects but `redirected: false` | iptables error | Check IDS log for iptables errors |
| Cowrie shows no logs | Cowrie not running | Run `bin/cowrie status` and restart |
| Internet breaks | Stale iptables rules | Run `sudo iptables -P INPUT ACCEPT` |

---

## Tech Stack

| Component | Technology |
|---|---|
| Packet capture | Scapy |
| Detection rules | Sliding window (deque-based) |
| Redirection | iptables DNAT |
| Honeypot | Cowrie |
| Brute-force protection | fail2ban |
| Language | Python 3.10+ |

---

## Security Note

This project is intended for **educational use only** between consenting parties on a private network. Do not deploy on production systems or public networks.
