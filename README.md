# CybWatch

A Raspberry Pi-based home network security monitor. Captures network traffic with Zeek, runs detection rules against it, and surfaces results through a web dashboard and email alerts.

---

## Stack

- **Hardware:** Raspberry Pi 5
- **Backend:** Python 3.11, FastAPI, SQLite (via aiosqlite)
- **Frontend:** Jinja2 + Tailwind CSS (CDN) + htmx + Chart.js
- **Network tools:** Zeek (traffic capture), Nmap (device discovery)
- **Alerts:** Gmail SMTP

---

## Detection Rules

| Rule | Severity | Trigger |
|------|----------|---------|
| `suspicious_port_connection` | HIGH | Connection to risky ports (22, 23, 445, 3389, etc.) |
| `port_scan_detection` | HIGH | 10+ unique ports from one source in 60 seconds |
| `new_device_alert` | MEDIUM | Previously unseen MAC address on the network |
| `malicious_ip_connection` | CRITICAL | Destination IP appears in threat intel blocklist |

---

## Setup

On the Pi:

```bash
git clone <repo-url> cybwatch
cd cybwatch

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# edit .env to configure SMTP credentials, target network, etc.

./setup/update-blocklists.sh        # fetch threat intel data
./setup/install-services.sh         # install systemd units

sudo systemctl start cybwatch-web cybwatch-worker
sudo systemctl enable cybwatch-web cybwatch-worker
```

Web UI is then available at `http://<pi-ip>:8000`.

---

## Project Structure

```
cybwatch/
├── src/
│   ├── config.py            # Pydantic settings loader
│   ├── database.py          # SQLite schema + access layer
│   ├── models.py            # Pydantic data models
│   ├── main.py              # FastAPI application
│   ├── worker.py            # Background log-processing loop
│   ├── parsers/             # Zeek log + Nmap XML parsers
│   ├── detection/           # Detection rule engine
│   ├── alerts/              # Email notifier (SMTP)
│   ├── threat_intel/        # Blocklist loader + checker
│   └── routers/             # FastAPI routes (5 pages)
├── templates/               # Jinja2 templates (one per page + base layout)
├── setup/                   # install-services.sh, update-blocklists.sh
├── data/blocklists/         # Cached threat intel feeds
├── tests/                   # pytest suite
├── .env.example
└── requirements.txt
```

---

## Running Manually

```bash
# Web server
uvicorn src.main:app --host 0.0.0.0 --port 8000 --reload

# Worker
python -m src.worker
```

---

## Tests

```bash
pytest tests/
```
