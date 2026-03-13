# Pi-Gotcha

A network monitoring dashboard for Raspberry Pi. See where all your traffic is going and block anything you don't like — in real time.

---

## What It Does

- **DNS Proxy** — intercepts every DNS query on your network, logs who asked for what
- **Packet Capture** — records TCP/UDP connections visible to the Pi
- **GeoIP Mapping** — shows where your traffic is going on a world map
- **One-click Blocking** — block any domain from the dashboard instantly
- **Device Inventory** — tracks every device that makes a DNS query
- **Live Dashboard** — auto-refreshes every 5 seconds

---

## Requirements

- Raspberry Pi (any model with network access)
- Python 3.9+
- Root/sudo (required for port 53 and raw packet capture)

---

## Setup

### 1. Clone and install

```bash
git clone https://github.com/YOUR_USERNAME/Pi-Gotcha.git
cd Pi-Gotcha
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure

```bash
cp .env.example .env
```

Edit `.env` if you want to change defaults:

```
UPSTREAM_DNS=8.8.8.8     # Where Pi-Gotcha forwards DNS queries
DNS_PORT=53
API_PORT=8080
```

### 3. Download GeoIP database (free)

1. Create a free account at https://dev.maxmind.com
2. Download **GeoLite2-City.mmdb**
3. Place it at `geoip/GeoLite2-City.mmdb`

### 4. Point your router's DNS at the Pi

In your router's DHCP settings, set the **DNS server** to your Pi's IP address (e.g. `192.168.1.100`).

This makes every device on your network send DNS queries through Pi-Gotcha.

> Find your Pi's IP: `hostname -I`

### 5. Run

```bash
sudo .venv/bin/python main.py
```

Open your browser to `http://<pi-ip>:8080`

---

## Dashboard

| Section | What it shows |
|---|---|
| Stats bar | Total queries, blocked count, block rate, device count |
| Live DNS Feed | Real-time stream of DNS queries with one-click block |
| Top Domains | Bar chart of most queried domains |
| Traffic Map | World map of where connections are going |
| Blocklist | Manage blocked domains |
| Devices | Every device seen on the network |

---

## Blocking

### From the dashboard

Click **Block** next to any entry in the DNS feed, or type a domain into the Blocklist panel.

### From the command line

```bash
# Block a domain
curl -X POST http://localhost:8080/api/blocklist/ \
  -H "Content-Type: application/json" \
  -d '{"domain": "ads.example.com", "reason": "tracker"}'

# Unblock
curl -X DELETE http://localhost:8080/api/blocklist/ads.example.com
```

Blocking works two ways:
1. **DNS sinkhole** — returns NXDOMAIN so the domain never resolves
2. **iptables** — drops outbound packets matching the domain string (best-effort)

---

## Project Structure

```
Pi-Gotcha/
├── main.py                     # Entry point
├── config.py                   # Settings from .env
├── requirements.txt
├── dns_server/
│   └── server.py               # DNS proxy (dnslib)
├── capture/
│   └── sniffer.py              # Packet capture (scapy)
├── database/
│   └── db.py                   # SQLite schema + helpers
├── blocking/
│   └── firewall.py             # Block/unblock logic
├── geoip/
│   └── lookup.py               # MaxMind GeoLite2 lookup
├── api/
│   ├── app.py                  # FastAPI app
│   └── routes/                 # dns, traffic, blocklist, devices, stats
└── dashboard/
    ├── templates/index.html    # Web UI
    └── static/                 # CSS + JS
```

---

## Run as a Service (optional)

To have Pi-Gotcha start automatically on boot:

```bash
sudo nano /etc/systemd/system/pigotcha.service
```

```ini
[Unit]
Description=Pi-Gotcha Network Monitor
After=network.target

[Service]
ExecStart=/home/pi/Pi-Gotcha/.venv/bin/python /home/pi/Pi-Gotcha/main.py
WorkingDirectory=/home/pi/Pi-Gotcha
Restart=always
User=root

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable pigotcha
sudo systemctl start pigotcha
```
