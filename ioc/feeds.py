"""
IOC feed downloader.
Fetches threat intel from free public sources, parses them, and loads
indicators into the ioc_feeds table. Runs at startup and every 6 hours.
"""

import csv
import io
import json
import sqlite3
import time
import urllib.request

from config import DB_PATH

FEEDS = [
    {
        "name":    "threatfox_domains",
        "url":     "https://threatfox.abuse.ch/export/json/domains/recent/",
        "parser":  "threatfox_json",
        "source":  "threatfox",
        "type":    "domain",
    },
    {
        "name":    "threatfox_ips",
        "url":     "https://threatfox.abuse.ch/export/json/ip-port/recent/",
        "parser":  "threatfox_json",
        "source":  "threatfox",
        "type":    "ip",
    },
    {
        "name":    "urlhaus_domains",
        "url":     "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "parser":  "urlhaus_csv",
        "source":  "urlhaus",
        "type":    "domain",
    },
]


def _parse_threatfox_json(data: bytes, source: str, ioc_type: str) -> list:
    try:
        obj = json.loads(data)
        rows = []
        for entry in obj.get("data", []):
            raw = entry.get("ioc_value", "").strip()
            if not raw:
                continue
            # IP:port entries — strip the port
            indicator = raw.split(":")[0] if ioc_type == "ip" else raw
            category = entry.get("threat_type", "malware")
            rows.append((indicator, ioc_type, source, category, "high"))
        return rows
    except Exception as e:
        print(f"[IOC] threatfox parse error: {e}")
        return []


def _parse_urlhaus_csv(data: bytes, source: str, ioc_type: str) -> list:
    """URLhaus CSV columns: id, dateadded, url, url_status, threat, tags, ..."""
    rows = []
    try:
        text = data.decode("utf-8", errors="ignore")
        reader = csv.reader(io.StringIO(text))
        for line in reader:
            if not line or line[0].startswith("#"):
                continue
            if len(line) < 3:
                continue
            url = line[2].strip()
            if "://" in url:
                host = url.split("://", 1)[1].split("/")[0].split(":")[0].lower()
                if host:
                    rows.append((host, "domain", source, "malware", "high"))
    except Exception as e:
        print(f"[IOC] urlhaus parse error: {e}")
    return rows


def fetch_and_load(feed: dict) -> int:
    try:
        req = urllib.request.Request(
            feed["url"],
            headers={"User-Agent": "Pi-Gotcha-IOC/1.0"},
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = resp.read()
    except Exception as e:
        print(f"[IOC] Failed to fetch {feed['name']}: {e}")
        return 0

    if feed["parser"] == "threatfox_json":
        rows = _parse_threatfox_json(data, feed["source"], feed["type"])
    elif feed["parser"] == "urlhaus_csv":
        rows = _parse_urlhaus_csv(data, feed["source"], feed["type"])
    else:
        return 0

    if not rows:
        return 0

    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "DELETE FROM ioc_feeds WHERE source=? AND type=?",
            (feed["source"], feed["type"]),
        )
        conn.executemany(
            """INSERT OR IGNORE INTO ioc_feeds (indicator, type, source, category, severity)
               VALUES (?, ?, ?, ?, ?)""",
            rows,
        )
        conn.commit()
        count = conn.execute(
            "SELECT COUNT(*) FROM ioc_feeds WHERE source=? AND type=?",
            (feed["source"], feed["type"]),
        ).fetchone()[0]
        conn.close()
    except Exception as e:
        print(f"[IOC] DB error loading {feed['name']}: {e}")
        return 0

    print(f"[IOC] {feed['name']}: {count} indicators loaded")
    return count


def update_all_feeds():
    total = sum(fetch_and_load(f) for f in FEEDS)
    print(f"[IOC] Feed update complete — {total} total indicators")


def start_feed_updater():
    """Blocking loop — run in a daemon thread. Updates at startup then every 6h."""
    while True:
        update_all_feeds()
        time.sleep(6 * 3600)
