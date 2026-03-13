"""
IOC checker — heuristic detection and feed-based lookups.
Called synchronously from the DNS server thread.
"""

import math
import sqlite3
from config import DB_PATH

# Shannon entropy threshold — randomized DGA labels typically score > 3.5
_DGA_ENTROPY_THRESHOLD = 3.5
_DGA_MIN_LABEL_LEN = 8

# TLDs with historically high abuse rates
_SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",
    ".pw", ".xyz", ".top", ".click",
    ".loan", ".work", ".date", ".racing",
}


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def check_heuristics(domain: str) -> list:
    """Return a list of alert dicts for any heuristic hits on this domain."""
    alerts = []
    parts = domain.split(".")
    label = parts[0] if parts else ""

    # DGA detection — high entropy in the leftmost label
    if len(label) >= _DGA_MIN_LABEL_LEN:
        ent = _shannon_entropy(label)
        if ent >= _DGA_ENTROPY_THRESHOLD:
            alerts.append({
                "ioc_source": "heuristic:dga",
                "category":   "malware",
                "severity":   "medium",
                "detail":     f"High-entropy label '{label}' (entropy={ent:.2f})",
            })

    # DNS tunneling — very long domain names carry data payloads
    if len(domain) > 100:
        alerts.append({
            "ioc_source": "heuristic:dns_tunnel",
            "category":   "exfiltration",
            "severity":   "high",
            "detail":     f"Unusually long domain ({len(domain)} chars)",
        })

    # Suspicious TLD
    tld = ("." + parts[-1].lower()) if len(parts) > 1 else ""
    if tld in _SUSPICIOUS_TLDS:
        alerts.append({
            "ioc_source": "heuristic:suspicious_tld",
            "category":   "suspicious",
            "severity":   "low",
            "detail":     f"High-abuse TLD: {tld}",
        })

    return alerts


def check_domain_feeds(domain: str) -> list:
    """Check domain against loaded IOC feed indicators."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        # Exact match OR the domain is a subdomain of a feed indicator
        rows = conn.execute(
            """SELECT indicator, source, category, severity
               FROM ioc_feeds
               WHERE type='domain'
                 AND (indicator = ? OR ? LIKE '%.' || indicator)
               LIMIT 5""",
            (domain, domain),
        ).fetchall()
        conn.close()
    except Exception:
        return []

    return [{
        "ioc_source": f"feed:{r['source']}",
        "category":   r["category"],
        "severity":   r["severity"],
        "detail":     f"Matched feed indicator: {r['indicator']}",
    } for r in rows]


def check_ip_feeds(ip: str) -> list:
    """Check an IP against loaded IOC feed indicators."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """SELECT indicator, source, category, severity
               FROM ioc_feeds
               WHERE type='ip' AND indicator = ?
               LIMIT 5""",
            (ip,),
        ).fetchall()
        conn.close()
    except Exception:
        return []

    return [{
        "ioc_source": f"feed:{r['source']}",
        "category":   r["category"],
        "severity":   r["severity"],
        "detail":     f"Matched feed indicator: {r['indicator']}",
    } for r in rows]


def log_alert(client_ip: str, indicator: str, alert: dict, blocked: bool = False):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            """INSERT INTO alerts
                   (client_ip, indicator, ioc_source, category, severity, detail, blocked)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                client_ip,
                indicator,
                alert["ioc_source"],
                alert["category"],
                alert["severity"],
                alert.get("detail", ""),
                int(blocked),
            ),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[IOC] Failed to log alert: {e}")


def scan_domain(client_ip: str, domain: str, blocked: bool = False):
    """Run all checks against a domain and log any hits. Called per DNS query."""
    hits = check_heuristics(domain) + check_domain_feeds(domain)
    for hit in hits:
        print(f"[ALERT] {hit['severity'].upper()} {hit['ioc_source']} — {domain} from {client_ip}")
        log_alert(client_ip, domain, hit, blocked)
