"""
Blocking engine — DNS sinkhole + optional iptables rules.
"""

import sqlite3
import subprocess
from config import DB_PATH


def get_blocklist() -> set:
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("SELECT domain FROM blocklist").fetchall()
    conn.close()
    return {row[0].lower() for row in rows}


def is_blocked(domain: str) -> bool:
    domain = domain.lower().rstrip(".")
    conn   = sqlite3.connect(DB_PATH)
    row    = conn.execute(
        "SELECT 1 FROM blocklist WHERE ? LIKE '%' || domain", (domain,)
    ).fetchone()
    conn.close()
    return row is not None


def add_block(domain: str, reason: str = "") -> bool:
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT OR IGNORE INTO blocklist (domain, reason) VALUES (?, ?)",
            (domain.lower(), reason)
        )
        conn.commit()
        conn.close()
        _iptables_drop(domain)
        return True
    except Exception as e:
        print(f"[BLOCK] Error adding {domain}: {e}")
        return False


def remove_block(domain: str) -> bool:
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("DELETE FROM blocklist WHERE domain=?", (domain.lower(),))
        conn.commit()
        conn.close()
        _iptables_accept(domain)
        return True
    except Exception as e:
        print(f"[BLOCK] Error removing {domain}: {e}")
        return False


def _iptables_drop(domain: str):
    """Best-effort iptables block by domain name string match (DNS already blocks it)."""
    try:
        subprocess.run(
            ["iptables", "-I", "OUTPUT", "-m", "string",
             "--string", domain, "--algo", "bm", "-j", "DROP"],
            check=True, capture_output=True
        )
    except Exception:
        pass  # iptables may not be available in dev; DNS block is primary


def _iptables_accept(domain: str):
    try:
        subprocess.run(
            ["iptables", "-D", "OUTPUT", "-m", "string",
             "--string", domain, "--algo", "bm", "-j", "DROP"],
            check=True, capture_output=True
        )
    except Exception:
        pass
