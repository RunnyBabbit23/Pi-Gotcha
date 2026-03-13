from fastapi import APIRouter
from database.db import get_db
from geoip.lookup import lookup

router = APIRouter()

# Ports considered normal everyday traffic — anything else is worth surfacing
STANDARD_PORTS = (
    20, 21, 22, 25, 53, 80, 110, 123, 143, 443,
    465, 587, 993, 995, 3389, 5353, 8080, 8443,
)


@router.get("/recent")
async def recent_traffic(limit: int = 200):
    db   = await get_db()
    rows = await db.execute_fetchall(
        "SELECT * FROM traffic ORDER BY timestamp DESC LIMIT ?", (limit,)
    )
    await db.close()
    result = []
    for r in rows:
        d = dict(r)
        d["geo"] = lookup(d["dst_ip"])
        result.append(d)
    return result


@router.get("/top-destinations")
async def top_destinations(limit: int = 20):
    db   = await get_db()
    rows = await db.execute_fetchall(
        """SELECT dst_ip, dst_port, protocol, COUNT(*) as connections, SUM(size) as total_bytes
           FROM traffic GROUP BY dst_ip, dst_port ORDER BY connections DESC LIMIT ?""",
        (limit,)
    )
    await db.close()
    result = []
    for r in rows:
        d = dict(r)
        d["geo"] = lookup(d["dst_ip"])
        result.append(d)
    return result


@router.get("/nonstandard-ports")
async def nonstandard_ports(limit: int = 50):
    placeholders = ",".join("?" * len(STANDARD_PORTS))
    db   = await get_db()
    rows = await db.execute_fetchall(
        f"""SELECT dst_ip, dst_port, protocol,
                   COUNT(*) as connections,
                   SUM(size) as total_bytes,
                   MAX(timestamp) as last_seen
            FROM traffic
            WHERE dst_port NOT IN ({placeholders})
            GROUP BY dst_ip, dst_port, protocol
            ORDER BY connections DESC
            LIMIT ?""",
        (*STANDARD_PORTS, limit),
    )
    await db.close()
    result = []
    for r in rows:
        d = dict(r)
        d["geo"] = lookup(d["dst_ip"])
        result.append(d)
    return result
