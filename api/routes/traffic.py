from fastapi import APIRouter
from database.db import get_db
from geoip.lookup import lookup

router = APIRouter()


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
