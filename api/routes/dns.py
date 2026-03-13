from fastapi import APIRouter
from database.db import get_db
from geoip.lookup import lookup

router = APIRouter()


@router.get("/queries")
async def recent_queries(limit: int = 100):
    db   = await get_db()
    rows = await db.execute_fetchall(
        "SELECT * FROM dns_queries ORDER BY timestamp DESC LIMIT ?", (limit,)
    )
    await db.close()
    return [dict(r) for r in rows]


@router.get("/top-domains")
async def top_domains(limit: int = 20):
    db   = await get_db()
    rows = await db.execute_fetchall(
        """SELECT domain, COUNT(*) as count, SUM(blocked) as blocked_count
           FROM dns_queries GROUP BY domain ORDER BY count DESC LIMIT ?""",
        (limit,)
    )
    await db.close()
    return [dict(r) for r in rows]


@router.get("/top-clients")
async def top_clients(limit: int = 20):
    db   = await get_db()
    rows = await db.execute_fetchall(
        """SELECT client_ip, COUNT(*) as query_count
           FROM dns_queries GROUP BY client_ip ORDER BY query_count DESC LIMIT ?""",
        (limit,)
    )
    await db.close()
    result = []
    for r in rows:
        d = dict(r)
        d["geo"] = lookup(d["client_ip"])
        result.append(d)
    return result
