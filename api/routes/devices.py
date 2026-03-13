from fastapi import APIRouter
from database.db import get_db
from geoip.lookup import lookup

router = APIRouter()


@router.get("/")
async def get_devices():
    db   = await get_db()
    rows = await db.execute_fetchall(
        "SELECT * FROM devices ORDER BY last_seen DESC"
    )
    await db.close()
    result = []
    for r in rows:
        d = dict(r)
        d["geo"] = lookup(d["ip"])
        result.append(d)
    return result
