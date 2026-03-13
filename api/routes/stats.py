from fastapi import APIRouter
from database.db import get_db

router = APIRouter()


@router.get("/")
async def get_stats():
    db = await get_db()

    total_queries = (await db.execute_fetchall(
        "SELECT COUNT(*) as c FROM dns_queries"
    ))[0]["c"]

    blocked_queries = (await db.execute_fetchall(
        "SELECT COUNT(*) as c FROM dns_queries WHERE blocked=1"
    ))[0]["c"]

    total_traffic = (await db.execute_fetchall(
        "SELECT COUNT(*) as c FROM traffic"
    ))[0]["c"]

    total_devices = (await db.execute_fetchall(
        "SELECT COUNT(*) as c FROM devices"
    ))[0]["c"]

    blocklist_size = (await db.execute_fetchall(
        "SELECT COUNT(*) as c FROM blocklist"
    ))[0]["c"]

    await db.close()

    block_pct = round((blocked_queries / total_queries * 100), 1) if total_queries else 0

    return {
        "total_queries":   total_queries,
        "blocked_queries": blocked_queries,
        "block_percent":   block_pct,
        "total_traffic":   total_traffic,
        "total_devices":   total_devices,
        "blocklist_size":  blocklist_size,
    }
