from fastapi import APIRouter
from database.db import get_db

router = APIRouter()


@router.get("/")
async def get_alerts(limit: int = 100):
    db = await get_db()
    rows = await db.execute_fetchall(
        "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
    )
    await db.close()
    return [dict(r) for r in rows]


@router.delete("/")
async def dismiss_all_alerts():
    db = await get_db()
    await db.execute("DELETE FROM alerts")
    await db.commit()
    await db.close()
    return {"status": "cleared"}


@router.delete("/{alert_id}")
async def dismiss_alert(alert_id: int):
    db = await get_db()
    await db.execute("DELETE FROM alerts WHERE id=?", (alert_id,))
    await db.commit()
    await db.close()
    return {"status": "dismissed"}
