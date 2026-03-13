from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from database.db import get_db
from blocking.firewall import add_block, remove_block

router = APIRouter()


class BlockRequest(BaseModel):
    domain: str
    reason: str = ""


@router.get("/")
async def get_blocklist():
    db   = await get_db()
    rows = await db.execute_fetchall(
        "SELECT * FROM blocklist ORDER BY added_at DESC"
    )
    await db.close()
    return [dict(r) for r in rows]


@router.post("/")
async def block_domain(req: BlockRequest):
    success = add_block(req.domain, req.reason)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to add block")
    return {"blocked": req.domain}


@router.delete("/{domain}")
async def unblock_domain(domain: str):
    success = remove_block(domain)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to remove block")
    return {"unblocked": domain}
