import aiosqlite
from config import DB_PATH

CREATE_TABLES = """
CREATE TABLE IF NOT EXISTS dns_queries (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP,
    client_ip   TEXT,
    domain      TEXT,
    query_type  TEXT,
    blocked     INTEGER DEFAULT 0,
    response_ip TEXT
);

CREATE TABLE IF NOT EXISTS traffic (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    src_ip    TEXT,
    dst_ip    TEXT,
    src_port  INTEGER,
    dst_port  INTEGER,
    protocol  TEXT,
    size      INTEGER
);

CREATE TABLE IF NOT EXISTS blocklist (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    domain    TEXT UNIQUE,
    reason    TEXT,
    added_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS devices (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ip         TEXT UNIQUE,
    mac        TEXT,
    hostname   TEXT,
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen  DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ioc_feeds (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    indicator TEXT,
    type      TEXT,
    source    TEXT,
    category  TEXT,
    severity  TEXT,
    UNIQUE(indicator, source)
);

CREATE TABLE IF NOT EXISTS alerts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp  DATETIME DEFAULT CURRENT_TIMESTAMP,
    client_ip  TEXT,
    indicator  TEXT,
    ioc_source TEXT,
    category   TEXT,
    severity   TEXT,
    detail     TEXT,
    blocked    INTEGER DEFAULT 0
);
"""


async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript(CREATE_TABLES)
        await db.commit()


async def get_db() -> aiosqlite.Connection:
    db = await aiosqlite.connect(DB_PATH)
    db.row_factory = aiosqlite.Row
    return db
