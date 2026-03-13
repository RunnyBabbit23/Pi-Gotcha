from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.requests import Request

from api.routes import dns, traffic, blocklist, devices, stats, alerts

app = FastAPI(title="Pi-Gotcha")

app.include_router(dns.router,       prefix="/api/dns")
app.include_router(traffic.router,   prefix="/api/traffic")
app.include_router(blocklist.router, prefix="/api/blocklist")
app.include_router(devices.router,   prefix="/api/devices")
app.include_router(stats.router,     prefix="/api/stats")
app.include_router(alerts.router,    prefix="/api/alerts")

app.mount("/static", StaticFiles(directory="dashboard/static"), name="static")
templates = Jinja2Templates(directory="dashboard/templates")


@app.get("/")
async def dashboard(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})
