"""
Pi-Gotcha — Network Monitor
Entry point: starts DNS server, packet sniffer, and web dashboard concurrently.
Run with: sudo python main.py  (root required for DNS port 53 and raw packet capture)
"""

import asyncio
import threading
import uvicorn

from database.db import init_db
from dns_server.server import start_dns_server
from capture.sniffer import start_sniffer
from ioc.feeds import start_feed_updater
from api.app import app
from config import API_PORT


def run_api():
    uvicorn.run(app, host="0.0.0.0", port=API_PORT, log_level="warning")


async def main():
    await init_db()

    # DNS server in a background thread (blocking UDP server)
    dns_thread = threading.Thread(target=start_dns_server, daemon=True)
    dns_thread.start()

    # Packet sniffer in a background thread
    sniff_thread = threading.Thread(target=start_sniffer, daemon=True)
    sniff_thread.start()

    # IOC feed updater in a background thread
    ioc_thread = threading.Thread(target=start_feed_updater, daemon=True)
    ioc_thread.start()

    # FastAPI in a background thread
    api_thread = threading.Thread(target=run_api, daemon=True)
    api_thread.start()

    print("Pi-Gotcha is running.")
    print(f"  Dashboard : http://localhost:{API_PORT}")
    print(f"  DNS       : port 53")
    print("  Press Ctrl+C to stop.\n")

    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping Pi-Gotcha.")


if __name__ == "__main__":
    asyncio.run(main())
