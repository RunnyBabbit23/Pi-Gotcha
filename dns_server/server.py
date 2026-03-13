"""
DNS proxy server — intercepts all queries, logs them, blocks if on blocklist,
and forwards everything else upstream.
"""

import asyncio
import socket
import sqlite3
from datetime import datetime

import dnslib
from dnslib import DNSRecord, RR, QTYPE, A

from config import LISTEN_HOST, DNS_PORT, UPSTREAM_DNS, DB_PATH
from blocking.firewall import is_blocked


def log_query(client_ip: str, domain: str, qtype: str, blocked: bool, response_ip: str = ""):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO dns_queries (client_ip, domain, query_type, blocked, response_ip) VALUES (?,?,?,?,?)",
        (client_ip, domain, qtype, int(blocked), response_ip)
    )
    # Upsert device
    conn.execute(
        """INSERT INTO devices (ip) VALUES (?)
           ON CONFLICT(ip) DO UPDATE SET last_seen=CURRENT_TIMESTAMP""",
        (client_ip,)
    )
    conn.commit()
    conn.close()


def resolve_upstream(data: bytes) -> bytes:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    sock.sendto(data, (UPSTREAM_DNS, 53))
    response, _ = sock.recvfrom(4096)
    sock.close()
    return response


def handle_query(data: bytes, client_addr: tuple) -> bytes:
    client_ip = client_addr[0]

    try:
        request = DNSRecord.parse(data)
    except Exception:
        return data

    domain = str(request.q.qname).rstrip(".")
    qtype  = QTYPE[request.q.qtype]

    if is_blocked(domain):
        # Return NXDOMAIN for blocked domains
        reply = request.reply()
        reply.header.rcode = dnslib.RCODE.NXDOMAIN
        log_query(client_ip, domain, qtype, blocked=True)
        print(f"[BLOCKED]   {client_ip} → {domain}")
        return reply.pack()

    try:
        response_data = resolve_upstream(data)
        response      = DNSRecord.parse(response_data)
        response_ip   = ""
        for rr in response.rr:
            if rr.rtype == QTYPE.A:
                response_ip = str(rr.rdata)
                break
        log_query(client_ip, domain, qtype, blocked=False, response_ip=response_ip)
        print(f"[QUERY]     {client_ip} → {domain} ({response_ip})")
        return response_data
    except Exception as e:
        print(f"[ERROR] DNS resolve failed for {domain}: {e}")
        reply = request.reply()
        reply.header.rcode = dnslib.RCODE.SERVFAIL
        return reply.pack()


class DNSHandler(asyncio.DatagramProtocol):
    def __init__(self):
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        response = handle_query(data, addr)
        self.transport.sendto(response, addr)


def start_dns_server():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    listen = loop.run_until_complete(
        loop.create_datagram_endpoint(
            DNSHandler,
            local_addr=(LISTEN_HOST, DNS_PORT)
        )
    )
    print(f"[DNS] Listening on {LISTEN_HOST}:{DNS_PORT}")
    try:
        loop.run_forever()
    finally:
        listen[0].close()
