"""
Packet sniffer — captures TCP/UDP traffic visible to the Pi.
On a standard home network this covers the Pi's own traffic plus
broadcasts/ARP/mDNS from other devices.
"""

import sqlite3
from scapy.all import sniff, IP, TCP, UDP

from config import DB_PATH


def log_packet(src_ip, dst_ip, src_port, dst_port, protocol, size):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO traffic (src_ip, dst_ip, src_port, dst_port, protocol, size) VALUES (?,?,?,?,?,?)",
            (src_ip, dst_ip, src_port, dst_port, protocol, size)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[SNIFFER] DB error: {e}")


def process_packet(pkt):
    if not pkt.haslayer(IP):
        return

    ip  = pkt[IP]
    src = ip.src
    dst = ip.dst

    if pkt.haslayer(TCP):
        layer    = pkt[TCP]
        protocol = "TCP"
    elif pkt.haslayer(UDP):
        layer    = pkt[UDP]
        protocol = "UDP"
    else:
        return

    log_packet(src, dst, layer.sport, layer.dport, protocol, len(pkt))


def start_sniffer():
    print("[SNIFFER] Starting packet capture (promiscuous mode)...")
    sniff(prn=process_packet, store=False, filter="ip")
