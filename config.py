import os
from dotenv import load_dotenv

load_dotenv()

UPSTREAM_DNS   = os.getenv("UPSTREAM_DNS", "8.8.8.8")
LISTEN_HOST    = os.getenv("LISTEN_HOST", "0.0.0.0")
DNS_PORT       = int(os.getenv("DNS_PORT", 53))
API_PORT       = int(os.getenv("API_PORT", 8080))
GEOIP_DB_PATH  = os.getenv("GEOIP_DB_PATH", "./geoip/GeoLite2-City.mmdb")
DB_PATH        = os.getenv("DB_PATH", "./pigotcha.db")
