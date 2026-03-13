"""
GeoIP lookup using MaxMind GeoLite2.
Download the free DB from: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
Place GeoLite2-City.mmdb in the geoip/ directory.
"""

import geoip2.database
import geoip2.errors
from config import GEOIP_DB_PATH

_reader = None


def _get_reader():
    global _reader
    if _reader is None:
        try:
            _reader = geoip2.database.Reader(GEOIP_DB_PATH)
        except FileNotFoundError:
            pass
    return _reader


def lookup(ip: str) -> dict:
    reader = _get_reader()
    if reader is None:
        return {}
    try:
        record = reader.city(ip)
        return {
            "country":   record.country.name,
            "country_code": record.country.iso_code,
            "city":      record.city.name,
            "latitude":  record.location.latitude,
            "longitude": record.location.longitude,
        }
    except (geoip2.errors.AddressNotFoundError, Exception):
        return {}
