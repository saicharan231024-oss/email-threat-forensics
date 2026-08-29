"""
geolocation.py
----------------
IP geolocation. Tries a live lookup (ip-api.com, free/no-key) when
network access is available; otherwise falls back to the small static
table used by sample_generator.py so demo mode always has coordinates
to plot, even fully offline.
"""

try:
    import requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False

_FALLBACK_TABLE = {
    "185.220.101.45": ("Groß Kreutz", "Brandenburg", "DE", 52.4028, 12.7794, "AS60729 Stiftung Erneuerbare Freiheit"),
    "45.132.192.14": ("Amsterdam", "North Holland", "NL", 52.3676, 4.9041, "Unknown ISP"),
    "103.101.222.9": ("Hanoi", "Hanoi", "VN", 21.0278, 105.8342, "Unknown ISP"),
    "194.61.24.83": ("Bucharest", "Bucharest", "RO", 44.4268, 26.1025, "Unknown ISP"),
    "5.188.62.14": ("Moscow", "Moscow", "RU", 55.7558, 37.6173, "Unknown ISP"),
    "91.219.237.244": ("Kyiv", "Kyiv City", "UA", 50.4501, 30.5234, "Unknown ISP"),
    "40.101.32.10": ("Redmond", "Washington", "US", 47.6740, -122.1215, "Microsoft Corp"),
    "104.244.42.1": ("San Francisco", "California", "US", 37.7749, -122.4194, "Twitter Inc"),
    "13.107.42.14": ("Dublin", "Leinster", "IE", 53.3498, -6.2603, "Microsoft Corp"),
    "142.250.72.14": ("Mountain View", "California", "US", 37.3861, -122.0839, "Google LLC"),
}


def geolocate_ip(ip: str):
    if not ip:
        return None

    if _REQUESTS_AVAILABLE:
        try:
            resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
            data = resp.json()
            if data.get("status") == "success":
                return {
                    "ip": ip,
                    "city": data.get("city"),
                    "region": data.get("regionName"),
                    "country": data.get("countryCode"),
                    "lat": data.get("lat"),
                    "lon": data.get("lon"),
                    "isp_org": data.get("org") or data.get("isp"),
                    "source": "live (ip-api.com)",
                }
        except Exception:
            pass

    if ip in _FALLBACK_TABLE:
        city, region, country, lat, lon, org = _FALLBACK_TABLE[ip]
        return {
            "ip": ip, "city": city, "region": region, "country": country,
            "lat": lat, "lon": lon, "isp_org": org, "source": "offline fallback table",
        }

    return {
        "ip": ip, "city": "Unknown", "region": "Unknown", "country": "XX",
        "lat": 0.0, "lon": 0.0, "isp_org": "Unknown", "source": "no data available",
    }
