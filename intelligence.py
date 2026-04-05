import re
import socket
import requests
from urllib.parse import urlparse

def calculate_threat_score(indicator, is_ip=False):
    score = 50 
    if is_ip:
        score += 35 
        return min(score, 100)

    try:
        parsed_url = urlparse(indicator)
        domain = parsed_url.netloc
        path = parsed_url.path.lower()
        
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$", domain):
            score += 25
        if any(domain.endswith(tld) for tld in ['.xyz', '.top', '.pw', '.cc', '.ru']):
            score += 15
        if any(path.endswith(ext) for ext in ['.exe', '.apk', '.bin', '.sh', '.bat']):
            score += 20
    except Exception:
        pass
    return min(score, 100)

def enrich_indicator(indicator):
    try:
        hostname = urlparse(indicator).netloc or indicator
        ip_addr = socket.gethostbyname(hostname.split(':')[0])
        
        geo_res = requests.get(f"http://ip-api.com/json/{ip_addr}?fields=status,country,city,isp", timeout=5).json()
        
        if geo_res['status'] == 'success':
            return geo_res.get('country', 'Unknown'), geo_res.get('city', 'Unknown'), geo_res.get('isp', 'Unknown')
    except Exception:
        pass
    return 'Unknown', 'Unknown', 'Unknown'