import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
from config import SHODAN_API_KEY, SHODAN_BASE_URL, CRITICAL_PORTS

def query_ip(ip):
    try:
        url = f"{SHODAN_BASE_URL}/shodan/host/{ip}"
        params = {"key": SHODAN_API_KEY}

        response = requests.get(url, params=params, timeout=10)

        if response.status_code == 404:
            return {
                "source": "shodan",
                "target_type": "ip",
                "found": False,
                "error": None,
                "reason": "Bu IP Shodan'da kayıtlı değil"
            }

        if response.status_code == 401:
            return {"error": "Invalid API key", "source": "shodan"}

        if response.status_code == 429:
            return {"error": "API rate limit has been reached", "source": "shodan"}

        if response.status_code == 403:
            return {"source": "shodan", "error": None, "skipped": True, "reason": "Shodan free plan"}

        if response.status_code != 200:
            return {"error": f"API Error: {response.status_code}", "source": "shodan"}

        

        data = response.json()

        open_ports = data.get("ports", [])

        found_critical_ports = [p for p in open_ports if p in CRITICAL_PORTS]

        vulns_raw = data.get("vulns", {})
        vulns = list(vulns_raw.keys()) if isinstance(vulns_raw, dict) else list(vulns_raw)

        services = []
        for item in data.get("data", []):
            service = {
                "port": item.get("port"),
                "transport": item.get("transport", "tcp"),
                "product": item.get("product", ""),
                "version": item.get("version", ""),
            }
            services.append(service)

        # Tüm servis detayları
        all_services = []
        for item in data.get("data", []):
            all_services.append({
                "port": item.get("port"),
                "transport": item.get("transport", "tcp"),
                "product": item.get("product", ""),
                "version": item.get("version", ""),
                "banner": item.get("data", "")[:200]
            })

        return {
            "source": "shodan",
            "target_type": "ip",
            "found": True,
            "country": data.get("country_name", "Unknown"),
            "country_code": data.get("country_code", ""),
            "city": data.get("city", "Unknown"),
            "org": data.get("org", "Unknown"),
            "isp": data.get("isp", "Unknown"),
            "os": data.get("os", "Unknown"),
            "open_ports": open_ports,
            "critical_ports": found_critical_ports,
            "services": services[:5],
            "all_services": all_services,
            "vulns": vulns,
            "last_update": data.get("last_update", "Unknown"),
            "error": None
        }

    except requests.exceptions.Timeout:
        return {"error": "Connection timeout", "source": "shodan"}
    except requests.exceptions.ConnectionError:
        return {"error": "Connection Error", "source": "shodan"}
    except Exception as e:
        return {"error": str(e), "source": "shodan"}

def query(target, target_type):
    if target_type == "ip":
        return query_ip(target)
    else:
        return {
            "source": "shodan",
            "error": None,
            "skipped": True,
            "reason": f"Shodan queries just IP - {target_type} is not supported"
        }


if __name__ == "__main__":
    import json

    print("=== IP Testi — Cloudflare ===")
    result = query_ip("1.1.1.1")
    print(json.dumps(result, indent=2))
