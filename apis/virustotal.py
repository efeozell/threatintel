import requests
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import VIRUSTOTAL_API_KEY, VIRUSTOTAL_BASE_URL

def _get_headers():
    return {"x-apikey": VIRUSTOTAL_API_KEY}

def _parse_stats(stats):
    total = sum(stats.values())
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    return {
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "total_engines": total
    }

def query_ip(ip):
    try:
        url = f"{VIRUSTOTAL_BASE_URL}/ip_addresses/{ip}"
        response = requests.get(url, headers=_get_headers(), timeout=10)

        if response.status_code == 404:
            return {"error": "IP not found", "source": "virustotal"}

        if response.status_code == 429:
            return {"error": "API rate has been reached", "source": "virustotal"}

        if response.status_code != 200:
            return {"error": f"API Error: {response.status_code}", "source": "virustotal"}

        data = response.json()["data"]["attributes"]

        stats = _parse_stats(data.get("last_analysis_stats", {}))

        analysis_results = data.get("last_analysis_results", {})
        detections = []
        for engine, result in analysis_results.items():
            category = result.get("category", "")
            if category in ["malicious", "suspicious"]:
                detections.append({
                    "engine": engine,
                    "category": category,
                    "result": result.get("result", "")
                })


        return {
            "source": "virustotal",
            "target_type": "ip",
            "stats": stats,
            "country": data.get("country", "Unknown"),
            "owner": data.get("as_owner", "Unknown"),
            "asn": data.get("asn", "Unknown"),
            "last_analysis_date": data.get("last_analysis_date", "Unknown"),
            "detections": detections,
            "total_engines": len(analysis_results),
            "error": None
        }

    except requests.exceptions.Timeout:
        return {"error": "Connection timeout", "source": "virustotal"}
    except requests.exceptions.ConnectionError:
        return {"error": "Connection error", "source": "virustotal"}
    except Exception as e:
        return {"error": str(e), "source": "virustotal"}

def query_domain(domain):
    try:
        url = f"{VIRUSTOTAL_BASE_URL}/domains/{domain}"
        response = requests.get(url, headers=_get_headers(), timeout=10)

        if response.status_code == 404:
            return {"error": "Domain not found", "source": "virustotal"}

        if response.status_code == 429:
            return {"error": "API Rate has been reached", "source": "virustotal"}

        if response.status_code != 200:
            return {"error": f"API Error: {response.status_code}", "source": "virustotal"}

        data = response.json()["data"]["attributes"]
        stats = _parse_stats(data.get("last_analysis_stats", {}))

        analysis_results = data.get("last_analysis_results", {})
        detections = []
        for engine, result in analysis_results.items():
            category = result.get("category", "")
            if category in ["malicious", "suspicious"]:
                detections.append({
                    "engine": engine,
                    "category": category,
                    "result": result.get("result", "")
                })

        return {
            "source": "virustotal",
            "target_type": "domain",
            "stats": stats,
            "registrar": data.get("registrar", "Unknown"),
            "creation_date": data.get("creation_date", "Unknown"),
            "last_analysis_date": data.get("last_analysis_date", "Unknown"),
            "categories": data.get("categories", {}),
            "detections": detections,
            "total_engines": len(analysis_results),
            "error": None
        }

    except requests.exceptions.Timeout:
        return {"error": "Connection timout", "source": "virustotal"}
    except requests.exceptions.ConnectionError:
        return {"error": "Connection Error", "source": "virustotal"}
    except Exception as e:
        return {"error": str(e), "source": "virustotal"}


def query_hash(file_hash):
    try:
        url = f"{VIRUSTOTAL_BASE_URL}/files/{file_hash}"
        response = requests.get(url, headers=_get_headers(), timeout=10)

        if response.status_code == 404:
            return {"error": "Hash not found — not analysed previously", "source": "virustotal"}

        if response.status_code == 429:
            return {"error": "API Rate has been reached", "source": "virustotal"}

        if response.status_code != 200:
            return {"error": f"API Error: {response.status_code}", "source": "virustotal"}

        data = response.json()["data"]["attributes"]
        stats = _parse_stats(data.get("last_analysis_stats", {}))

        analysis_results = data.get("last_analysis_results", {})
        detections = []
        for engine, result in analysis_results.items():
            category = result.get("category", "")
            if category in ["malicious", "suspicious"]:
                detections.append({
                    "engine": engine,
                    "category": category,
                    "result": result.get("result", "")
                })

        return {
            "source": "virustotal",
            "target_type": "hash",
            "stats": stats,
            "file_name": data.get("meaningful_name", "Unknown"),
            "file_type": data.get("type_description", "Unknown"),
            "file_size": data.get("size", 0),
            "last_analysis_date": data.get("last_analysis_date", "Unknown"),
            "detections": detections,
            "total_engines": len(analysis_results),
            "error": None
        }

    except requests.exceptions.Timeout:
        return {"error": "Connection Timeout", "source": "virustotal"}
    except requests.exceptions.ConnectionError:
        return {"error": "Connection Error", "source": "virustotal"}
    except Exception as e:
        return {"error": str(e), "source": "virustotal"}


def query(target, target_type):
    if target_type == "ip":
        return query_ip(target)
    elif target_type == "domain":
        return query_domain(target)
    elif target_type == "hash":
        return query_hash(target)
    else:
        return {"error": "Invalid target type", "source": "virustotal"}

def get_ip_relations(ip):
    try:
        url = f"{VIRUSTOTAL_BASE_URL}/ip_addresses/{ip}/urls"
        response = requests.get(url, headers=_get_headers(), timeout=10)

        related_urls = []
        if response.status_code == 200:
            data = response.json().get("data", [])
            for item in data[:10]:
                attrs = item.get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                related_urls.append({
                    "url": attrs.get("url", ""),
                    "malicious": stats.get("malicious", 0),
                    "last_analysis": attrs.get("last_analysis_date", "")
                })

        return {"related_urls": related_urls}

    except Exception as e:
        return {"error": str(e), "related_urls": []}

def get_domain_relations(domain):
    try:
        url = f"{VIRUSTOTAL_BASE_URL}/domains/{domain}/resolutions"
        response = requests.get(url, headers=_get_headers(), timeout=10)

        related_ips = []
        if response.status_code == 200:
            data = response.json().get("data", [])
            for item in data[:10]:
                attrs = item.get("attributes", {})
                related_ips.append({
                    "ip": attrs.get("ip_address", ""),
                    "last_resolved": attrs.get("date", "")
                })

        return {"related_ips": related_ips}

    except Exception as e:
        return {"error": str(e), "related_ips": []}