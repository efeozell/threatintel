import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
from config import ABUSEIPDB_API_KEY, ABUSEIPDB_BASE_URL

ABUSE_CATEGORIES = {
    1: "DNS Compromise",
    2: "DNS Poisoning",
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH Brute Force",
    23: "IoT Targeted"
}


def query_ip(ip):
    try:
        url = f"{ABUSEIPDB_BASE_URL}/check"
        headers = {
            "Key": ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": True
        }

        response = requests.get(url, headers=headers, params=params, timeout=10)

        if response.status_code == 422:
            return {"error": "Invalid IP Format", "source": "abuseipdb"}

        if response.status_code == 429:
            return {"error": "API Limit has been reached", "source": "abuseipdb"}

        if response.status_code != 200:
            return {"error": f"API Error: {response.status_code}", "source": "abuseipdb"}

        data = response.json()["data"]

        report_data = data.get("reports", [])
        recent_reports = []
        categories_count = {}

        for repo in report_data[:10]:
            cats = repo.get("categories", [])
            recent_reports.append({
                "reported_at": repo.get("reportedAt", ""),
                "comment": repo.get("comment", "")[:100],  
                "categories": [ABUSE_CATEGORIES.get(c, f"Category {c}") for c in cats],
                "country": repo.get("reporterCountryCode", "")
            })
            for cat in cats:
                categories_count[cat] = categories_count.get(cat, 0) + 1

        return {
            "source": "abuseipdb",
            "target_type": "ip",
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "last_reported": data.get("lastReportedAt", "Hiç raporlanmamış"),
            "country": data.get("countryCode", "Bilinmiyor"),
            "usage_type": data.get("usageType", "Bilinmiyor"),
            "isp": data.get("isp", "Bilinmiyor"),
            "is_tor": data.get("isTor", False),
            "is_whitelisted": data.get("isWhitelisted", False),
            "recent_reports": recent_reports,
            "categories_count": categories_count,
            "error": None
        }

    except requests.exceptions.Timeout:
        return {"error": "Connection timeout", "source": "abuseipdb"}
    except requests.exceptions.ConnectionError:
        return {"error": "Connection error", "source": "abuseipdb"}
    except Exception as e:
        return {"error": str(e), "source": "abuseipdb"}

def query(target, target_type):
    if target_type == "ip":
        return query_ip(target)
    else:
        return {
            "source": "abuseipdb",
            "error": None,
            "skipped": True,
            "reason": f"AbuseIPDB just queries IP - {target_type} not supported"
        }