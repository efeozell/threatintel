import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import SCORE_CLEAN, SCORE_SUSPICIOUS, SCORE_HIGH_RISK

def calculate_virustotal_score(vt_result):
    if not vt_result or vt_result.get("error") or vt_result.get("skipped"):
        return 0

    stats = vt_result.get("stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    if malicious == 0 and suspicious == 0:
        return 0
    elif malicious <= 3:
        return 30
    elif malicious <= 10:
        return 60
    elif malicious <= 20:
        return 80
    else:
        return 100

def calculate_abuseipdb_score(abuse_result):
    if not abuse_result or abuse_result.get("error") or abuse_result.get("skipped"):
        return 0

    abuse_score = abuse_result.get("abuse_score", 0)
    is_tor = abuse_result.get("is_tor", False)

    score = 0

    if abuse_score >= 75:
        score = 100
    elif abuse_score >= 50:
        score = 70
    elif abuse_score >= 25:
        score = 40
    else:
        score = 0

    if is_tor:
        score = min(score + 20, 100)

    return score

def calculate_shodan_score(shodan_result):
    if not shodan_result or shodan_result.get("error") or shodan_result.get("skipped"):
        return 0

    if not shodan_result.get("found", False):
        return 0

    score = 0

    vulns = shodan_result.get("vulns", [])
    if len(vulns) > 0:
        score += min(len(vulns) * 15, 60)

    critical_ports = shodan_result.get("critical_ports", [])
    if len(critical_ports) > 0:
        score += min(len(critical_ports) * 10, 40)

    return min(score, 100)

def get_threat_level(score):
    if score <= SCORE_CLEAN:
        return {
            "level": "CLEAR",
            "emoji": "🟢",
            "color": "green"
        }
    elif score <= SCORE_SUSPICIOUS:
        return {
            "level": "SUSPECT",
            "emoji": "🟡",
            "color": "yellow"
        }
    elif score <= SCORE_HIGH_RISK:
        return {
            "level": "HIGH RISK",
            "emoji": "🟠",
            "color": "orange"
        }
    else:
        return {
            "level": "DANGEROUS",
            "emoji": "🔴",
            "color": "red"
        }

def extract_key_findings(vt_result, abuse_result, shodan_results):
    findings = []

    if vt_result and not vt_result.get("error") and not vt_result.get("skipped"):
        stats = vt_result.get("stats", {})
        malicious = stats.get("malicious", 0)
        if malicious > 0:
            findings.append(f"VirusTotal: {malicious} The engine flagged it as malicious")
        country = vt_result.get("country")
        if country and country != "Unknown":
            findings.append(f"VirusTotal: Source Country - {country}")

    if abuse_result and not abuse_result.get("error") and not abuse_result.get("skipped"):
        abuse_score = abuse_result.get("abuse_score", 0)
        total_reports = abuse_result.get("total_reports", 0)
        if abuse_score > 0:
            findings.append(f"AbuseIPDB: Misuse score {abuse_score}/100")
        if total_reports > 0:
            findings.append(f"AbuseIPDB: Reported {total_reports} times")
        if abuse_result.get("is_tor"):
            findings.append("AbuseIPDB: A Tor exit node has been identified")

    if shodan_results and not shodan_results.get("error") and not shodan_results.get("skipped"):
        if shodan_results.get("found"):
            vulns = shodan_results.get("vulns", [])
            if vulns:
                findings.append(f"Shodan: {len(vulns)} CVE detected - {', '.join(vulns[:3])}")
            critical_ports = shodan_results.get("critical_ports", [])
            if critical_ports:
                findings.append(f"Shodan: Critical Ports open - {critical_ports}")
            org = shodan_results.get("org", "")
            if org and org != "Unknown":
                findings.append(f"Shodan: Organisation")

        if not findings:
            findings.append("No signs of a threat were detected")

        return findings

def aggregate(target, target_type, vt_result, abuse_result, shodan_result):
    vt_score = calculate_virustotal_score(vt_result)
    abuse_score = calculate_abuseipdb_score(abuse_result)
    shodan_score = calculate_shodan_score(shodan_result)

    if target_type == "ip":
        final_score = int((vt_score * 0.4) + (abuse_score * 0.4) + (shodan_score * 0.2))
    elif target_type == "domain":
        final_score = int(vt_score * 1.0)
    elif target_type == "hash":
        final_score = int(vt_score * 1.0)

    threat_level = get_threat_level(final_score)
    findings = extract_key_findings(vt_result, abuse_result, shodan_result)

    return {
        "target": target,
        "target_type": target_type,
        "final_score": final_score,
        "threat_level": threat_level,
        "scores": {
            "virustotal": vt_score,
            "abuseipdb": abuse_score,
            "shodan": shodan_score
        },
        "findings": findings,
        "raw": {
            "virustotal": vt_result,
            "abuseipdb": abuse_result,
            "shodan": shodan_result
        }
    }


