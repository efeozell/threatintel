import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from concurrent.futures import ThreadPoolExecutor, as_completed
from apis import virustotal, abuseipdb, shodan_api
from core.aggregator import aggregate

def run_queries(target, target_type):
    results = {
        "virustotal": None,
        "abuseipdb": None,
        "shodan": None
    }

    tasks = {
        "virustotal": lambda: virustotal.query(target, target_type),
        "abuseipdb": lambda: abuseipdb.query(target, target_type),
        "shodan": lambda: shodan_api.query(target, target_type)
    }
    with ThreadPoolExecutor(max_workers=3) as executor:
        future_to_api = {
            executor.submit(func): api_name
            for api_name, func in tasks.items()
        }

        for future in as_completed(future_to_api):
            api_name = future_to_api[future]
            try:
                results[api_name] = future.result()
            except Exception as e:
                results[api_name] = {
                    "error": str(e),
                    "source": api_name
                }

    final_result = aggregate(
        target=target,
        target_type=target_type,
        vt_result=results["virustotal"],
        abuse_result=results["abuseipdb"],
        shodan_result=results["shodan"]
    )

    return final_result