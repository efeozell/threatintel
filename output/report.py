import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
from datetime import datetime

def save_json_report(result):
    reports_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "reports"
    )
    os.makedirs(reports_dir, exist_ok=True)

    target = result["target"].replace(".", "_").replace("/", "_")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"report_{target}_{timestamp}.json"
    filepath = os.path.join(reports_dir, filename)

    report_data = {
        "report_metadata": {
            "generated_at": datetime.now().isoformat(),
            "tool": "Threat Intelligence Tool v1.0",
            "analyst": "SOC Analyst"
        },
        "summary": {
            "target": result["target"],
            "target_type": result["target_type"],
            "final_score": result["final_score"],
            "threat_level": result["threat_level"]["level"],
            "findings": result.get("findings", [])
        },
        "scores": result.get("scores", {}),
        "detailed_results": result.get("raw", {})
    }

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False, default=str)

    return filepath    