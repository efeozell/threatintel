import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, render_template, request, jsonify
from core.validator import validate_target
from core.query_manager import run_queries

def create_app():
    app = Flask(__name__)

    @app.route("/")
    def index():
        return render_template("dashboard.html")


    @app.route("/api/analyze", methods=["POST"])
    def analyze():
        try:
            body = request.get_json()

            if not body or "target" not in body:
                return jsonify({
                    "success": False,
                    "error": "target alanı gerekli"
                }), 400

            target = body["target"].strip()

            validation = validate_target(target)
            if not validation["valid"]:
                return jsonify({
                    "success": False,
                    "error": validation["error"]
                }), 400

            cleaned_target = validation["target"]
            target_type = validation["type"]

            result = run_queries(cleaned_target, target_type)

            response_data = {
                "target": result["target"],
                "target_type": result["target_type"],
                "final_score": result["final_score"],
                "threat_level": result["threat_level"],
                "scores": result["scores"],
                "findings": result.get("findings", []),
                "raw": {
                    "virustotal": result["raw"].get("virustotal"),
                    "abuseipdb": result["raw"].get("abuseipdb"),
                    "shodan": result["raw"].get("shodan")
                }
            }

            return jsonify({
                "success": True,
                "data": response_data
            })

        except Exception as e:
            return jsonify({
                "success": False,
                "error": str(e)
            }), 500


    @app.route("/api/health")
    def health():
        return jsonify({
            "status": "ok",
            "tool": "Threat Intelligence Tool v1.0"
        })

    @app.route("/api/vt-details", methods=["POST"])
    def vt_details():
        try:
            body = request.get_json()
            target = body.get("target", "").strip()
            target_type = body.get("target_type", "").strip()

            from apis.virustotal import get_ip_relations, get_domain_relations

            relations = {}
            if target_type == "ip":
                relations = get_ip_relations(target)
            elif target_type == "domain":
                relations = get_domain_relations(target)
            else:
                relations = {"note": "Relations only available for IP and Domain"}

            return jsonify({
                "success": True,
                "relations": relations
            })

        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500
        

    return app





if __name__ == "__main__":
    app = create_app()
    app.run(host="127.0.0.1", port=5000, debug=True)

