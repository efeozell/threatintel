from dotenv import load_dotenv
import os

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTORAL_API")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"
ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"
SHODAN_BASE_URL = "https://api.shodan.io"

WEB_HOST = "127.0.0.1"
WEB_PORT = 5000
DEBUG = False

SCORE_CLEAN = 30
SCORE_SUSPICIOUS = 60
SCORE_HIGH_RISK = 80

CRITICAL_PORTS = [21, 22, 23, 25, 445, 1433, 3306, 3389, 5900]

def validate_config():
    missing = []
    if not VIRUSTOTAL_API_KEY:
        missing.append("VIRUSTOTAL_API_KEY")
    if not ABUSEIPDB_API_KEY:
        missing.append("ABUSEIPDB_API_KEY")
    if not SHODAN_API_KEY:
        missing.append("SHODAN_API_KEY")
    if missing:
        raise ValueError(f"Missing API Keys: {', '.join(missing)}")
