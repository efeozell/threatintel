import re
import ipaddress

INPUT_TYPE_IP = "ip"
INPUT_TYPE_DOMAIN = "domain"
INPUT_TYPE_HASH = "hash"
INPUT_TYPE_UNKNOWN = "unknown"

def detect_input_type(target):
    """
    Detects the type of the user’s input.
    """
    target = target.strip().lower()

    if target.startswith("http://") or target.startswith("https://"):
        target = target.split("//")[1].split("/")[0]

    if is_valid_ip(target):
        return INPUT_TYPE_IP, target

    if is_valid_hash(target):
        return INPUT_TYPE_HASH, target

    if is_valid_domain(target):
        return INPUT_TYPE_DOMAIN, target

    return INPUT_TYPE_UNKNOWN, target

def is_valid_ip(target):
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False

def is_private_ip(target):
    try:
        ip = ipaddress.ip_address(target)
        return ip.is_private or ip.is_loopback or ip.is_reserved
    except ValueError:
        return False

def is_valid_hash(target):
    hash_patterns = {
        32: "md5",
        40: "sha1",
        64: "sha256"
    }
    if len(target) in hash_patterns:
        if re.match(r'^[a-f0-9]+$', target):
            return True
    return False

def get_hash_type(target):
    hash_types = {32: "md5", 40: "sha1", 64: "sha256"}
    return hash_types.get(len(target), "unknown")

def is_valid_domain(target):
    pattern = r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$'
    return bool(re.match(pattern, target))

def validate_target(target):
    if not target or not target.strip():
        return {
            "valid": False,
            "type": INPUT_TYPE_UNKNOWN,
            "target": "",
            "error": "An empty input cannot be entered",
            "warning": None
        }
    input_type, cleaned_target = detect_input_type(target)

    if input_type == INPUT_TYPE_UNKNOWN:
        return {
            "valid": False,
            "type": INPUT_TYPE_UNKNOWN,
            "target": cleaned_target,
            "error": f"Invalid Format: {target}. Enter the IP, domain or hash",
            "warning": None
        }

    warning = None
    if input_type == INPUT_TYPE_IP and is_private_ip(cleaned_target):
        return {
            "valid": False,
            "type": INPUT_TYPE_IP,
            "target": cleaned_target,
            "error": f"{cleaned_target} private/loopback IP",
            "warning": None
        }
    extra_info = None
    if input_type == INPUT_TYPE_HASH:
        extra_info = get_hash_type(cleaned_target)

    return {
        "valid": True,
        "type": input_type,
        "target": cleaned_target,
        "error": None,
        "warning": warning,
        "extra": extra_info
    }
