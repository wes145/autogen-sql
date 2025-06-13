import json, os, atexit, gzip, base64
from typing import Any, Dict

STATE_FILE = "pentest_state.json.gz"

def _compress(data: str) -> str:
    return base64.b64encode(gzip.compress(data.encode("utf-8"))).decode()

def _decompress(data: str) -> str:
    return gzip.decompress(base64.b64decode(data.encode())).decode()

def save_state(state_dict: Dict[str, Any]) -> None:
    try:
        serialized = json.dumps(state_dict)
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            f.write(_compress(serialized))
    except Exception:
        pass

def load_state() -> Dict[str, Any]:
    if not os.path.exists(STATE_FILE):
        return {}
    try:
        raw = open(STATE_FILE, "r", encoding="utf-8").read()
        return json.loads(_decompress(raw))
    except Exception:
        return {}

# atexit helper placeholder – caller must register 