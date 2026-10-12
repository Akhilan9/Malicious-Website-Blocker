import json
import os
from config import BASE_DIR

STATS_FILE = os.path.join(BASE_DIR, "stats.json")

def load_stats():
    if os.path.exists(STATS_FILE):
        with open(STATS_FILE, "r") as f:
            return json.load(f)
    return {
        "total_scans": 0,
        "malicious_detected": 0,
        "safe_detected": 0,
        "total_blocks": 0
    }

def save_stats(stats):
    with open(STATS_FILE, "w") as f:
        json.dump(stats, f)

def record_scan(is_malicious):
    stats = load_stats()
    stats["total_scans"] += 1
    if is_malicious:
        stats["malicious_detected"] += 1
    else:
        stats["safe_detected"] += 1
    save_stats(stats)

def record_block(count=1):
    stats = load_stats()
    stats["total_blocks"] += count
    save_stats(stats)
