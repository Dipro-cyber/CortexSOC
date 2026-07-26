"""
Seed synthetic security events into the CortexSOC pipeline.
Usage: python scripts/seed_events.py [--count N] [--url URL] [--token TOKEN]
"""
import argparse
import json
import random
import uuid
import urllib.request

EVENTS = [
    ('{"ts":"2024-01-15T10:30:00Z","src_ip":"192.168.1.50","dst_ip":"10.0.0.1","event_type":"port_scan","severity":"medium"}', "syslog"),
    ('{"ts":"2024-01-15T11:00:00Z","src_ip":"10.10.10.5","event_type":"failed_login","severity":"high","user":"admin"}', "syslog"),
    ("CEF:0|ArcSight|Logger|1.0|100|Brute Force|8|src=172.16.0.100 dst=10.0.0.5 start=2024-01-15T12:00:00Z", "cef"),
    ("CEF:0|Cisco|Firewall|2.0|200|Port Scan Detected|6|src=192.168.100.1 dst=10.0.0.1", "cef"),
    ('10.0.0.99 - - [15/Jan/2024:13:00:00 +0000] "GET /admin HTTP/1.1" 403 512', "apache"),
    ('203.0.113.5 - - [15/Jan/2024:14:00:00 +0000] "POST /api/login HTTP/1.1" 500 0', "apache"),
]

def seed(url: str, token: str, count: int) -> None:
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {token}"}
    for i in range(count):
        raw, source = random.choice(EVENTS)
        body = json.dumps({"source": source, "raw_payload": raw}).encode()
        req = urllib.request.Request(f"{url}/api/v1/events", data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read())
                print(f"[{i+1}/{count}] accepted event_id={data.get('message_id','?')}")
        except Exception as e:
            print(f"[{i+1}/{count}] error: {e}")

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--count", type=int, default=10)
    p.add_argument("--url", default="http://localhost:8000")
    p.add_argument("--token", default="")
    args = p.parse_args()
    seed(args.url, args.token, args.count)
