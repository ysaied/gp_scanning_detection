import socket
import json
import threading
import time
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
import requests
import xmltodict
from collections import defaultdict, deque
from http.server import HTTPServer, SimpleHTTPRequestHandler
import os

# Configuration
UDP_IP = "0.0.0.0"
UDP_PORT = 1514  # SYSLOG LISTNER PORT HERE
EDL_PORT = 8888  # HTTP SERVER PORT HERE
LOG_FILE = "gp_scanning_detection_log.jsonl"
USER_FILE = "gp_scanning_detection_users.json"
GRAY_LIST_FILE = "gp_edl_gray.txt"
BLOCK_LIST_FILE = "gp_edl_black.txt"
DUBAI_TZ = ZoneInfo("Asia/Dubai")  # TIME ZONE HERE
RUN_INTERVAL_MINUTES = 10
LOOKBACK_MINUTES = 1440 + RUN_INTERVAL_MINUTES  # 24h + buffer
FIREWALL_IP = "FIREWALL-IP-ADDRESS-HERE"
API_KEY = "FIREWALL-API-KEY-HERE"
XPATH = "/config/shared/local-user-database/user-group/entry[@name='LOCAL-DB-NAME-HERE']"

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

def log_timestamp():
    return datetime.now(DUBAI_TZ).strftime("%Y-%m-%d %H:%M:%S")

def panos_config_show(fw_ip, fw_key, xpath):
    api_url = f"https://{fw_ip}/api"
    params = {
        "key": fw_key,
        "type": "config",
        "action": "show",
        "xpath": xpath
    }
    response = requests.get(api_url, params=params, verify=False, timeout=5)
    result = xmltodict.parse(response.text)["response"]
    return result

def gp_localdb():
    try:
        print(f"{log_timestamp()} 🔄 [GP LocalDB] Fetching users from firewall...")
        api_call = panos_config_show(FIREWALL_IP, API_KEY, XPATH)
        gp_users = api_call['result']['entry']['user']['member']
        with open(USER_FILE, "w") as f:
            json.dump(gp_users, f, indent=4)
        print(f"{log_timestamp()} ✅ [GP LocalDB] Saved {len(gp_users)} users to {USER_FILE}")
    except Exception as e:
        print(f"{log_timestamp()} ❌ [GP LocalDB] Error: {e}")

def gp_localdb_scheduler():
    while True:
        gp_localdb()
        time.sleep(3600)  # 1 hour

def load_users(path):
    try:
        with open(path, "r") as f:
            return set(json.load(f))
    except:
        return set()

def parse_log_file():
    now = datetime.now(DUBAI_TZ)
    entries = []
    try:
        with open(LOG_FILE, "r") as f:
            for line in reversed(f.readlines()):
                try:
                    entry = json.loads(line)
                    if all(k in entry for k in ("ip_address", "username", "timestamp")):
                        ts = datetime.fromisoformat(entry["timestamp"])
                        if now - ts <= timedelta(minutes=LOOKBACK_MINUTES):
                            entry["timestamp_dt"] = ts
                            entries.append(entry)
                        else:
                            break
                except:
                    continue
    except FileNotFoundError:
        pass
    return list(reversed(entries))

def write_edl(path, ip_set):
    with open(path, "w") as f:
        for ip in sorted(ip_set):
            f.write(f"{ip}\n")

def process_log():
    print(f"{log_timestamp()} 🔎 [Process Log] Running analysis...")
    known_users = load_users(USER_FILE)
    entries = parse_log_file()
    ip_events_1h = defaultdict(deque)
    ip_events_24h = defaultdict(deque)
    gray_list, block_list = set(), set()

    for entry in entries:
        ip = entry["ip_address"]
        user = entry["username"]
        ts = entry["timestamp_dt"]

        while ip_events_1h[ip] and ts - ip_events_1h[ip][0] > timedelta(hours=1):
            ip_events_1h[ip].popleft()
        ip_events_1h[ip].append(ts)

        while ip_events_24h[ip] and ts - ip_events_24h[ip][0] > timedelta(hours=24):
            ip_events_24h[ip].popleft()
        ip_events_24h[ip].append(ts)

        if user in known_users:
            recent_10min = [t for t in ip_events_1h[ip] if ts - t <= timedelta(minutes=10)]
            if len(recent_10min) >= 10:
                #print(f"{log_timestamp()} ⚠️ [GRAYLIST] {ip} - {len(recent_10min)} failures in 10 min (user={user})")
                gray_list.add(ip)
        else:
            if len(ip_events_1h[ip]) >= 5 or len(ip_events_24h[ip]) >= 10:
                #print(f"{log_timestamp()} ⛔ [BLOCKLIST] {ip} - {len(ip_events_1h[ip])} in 1h / {len(ip_events_24h[ip])} in 24h")
                block_list.add(ip)

    write_edl(GRAY_LIST_FILE, gray_list)
    write_edl(BLOCK_LIST_FILE, block_list)
    print(f"{log_timestamp()} ✅ [Process Log] Done. Gray: {len(gray_list)} | Block: {len(block_list)}")

def process_log_schedule():
    while True:
        process_log()
        time.sleep(RUN_INTERVAL_MINUTES * 60)

def syslog_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_IP, UDP_PORT))
    print(f"{log_timestamp()} 🟢 Syslog listener started on {UDP_PORT}")

    while True:
        try:
            data, _ = sock.recvfrom(4096)
            message = data.decode(errors='ignore')
            json_start = message.index("{")
            json_payload = message[json_start:]
            log_data = json.loads(json_payload)

            log_data["timestamp"] = datetime.now(DUBAI_TZ).isoformat()
            with open(LOG_FILE, "a") as f:
                f.write(json.dumps(log_data) + "\n")

            if "cmd" in log_data:
                print(f"{log_timestamp()} ⚙️ Detected config change, fetching users in 60s...")
                threading.Timer(60, gp_localdb).start()
            else:
                print(f"{log_timestamp()} 📩 Syslog logged: {log_data['ip_address']} | user={log_data.get('username', '-')}")

        except (ValueError, json.JSONDecodeError):
            print(f"{log_timestamp()} ⚠️ No JSON found or malformed JSON.")
        except Exception as e:
            print(f"{log_timestamp()} ❌ Error in syslog_listener: {e}")

def start_http_server():
    os.chdir(".")  # Serve current directory
    httpd = HTTPServer(("0.0.0.0", EDL_PORT), SimpleHTTPRequestHandler)
    print(f"{log_timestamp()} 🌐 HTTP server started on port {EDL_PORT} (EDL serving)")
    httpd.serve_forever()

if __name__ == "__main__":
    threading.Thread(target=syslog_listener, daemon=True).start()
    threading.Thread(target=gp_localdb_scheduler, daemon=True).start()
    threading.Thread(target=process_log_schedule, daemon=True).start()
    threading.Thread(target=start_http_server, daemon=True).start()

    while True:
        time.sleep(1)
