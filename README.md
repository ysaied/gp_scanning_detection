# 🌐 GlobalProtect Brute-force Detection & EDL Generator

## 🧩 Purpose:
This Python script is designed to monitor GlobalProtect login failures, detect suspicious IP behavior, and serve dynamically generated External Dynamic Lists (EDLs) to Palo Alto firewalls for automated blocking or graylisting.

---

## 🧱 Components:

1. **Syslog Listener**
   - Listens on UDP port `1514` for syslog events.
   - Parses logs and extracts JSON payloads.
   - Logs events into a file: `gp_scanning_detection_log.jsonl`.
   - If log includes `cmd`, it triggers the GP Local DB fetcher.

2. **GP Local DB Fetcher**
   - Queries the firewall (via API) for local user group members.
   - Saves user list in: `gp_scanning_detection_users.json`.
   - Runs every hour or on-demand (when syslog with `cmd` is received).

3. **Detection Engine**
   - Runs every 10 minutes.
   - Loads recent syslog data (up to 24 hours).
   - Tracks login failure frequency per IP:
     - 🔘 **Graylist:** Known user fails ≥10 times in 10 minutes
     - 🔴 **Blocklist:** Unknown user fails ≥3 times in 1h or ≥6 times in 24h
   - Saves lists to:
     - `gp_edl_gray.html`
     - `gp_eld_black.html`

4. **HTTP Server**
   - Serves the above EDLs on a configurable port (default: 8080)
   - Allows Palo Alto firewall to fetch block/gray lists dynamically.

5. **Thread Scheduler**
   - Each component runs in a separate daemon thread to ensure parallel execution and zero blocking.

---

## 🔁 Logic Flow Description:

1. Start Script
2. Launch:
   - Syslog Listener Thread
   - GP Local DB Fetcher Thread (scheduled)
   - Detection Engine Thread (scheduled)
   - HTTP EDL Server Thread

3. **Syslog Event Flow:**
   - Receive log → Extract JSON → Log to `.jsonl`
   - If `cmd` key present → Trigger immediate DB user fetch

4. **Detection Engine Flow:**
   - Load last 24h logs (up to `LOOKBACK_MINUTES`)
   - Track login failures per IP
   - Decide:
     - Add to graylist (10 failures in 10 min)
     - Add to blocklist (3 failures in 1h or 6 in 24h)
   - Write to `.html` files

---

## 📊 ASCII Architecture Diagram

                    +---------------------------+
                    |   Palo Alto Firewall      |
                    |     (Syslog Source)       |
                    +-------------+-------------+
                                  |
                                  v
                     +-------------------------+
                     |  Syslog Listener (UDP)  |
                     |  Port: 1514             |
                     +-------------------------+
                                  |
                                  v
              +-----------------------------------------+
              | gp_scanning_detection_log.jsonl         |
              +-----------------------------------------+
                                  |
                   +-------------+--------------+
                   |                            |
                   v                            v
        +----------------------+    +-------------------------+
        | GP Local DB Fetcher  |    | Detection Engine        |
        | Timer + On-Demand    |    | Every 10 mins           |
        +----------------------+    |                         |
                |                    | Reads logs + users     |
                v                    | Determines violations  |
  gp_scanning_detection_users.json   +-------------------------+
                                               |
                          +--------------------+--------------------+
                          |                                         |
                          v                                         v
         +-----------------------------+        +------------------------------+
         | gp_edl_gray.html (EDL)      |        | gp_eld_black.html (EDL)      |
         +-----------------------------+        +------------------------------+
                          |                                         |
                          v                                         v
           +-------------------------------------------------------------+
           |    Lightweight HTTP Server (port 8080 or configured port)   |
           +-------------------------------------------------------------+

---

## ⚙️ Configuration Notes

- **Syslog Port**: `1514`
- **EDL HTTP Port**: configurable via variable (default `8080`)
- **Log Files**:
  - `gp_scanning_detection_log.jsonl`: All login attempts
  - `gp_scanning_detection_users.json`: User list
- **EDL Files**:
  - `gp_edl_gray.html`: Graylisted IPs
  - `gp_eld_black.html`: Blocklisted IPs
- **Run Frequency**:
  - Local DB Fetcher: every 60 minutes
  - Detection Engine: every 10 minutes

---

## 🧾 Runtime Logging Format

Every log includes timestamp (Asia/Dubai):

```python
print(f"{log_timestamp()} ✅ Message here.")
```

Examples:
- `2025-06-06 10:10:10 ✅ Syslog received and processed.`
- `2025-06-06 10:15:10 ⚠️ Malformed JSON skipped.`
- `2025-06-06 10:20:10 🔴 IP 31.43.185.67 added to Blocklist.`

---

## 📥 Dependencies

- Python 3.9+
- Modules:
  - `requests`
  - `xmltodict`
  - `zoneinfo` (Python 3.9+)
  - `collections`, `json`, `datetime`, `http.server`, etc.

---

## 📦 Optional Improvements (Future Ideas)
- Dockerize this script
- Systemd service for always-on behavior
- Add basic auth to HTTP server
- Enable dynamic rule sync via firewall API
