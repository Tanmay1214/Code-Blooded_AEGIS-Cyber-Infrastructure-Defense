import time
import requests
import random
import pandas as pd
from pathlib import Path

import os

API_BASE = os.getenv("API_BASE", "http://127.0.0.1:8000/api")
LOGS_CSV = "data/system_logs.csv"

def get_nodes():
    try:
        resp = requests.get(f"{API_BASE}/dashboard-aggregator?full=true")
        if resp.status_code == 200:
            data = resp.json()
            nodes = [n['id'] for n in data.get('nodes', [])]
            print(f" [+] Discovered {len(nodes)} nodes for telemetry.")
            return nodes
    except Exception as e:
        print(f"Error fetching nodes: {e}")
    return []

def main():
    print("AEGIS_CORE_HEARTBEAT_ACTIVE [MISSION: CSV_SYNC_LOOP]")
    
    nodes = get_nodes()
    if not nodes:
        print("CRITICAL_ERROR: No nodes detected. Seeding may be required.")
        return

    # Load the 10,000 log entries from the intelligence dataset
    print(f" [+] Loading forensic intelligence from {LOGS_CSV}...")
    try:
        df_logs = pd.read_csv(LOGS_CSV)
        total_csv_logs = len(df_logs)
        print(f" [+] Loaded {total_csv_logs} logs. Commencing sequential stream...")
    except Exception as e:
        print(f"CRITICAL_ERROR loading CSV: {e}")
        return

    iteration = 0
    while True:
        # BATCH MODE: Collect 100 packets then send in one HTTP request
        batch = []
        for _ in range(100):
            # Calculate the row index to loop sequentially through the 10,000 logs
            csv_idx = (iteration * 100 + len(batch)) % total_csv_logs
            row = df_logs.iloc[csv_idx]
            
            payload = {
                "node_id": int(row['node_id']),
                "json_status": row['json_status'],
                "http_response_code": int(row['http_response_code']),
                "response_time_ms": int(row['response_time_ms']),
                "load_val": float(row['load_val']) if pd.notnull(row['load_val']) else None,
                "l_v1": float(row['L_V1']) if pd.notnull(row['L_V1']) else None
            }
            batch.append(payload)

        try:
            resp = requests.post(f"{API_BASE}/ingest-bulk", json={"logs": batch})
            if resp.status_code in (200, 201):
                data = resp.json()
                print(f" [+] BATCH_SYNC [{iteration*100:06d}]: {data['ingested_count']} logs | Anomalies: {data['anomalies_detected']}")
            else:
                print(f" [!] BATCH_FAILED: {resp.status_code}")
        except Exception as e:
            print(f" [X] BATCH_ERROR: {e}")

        iteration += 1
        time.sleep(1.0) # 100 pkts/sec cadence

if __name__ == "__main__":
    main()