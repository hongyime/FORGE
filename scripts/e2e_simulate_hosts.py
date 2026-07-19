import sys
import os
from pathlib import Path

# Ensure forge is in path
sys.path.insert(0, str(Path(__file__).parent.parent.absolute()))

from forge.db.session import get_engagement_db
import json
from datetime import datetime, timezone

def main():
    engagement_id = 1001
    db_path = Path(f".forge_data/engagements/{engagement_id}.db")

    print("Simulating a burst of host discoveries...")
    
    hosts = [
        {"ip": "10.0.0.10", "os": "linux", "ports": [22, 80]},
        {"ip": "10.0.0.11", "os": "windows", "ports": [445, 3389]},
        {"ip": "10.0.0.12", "os": "linux", "ports": [22, 8080]},
        {"ip": "10.0.0.13", "os": "unknown", "ports": [443]},
        {"ip": "10.0.0.14", "os": "linux", "ports": [22, 80, 443]},
    ]
    
    con = get_engagement_db(db_path)
    try:
        # First ensure engagement exists
        con.execute(
            """
            INSERT OR IGNORE INTO engagements (id, name, status, operator)
            VALUES (?, ?, ?, ?)
            """,
            (engagement_id, f"Engagement {engagement_id}", "ACTIVE", "system")
        )
        for host in hosts:
            con.execute(
                """
                INSERT OR IGNORE INTO hosts (engagement_id, ip, os_family, host_context)
                VALUES (?, ?, ?, ?)
                """,
                (engagement_id, host["ip"], host["os"], json.dumps({"simulated": True, "os_family": host["os"]}))
            )
            
            host_id_row = con.execute("SELECT id FROM hosts WHERE engagement_id=? AND ip=?", (engagement_id, host["ip"])).fetchone()
            if not host_id_row:
                continue
            host_id = host_id_row[0]
            
            for port in host["ports"]:
                service_name = "ssh" if port == 22 else "http" if port in (80, 443, 8080) else "smb" if port == 445 else "rdp"
                con.execute(
                    """
                    INSERT OR IGNORE INTO services (host_id, port, service_name)
                    VALUES (?, ?, ?)
                    """,
                    (host_id, port, service_name)
                )
                con.execute(
                    """
                    INSERT INTO port_scan_results (engagement_id, host, port, service, confidence, scanned_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (engagement_id, host["ip"], port, service_name, 0.95, datetime.now(timezone.utc))
                )
                
        con.commit()
        print("Successfully simulated host burst. You should see them pop up on the Command Center!")
    finally:
        con.close()

if __name__ == "__main__":
    main()