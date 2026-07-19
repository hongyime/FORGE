import sys
import os
from pathlib import Path

# Ensure forge is in path
sys.path.insert(0, str(Path(__file__).parent.parent.absolute()))

from forge.db.session import get_engagement_db
from datetime import datetime, timezone

def main():
    engagement_id = 1001
    db_path = Path(f".forge_data/engagements/{engagement_id}.db")

    print("Simulating a critical finding for Sentry pause...")
    
    con = get_engagement_db(db_path)
    try:
        con.execute(
            """
            INSERT OR IGNORE INTO engagements (id, name, status, operator)
            VALUES (?, ?, ?, ?)
            """,
            (engagement_id, f"Engagement {engagement_id}", "ACTIVE", "system")
        )
        
        # Add a URL to a host first
        host_ip = "10.0.0.10"
        url = f"http://{host_ip}/admin"
        
        con.execute(
            """
            INSERT OR IGNORE INTO crawl_results (engagement_id, url, title, discovered_at)
            VALUES (?, ?, ?, ?)
            """,
            (engagement_id, url, "Admin Panel", datetime.now(timezone.utc))
        )
        
        # Add a critical vulnerability finding
        vuln_id = "CVE-2023-99999"
        con.execute(
            """
            INSERT OR IGNORE INTO passive_vulns (engagement_id, vuln_id, plugin, url, severity, verified, discovered_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (engagement_id, vuln_id, "Critical RCE", url, "critical", 1, datetime.now(timezone.utc))
        )
        
        con.commit()
        print("Successfully inserted critical finding. If Sentry was enabled, it should pause.")
    finally:
        con.close()

if __name__ == "__main__":
    main()