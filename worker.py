import time
import io
import pandas as pd
import requests
import hashlib
from datetime import datetime, timezone
from database import init_db, insert_threat
from intelligence import calculate_threat_score, enrich_indicator

def fetch_and_update_db():
    print("\n[WORKER] Fetching new threat intelligence from global sources...")
    
    try:
        # --- SOURCE 1: URLhaus (Malware URLs) ---
        try:
            res_urlhaus = requests.get("https://urlhaus.abuse.ch/downloads/csv_recent/", timeout=10)
            clean_urlhaus = '\n'.join([line for line in res_urlhaus.text.splitlines() if not line.startswith('#')])
            
            urlhaus_cols = ['id', 'dateadded', 'url', 'url_status', 'last_online', 'threat', 'tags', 'urlhaus_link', 'reporter']
            df_urlhaus = pd.read_csv(io.StringIO(clean_urlhaus), names=urlhaus_cols, on_bad_lines='skip')
            df_urlhaus.dropna(subset=['url'], inplace=True) 
            
            for _, row in df_urlhaus.head(20).iterrows():
                indicator = str(row['url'])
                score = calculate_threat_score(indicator, is_ip=False)
                severity = 'Critical' if score > 80 else 'High' if score > 60 else 'Medium'
                
                clean_threat = str(row['threat']).replace('_', ' ').title() if pd.notna(row['threat']) else 'Malware'
                country, city, isp = enrich_indicator(indicator)
                
                data = (f"UH-{row['id']}", "URLhaus", clean_threat, indicator, score, severity, country, city, isp, str(row['dateadded']))
                insert_threat(data)
        except Exception as e:
            print(f"[WORKER WARNING] URLhaus sync failed: {e}")

        # --- SOURCE 2: FeodoTracker (Botnet C2) ---
        try:
            res_feodo = requests.get("https://feodotracker.abuse.ch/downloads/ipblocklist.csv", timeout=10)
            clean_feodo = '\n'.join([line for line in res_feodo.text.splitlines() if not line.startswith('#')])
            
            feodo_cols = ['first_seen_utc', 'dst_ip', 'dst_port', 'c2_status', 'last_online', 'malware']
            df_feodo = pd.read_csv(io.StringIO(clean_feodo), names=feodo_cols, on_bad_lines='skip')
            df_feodo.dropna(subset=['dst_ip'], inplace=True)
            
            for _, row in df_feodo.head(15).iterrows():
                indicator = str(row['dst_ip'])
                score = calculate_threat_score(indicator, is_ip=True)
                country, city, isp = enrich_indicator(indicator)
                safe_id = indicator.replace('.', '')
                
                data = (f"FT-{safe_id}", "FeodoTracker", "Botnet C2", indicator, score, 'Critical', country, city, isp, str(row['first_seen_utc']))
                insert_threat(data)
        except Exception as e:
             print(f"[WORKER WARNING] FeodoTracker sync failed: {e}")

        # --- SOURCE 3: OpenPhish (Live Phishing URLs) ---
        try:
            response = requests.get("https://openphish.com/feed.txt", timeout=10)
            urls = response.text.splitlines()
            
            for url in urls[:20]: 
                indicator = str(url)
                score = calculate_threat_score(indicator, is_ip=False)
                country, city, isp = enrich_indicator(indicator)
                
                url_hash = hashlib.md5(indicator.encode()).hexdigest()[:8].upper()
                current_time = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
                
                data = (f"OP-{url_hash}", "OpenPhish", "Phishing Website", indicator, score, 'High', country, city, isp, current_time)
                insert_threat(data)
        except Exception as e:
            print(f"[WORKER WARNING] OpenPhish sync failed: {e}")

        # --- SOURCE 4: ThreatFox (Live IOCs) ---
        try:
            res_tf = requests.get("https://threatfox.abuse.ch/export/csv/recent/", timeout=10)
            clean_tf = '\n'.join([line for line in res_tf.text.splitlines() if not line.startswith('#')])
            
            # ThreatFox comments out its header. We use header=None and exact column indexes.
            # Index Map: 1=ID, 2=Indicator, 3=Type, 4=Classification
            df_tf = pd.read_csv(io.StringIO(clean_tf), header=None, on_bad_lines='skip', quotechar='"', skipinitialspace=True)
            df_tf.dropna(subset=[2], inplace=True)
            
            for _, row in df_tf.head(20).iterrows():
                indicator = str(row[2])
                is_ip = str(row[3]) in ["ip:port", "ipv4:port", "ipv4"]
                score = calculate_threat_score(indicator, is_ip=is_ip)
                severity = 'Critical' if score > 80 else 'High' if score > 60 else 'Medium'
                country, city, isp = enrich_indicator(indicator)
                
                clean_threat = str(row[4]).replace('_', ' ').title() if pd.notna(row[4]) else "Unknown IOC"
                current_time = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
                
                data = (f"TF-{row[1]}", "ThreatFox", f"IOC ({clean_threat})", indicator, score, severity, country, city, isp, current_time)
                insert_threat(data)
        except Exception as e:
            print(f"[WORKER WARNING] ThreatFox CSV sync failed: {e}")

        # --- SOURCE 5: MalwareBazaar (Malware File Hashes) ---
        try:
            res_mb = requests.get("https://bazaar.abuse.ch/export/csv/recent/", timeout=10)
            # Remove comment lines
            lines = [line for line in res_mb.text.splitlines() if not line.startswith('#')]
            clean_mb = '\n'.join(lines)
            
            # Using quotechar and skipinitialspace to ensure clean string extraction
            df_mb = pd.read_csv(io.StringIO(clean_mb), header=None, on_bad_lines='skip', quotechar='"', skipinitialspace=True)
            df_mb.dropna(subset=[1], inplace=True)
            
            for _, row in df_mb.head(25).iterrows():
                # Explicitly strip any lingering quotes just in case
                indicator = str(row[1]).strip('"')
                
                # Processing File Type and Signature
                file_type = str(row[6]).strip('"').upper() if pd.notna(row[6]) else "UNKNOWN"
                sig = str(row[8]).strip('"').title() if pd.notna(row[8]) else "Unknown"
                
                # Logic to handle the "N/A" strings found in MalwareBazaar
                if sig in ["Unknown", "None", "N/A", "n/a"]:
                    clean_threat = f"Malware Payload ({file_type})"
                else:
                    clean_threat = f"{sig} ({file_type})"
                
                current_time = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
                
                data = (
                    f"MB-{indicator[:8]}", 
                    "MalwareBazaar", 
                    clean_threat, 
                    indicator, 
                    90, 
                    'Critical', 
                    "Unknown", 
                    "Unknown", 
                    "Unknown", 
                    current_time
                )
                insert_threat(data)
                
        except Exception as e:
            print(f"[WORKER WARNING] MalwareBazaar CSV sync failed: {e}")

        print("[WORKER] Success: Database updated with cleanly parsed threats.")

    except Exception as e:
        print(f"[WORKER ERROR] Main sync loop failed: {e}")

if __name__ == '__main__':
    init_db()
    print("ThreatScope - Backend Worker Initialized.")
    print("Press Ctrl+C to shut down the worker.")
    
    while True:
        fetch_and_update_db()
        time.sleep(1800)