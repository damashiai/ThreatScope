# ThreatScope 🛡️

**ThreatScope** is a prototype for an automated, high-fidelity Threat Intelligence Platform (TIP) designed to aggregate, score, and visualize global cyber threats in real-time. By orchestrating data from multiple open-source intelligence (OSINT) feeds, ThreatScope provides security analysts with a unified dashboard for monitoring malware, botnets, and phishing campaigns.

---

## 🚀 Features

* **Multi-Source Aggregation:** Pulls live indicators of compromise (IOCs) from URLhaus, FeodoTracker, OpenPhish, ThreatFox, and MalwareBazaar.
* **Heuristic Scoring Engine:** Automatically calculates threat scores (0-100) based on indicator patterns (TLDs, file extensions, and IP signatures).
* **Automated Enrichment:** Performs real-time IP geolocation and ISP identification to track the physical infrastructure of threat actors.
* **Advanced Visualization:**
    * **Global Heatmap:** Interactive Choropleth map showing geographic concentrations of malicious activity.
    * **Spline Telemetry:** Professional curvy area charts for tracking detection volume over a 60-day rolling window.
    * **Infrastructure Tracking:** Identification of the top 5 most abused hosting providers and ISPs.
* **Modular Architecture:** Separated backend worker (ingestion) and frontend (Streamlit) for high stability and performance.

---

## 🛠️ Tech Stack

* **Language:** Python 3.9+
* **Frontend:** Streamlit (Custom CSS for professional/branded UI)
* **Visualization:** Plotly Express (Spline Interpolation, Mapbox)
* **Database:** SQLite3 (Local persistent storage)
* **Data Handling:** Pandas (Advanced CSV/JSON normalization and outlier removal)

---

## 📂 Project Structure
```
ThreatScope/
├── dashboard.py       - Streamlit UI & Data Visualization
├── worker.py          - Background data ingestion & enrichment engine
├── database.py        - SQLite abstraction layer
├── intelligence.py    - Scoring heuristics & geolocation logic
├── threats.db         - Local SQLite database (Generated at runtime)
└── requirements.txt   - Python dependencies
```

---

## ⚙️ Installation & Setup

1. Clone the repository:
```
git clone https://github.com/damashiai/ThreatScope.git
cd ThreatScope
```

2. Install dependencies:
```
pip install -r requirements.txt
```

3. Initialize the Data Worker:
   The worker runs in an infinite loop, fetching new data every 30 minutes.
```
python worker.py
```

4. Launch the Dashboard:
   Open a new terminal and run the Streamlit frontend.
```
streamlit run dashboard.py
```

---

## 🔍 Intelligence Sources

- URLhaus: Malware Distribution URLs (CSV Export)
- FeodoTracker: Botnet C2 Infrastructure (CSV Export)
- OpenPhish: Active Phishing Sites (Text Feed)
- ThreatFox: Multi-type IOCs (IPs, Domains) (CSV Export)
- MalwareBazaar: Malicious File Hashes (SHA256) (CSV Export)

---

## 🛠️ Deployment Notes

* Streamlit Community Cloud: Easiest for demoing. Requires requirements.txt.
* Outlier Handling: The dashboard automatically filters the timeline to a 60-day window relative to the newest entry to prevent x-axis distortion from stale data.
* Persistent Storage: If deploying to a containerized service (like Railway), ensure a volume is mounted for threats.db to prevent data loss on restart.