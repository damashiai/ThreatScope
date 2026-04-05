import sqlite3

DB_NAME = 'threats.db'

def get_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS threats (
            id TEXT PRIMARY KEY,
            source TEXT,
            type TEXT,
            indicator TEXT,
            threat_score INTEGER,
            severity TEXT,
            country TEXT,
            city TEXT,
            isp TEXT,
            timestamp TEXT
        )
    ''')
    conn.commit()
    conn.close()

def insert_threat(data):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT OR IGNORE INTO threats 
        (id, source, type, indicator, threat_score, severity, country, city, isp, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', data)
    conn.commit()
    conn.close()

def get_latest_threats(limit=100):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM threats ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]