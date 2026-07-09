import sqlite3
from datetime import datetime


def create_database():

    connection = sqlite3.connect("sentinelsiem.db")

    cursor = connection.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        severity TEXT,

        alert_type TEXT,

        source_ip TEXT,

        attempts INTEGER,

        threat_score INTEGER,

        timestamp TEXT,

        status TEXT

    )
    """)

    connection.commit()

    connection.close()



def save_alert(alert):

    connection = sqlite3.connect("sentinelsiem.db")

    cursor = connection.cursor()

    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")


    cursor.execute("""
    INSERT INTO alerts
    (
        severity,
        alert_type,
        source_ip,
        attempts,
        threat_score,
        timestamp,
        status
    )

    VALUES (?, ?, ?, ?, ?, ?, ?)

    """,
    (
        alert["severity"],
        alert["type"],
        alert["source_ip"],
        alert["attempts"],
        alert["threat_score"],
        current_time,
        "OPEN"
    ))


    connection.commit()

    connection.close()



create_database()

def update_alert_status(alert_id, status):

    connection = sqlite3.connect("sentinelsiem.db")

    cursor = connection.cursor()

    cursor.execute(
        """
        UPDATE alerts
        SET status = ?
        WHERE id = ?
        """,
        (status, alert_id)
    )

    connection.commit()

    connection.close()