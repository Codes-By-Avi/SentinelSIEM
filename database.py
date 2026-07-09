import sqlite3


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

        threat_score INTEGER

    )
    """)

    connection.commit()

    connection.close()


def save_alert(alert):

    connection = sqlite3.connect("sentinelsiem.db")

    cursor = connection.cursor()

    cursor.execute("""
    INSERT INTO alerts
    (
        severity,
        alert_type,
        source_ip,
        attempts,
        threat_score
    )

    VALUES (?, ?, ?, ?, ?)

    """,
    (
        alert["severity"],
        alert["type"],
        alert["source_ip"],
        alert["attempts"],
        alert["threat_score"]
    ))

    connection.commit()

    connection.close()


create_database()