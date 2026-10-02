import sqlite3
from datetime import datetime


DATABASE_NAME = "scans.db"


def create_database():

    connection = sqlite3.connect(DATABASE_NAME)

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            scan_time TEXT NOT NULL,
            status_code INTEGER,
            https INTEGER,
            server TEXT
        )
    """)

    connection.commit()
    connection.close()


def save_scan(result):

    connection = sqlite3.connect(DATABASE_NAME)

    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO scans (
            url,
            scan_time,
            status_code,
            https,
            server
        )
        VALUES (?, ?, ?, ?, ?)
    """, (
        result["url"],
        datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        result["status_code"],
        1 if result["https"] else 0,
        result["server"]
    ))

    connection.commit()
    connection.close()


def get_scan_history():

    connection = sqlite3.connect(DATABASE_NAME)

    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            url,
            scan_time,
            status_code,
            https,
            server
        FROM scans
        ORDER BY id DESC
    """)

    rows = cursor.fetchall()

    connection.close()

    return rows