import sqlite3

DB_NAME = "database.sqlite"


def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row  # Это позволяет получать данные в виде словаря
    return conn


def create_db():
    if get_db_connection() is not None:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
        """)

        conn.commit()
        conn.close()
    else: return 