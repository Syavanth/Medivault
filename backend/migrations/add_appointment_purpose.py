"""
Simple migration: add `purpose` column to appointments table if missing.
Run with: python migrations/add_appointment_purpose.py
"""
import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'mydb.sqlite')
DB_PATH = os.path.abspath(DB_PATH)

def column_exists(conn, table, column):
    cur = conn.execute(f"PRAGMA table_info({table})")
    cols = [r[1] for r in cur.fetchall()]
    return column in cols

if __name__ == '__main__':
    if not os.path.exists(DB_PATH):
        print(f"DB not found at {DB_PATH}, skipping migration")
        exit(0)

    conn = sqlite3.connect(DB_PATH)
    try:
        if not column_exists(conn, 'appointments', 'purpose'):
            print('Adding purpose column to appointments...')
            conn.execute("ALTER TABLE appointments ADD COLUMN purpose TEXT")
            conn.commit()
            print('Migration complete')
        else:
            print('purpose column already exists; nothing to do')
    finally:
        conn.close()
