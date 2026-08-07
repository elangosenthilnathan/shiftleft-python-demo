import os
import sqlite3
from pathlib import Path

from flask import Flask, g

DB_FILENAME = "database.db"


def query_db(query, args=(), one=False, commit=False):
    # SECURE: Validate query structure before execution to add defense-in-depth
    query_upper = query.upper().strip()
    
    # SECURE: Check for SQL keywords that should never appear in user-related queries
    dangerous_patterns = ['DROP', 'ALTER', 'CREATE', 'TRUNCATE', '--', '/*', '*/', 'EXEC', 'EXECUTE']
    for pattern in dangerous_patterns:
        if pattern in query_upper:
            raise ValueError(f"Potentially dangerous SQL pattern detected: {pattern}")
    
    # SECURE: Ensure query starts with expected operations only
    allowed_operations = ['SELECT', 'INSERT', 'UPDATE', 'DELETE']
    if not any(query_upper.startswith(op) for op in allowed_operations):
        raise ValueError("Query must start with SELECT, INSERT, UPDATE, or DELETE")
    
    # SECURE: Verify args is a tuple/list to prevent parameter smuggling
    if not isinstance(args, (tuple, list)):
        raise TypeError("Query parameters must be provided as tuple or list")
    
    with sqlite3.connect(DB_FILENAME) as conn:
        # SECURE: Remove trace callback to prevent sensitive data exposure in logs
        # conn.set_trace_callback(print)  # Removed for security
        cur = conn.cursor()
        # SECURE: Execute with explicit parameter binding to prevent SQL injection
        cur.execute(query, tuple(args))
        if commit:
            conn.commit()
        return cur.fetchone() if one else cur.fetchall()



def create_app():
    app = Flask(__name__)
    app.secret_key = "aeZ1iwoh2ree2mo0Eereireong4baitixaixu5Ee"

    db_path = Path(DB_FILENAME)
    if db_path.exists():
        db_path.unlink()

    conn = sqlite3.connect(DB_FILENAME)
    create_table_query = """CREATE TABLE IF NOT EXISTS user
    (id INTEGER PRIMARY KEY, username TEXT, password TEXT, access_level INTEGER)"""
    conn.execute(create_table_query)

    insert_admin_query = """INSERT INTO user (id, username, password, access_level)
    VALUES (1, 'admin', 'maximumentropy', 0)"""
    conn.execute(insert_admin_query)
    conn.commit()
    conn.close()

    with app.app_context():
        from . import actions
        from . import auth
        from . import status
        from . import ui
        from . import users

        app.register_blueprint(actions.bp)
        app.register_blueprint(auth.bp)
        app.register_blueprint(status.bp)
        app.register_blueprint(ui.bp)
        app.register_blueprint(users.bp)
        return app
