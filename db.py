import os
from contextlib import contextmanager
import psycopg2
import psycopg2.extras
from dotenv import load_dotenv

load_dotenv()


def get_connection():
    return psycopg2.connect(
        host=os.environ["DB_HOST"],
        port=os.environ.get("DB_PORT", 5432),
        dbname=os.environ["DB_NAME"],
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
    )


def query(sql, params=None):
    """Run a SELECT and return all rows as dicts. Always uses parameterized queries."""
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, params)
            return cur.fetchall()
    finally:
        conn.close()


def execute(sql, params=None):
    """Run a single INSERT/UPDATE/DELETE in its own transaction. Returns rowcount."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            conn.commit()
            return cur.rowcount
    finally:
        conn.close()


@contextmanager
def transaction():
    """
    Yield a RealDictCursor inside a single transaction.

    Use for multi-statement flows that must be atomic, e.g. creating a workspace and
    inserting the creator's admin membership row. Commits on clean exit; rolls back
    on any exception; always closes the connection.

        with db.transaction() as cur:
            cur.execute("INSERT INTO workspaces ...", (...,))
            cur.execute("INSERT INTO workspace_membership ...", (...,))
    """
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
