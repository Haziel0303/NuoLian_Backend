import os

import psycopg


def get_database_url() -> str:
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL is not set")
    return database_url


def check_database_connection() -> dict[str, str]:
    with psycopg.connect(get_database_url()) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT current_database(), current_user")
            database_name, current_user = cur.fetchone()

    return {
        "database": database_name,
        "user": current_user,
    }
