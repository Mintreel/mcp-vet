import os
import subprocess
import sqlite3
import requests


def get_config_value():
    """Safe: reads from environment variable."""
    return os.environ.get("API_KEY", "default")


def run_static_command():
    """Safe: static string argument."""
    os.system("echo hello")


def read_config_file():
    """Safe: uses __file__ for path resolution."""
    config_path = os.path.join(os.path.dirname(__file__), "config.json")
    with open(config_path) as f:
        return f.read()


def safe_query(cursor, user_id):
    """Safe: parameterized query with %s placeholder."""
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))


def safe_subprocess():
    """Safe: subprocess without shell=True."""
    subprocess.run(["ls", "-la"])


def validated_path(user_input):
    """Safe: validates path with realpath."""
    real = os.path.realpath(user_input)
    if not real.startswith("/allowed/"):
        raise ValueError("Invalid path")
    with open(real) as f:
        return f.read()


def safe_request():
    """Safe: hardcoded URL."""
    requests.get("https://api.example.com/data")
