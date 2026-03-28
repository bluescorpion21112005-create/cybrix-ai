"""
desktop_agent/config.py — Desktop agent configuration.
Override SERVER_URL via environment variable in production.
"""
import os

SERVER_URL = os.environ.get("AGENT_SERVER_URL", "http://localhost:5000")
DEFAULT_TIMEOUT = int(os.environ.get("AGENT_TIMEOUT", "30"))
