import argparse
import base64
import csv
import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import socketserver
import ssl
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
STORAGE = ROOT / "storage"
USERS_FILE = ROOT / "users.json"
METRICS_FILE = ROOT / "network_metrics.csv"

CHUNK_SIZE = 1024 * 1024
MAX_HEADER = 64 * 1024
PBKDF2_ITERATIONS = 310_000

storage_lock = threading.RLock()
metrics_lock = threading.Lock()
processing_files = set()

TEXT_EXTENSIONS = {
    ".txt", ".md", ".csv", ".json", ".xml", ".html", ".htm",
    ".py", ".c", ".cpp", ".h", ".hpp", ".log", ".yaml", ".yml"
}
AUDIO_EXTENSIONS = {
    ".mp3", ".wav", ".flac", ".m4a", ".aac", ".ogg", ".wma"
}
VIDEO_EXTENSIONS = {
    ".mp4", ".mkv", ".mov", ".avi", ".webm", ".mpeg", ".mpg", ".wmv"
}
PREFIX_BY_CATEGORY = {
    "text": "TS",
    "audio": "AU",
    "video": "VD",
    "other": "OT"
}


def send_json(sock, data):
    sock.sendall(json.dumps(data).encode("utf-8") + b"\n")
