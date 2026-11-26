#!/usr/bin/env python3
"""CNT3004 cloud file server: threaded TCP, TLS, authentication, file operations, metrics."""

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


def recv_json(sock):
    data = bytearray()
    while not data.endswith(b"\n"):
        chunk = sock.recv(1)
        if not chunk:
            raise ConnectionError("Connection closed while receiving a command.")
        data.extend(chunk)
        if len(data) > MAX_HEADER:
            raise ValueError("Command header exceeds the maximum allowed size.")
    return json.loads(data.decode("utf-8"))


def receive_exact(sock, byte_count):
    remaining = byte_count
    while remaining:
        chunk = sock.recv(min(CHUNK_SIZE, remaining))
        if not chunk:
            raise ConnectionError("Connection closed during file transfer.")
        remaining -= len(chunk)
        yield chunk


def category_for_name(filename):
    extension = Path(filename).suffix.lower()
    if extension in TEXT_EXTENSIONS:
        return "text"
    if extension in AUDIO_EXTENSIONS:
        return "audio"
    if extension in VIDEO_EXTENSIONS:
        return "video"
    return "other"


def safe_path(relative_path):
    """Resolve a client path and reject paths outside the storage root."""
    root = STORAGE.resolve()
    candidate = (root / relative_path).resolve()
    if candidate != root and root not in candidate.parents:
        raise ValueError("Invalid path: access outside server storage is prohibited.")
    return candidate


def validate_managed_filename(filename):
    """Require a category prefix and numeric identifier for explicitly named files."""
    if Path(filename).name != filename:
        raise ValueError("A managed filename cannot contain directory separators.")

    category = category_for_name(filename)
    expected_prefix = PREFIX_BY_CATEGORY[category]
    match = re.match(r"^(TS|AU|VD|OT)(\d{3,})_.+", filename)

    if not match:
        raise ValueError(
            "Filename must use the format CATEGORY###_filename.ext "
            "(examples: TS001_notes.txt, AU001_song.mp3, VD001_clip.mp4)."
        )

    if match.group(1) != expected_prefix:
        raise ValueError(
            f"This file type requires the {expected_prefix} prefix."
        )


def allocate_managed_filename(directory, original_name):
    """Generate a unique category ID such as TS001_notes.txt."""
    original_name = Path(original_name).name
    if not original_name or original_name in {".", ".."}:
        raise ValueError("A valid original filename is required.")

    category = category_for_name(original_name)
    prefix = PREFIX_BY_CATEGORY[category]
    safe_original = re.sub(r"[^A-Za-z0-9._-]+", "_", original_name).strip("._")
    if not safe_original:
        safe_original = "file"

    highest = 0
    pattern = re.compile(rf"^{re.escape(prefix)}(\d{{3,}})_")

    for existing in STORAGE.rglob("*"):
        if existing.is_file():
            match = pattern.match(existing.name)
            if match:
                highest = max(highest, int(match.group(1)))

    identifier = highest + 1
    while True:
        candidate = directory / f"{prefix}{identifier:03d}_{safe_original}"
        # Include paths reserved by uploads that have not created their final
        # files yet; otherwise two simultaneous clients could get one ID.
        if candidate.exists() or str(candidate.resolve()) in processing_files:
            identifier += 1
            continue
        return candidate


def load_users():
    if not USERS_FILE.exists():
        return {}
    with USERS_FILE.open("r", encoding="utf-8") as file:
        return json.load(file)


def create_user(username, password):
    if not username or not password:
        raise ValueError("Username and password cannot be empty.")

    users = load_users()
    if username in users:
        raise ValueError(f"User '{username}' already exists.")

    salt = secrets.token_bytes(16)
    verifier = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
    )

    users[username] = {
        "salt": base64.b64encode(salt).decode("ascii"),
        "verifier": base64.b64encode(verifier).decode("ascii"),
        "iterations": PBKDF2_ITERATIONS
    }

    temporary_file = USERS_FILE.with_suffix(".tmp")
    temporary_file.write_text(json.dumps(users, indent=2), encoding="utf-8")
    try:
        os.chmod(temporary_file, 0o600)
    except OSError:
        pass
    temporary_file.replace(USERS_FILE)
    print(f"Created account for '{username}'.")


def record_metric(operation, filename="", size_bytes=0,
                  transfer_seconds=0.0, response_seconds=0.0):
    new_file = not METRICS_FILE.exists()
    throughput = (
        size_bytes / (1024 * 1024) / transfer_seconds
        if transfer_seconds > 0 and size_bytes > 0 else 0.0
    )

    with metrics_lock, METRICS_FILE.open(
        "a", newline="", encoding="utf-8"
    ) as file:
        writer = csv.writer(file)
        if new_file:
            writer.writerow([
                "timestamp", "operation", "filename", "size_bytes",
                "transfer_seconds", "throughput_MBps", "response_seconds"
            ])
        writer.writerow([
            time.strftime("%Y-%m-%d %H:%M:%S"),
            operation,
            filename,
            size_bytes,
            round(transfer_seconds, 6),
            round(throughput, 6),
            round(response_seconds, 6)
        ])


class ClientHandler(socketserver.BaseRequestHandler):
    """One handler instance is created for each connected client thread."""

    def authenticate(self):
        users = load_users()
        send_json(self.request, {"status": "AUTH_REQUIRED"})

        auth_request = recv_json(self.request)
        username = auth_request.get("username", "")
        user = users.get(username)

        if user:
            salt = base64.b64decode(user["salt"])
            verifier = base64.b64decode(user["verifier"])
            iterations = int(user.get("iterations", PBKDF2_ITERATIONS))
        else:
            salt = secrets.token_bytes(16)
            verifier = secrets.token_bytes(32)
            iterations = PBKDF2_ITERATIONS

        nonce = secrets.token_bytes(32)
        send_json(self.request, {
            "status": "CHALLENGE",
            "salt": base64.b64encode(salt).decode("ascii"),
            "iterations": iterations,
            "nonce": base64.b64encode(nonce).decode("ascii")
        })

        proof_request = recv_json(self.request)
        supplied_proof = proof_request.get("proof", "")
        expected_proof = hmac.new(
            verifier, nonce, hashlib.sha256
        ).hexdigest()

        if not user or not hmac.compare_digest(supplied_proof, expected_proof):
            send_json(self.request, {
                "status": "ERROR",
                "message": "Authentication failed."
            })
            return False

        send_json(self.request, {
            "status": "OK",
            "message": "Authentication successful."
        })
        return True

    def handle(self):
        client = self.client_address
        print(f"[+] Client connected: {client[0]}:{client[1]}")

        try:
            if not self.authenticate():
                return

            while True:
                command = recv_json(self.request)
                action = command.get("action", "").lower()
                started = time.perf_counter()

                if action == "quit":
                    send_json(self.request, {
                        "status": "OK",
                        "message": "Disconnected."
                    })
                    break

                try:
                    if action == "dir":
                        self.do_dir(command, started)
                    elif action == "mkdir":
                        self.do_mkdir(command, started)
                    elif action == "rmdir":
                        self.do_rmdir(command, started)
                    elif action == "upload":
                        self.do_upload(command, started)
                    elif action == "download":
                        self.do_download(command, started)
                    elif action == "delete":
                        self.do_delete(command, started)
                    else:
                        send_json(self.request, {
                            "status": "ERROR",
                            "message": "Unknown command."
                        })
                        record_metric("unknown", response_seconds=time.perf_counter() - started)

                except (OSError, ValueError, KeyError, TypeError, ConnectionError) as exc:
                    send_json(self.request, {
                        "status": "ERROR",
                        "message": str(exc)
                    })
                    record_metric(
                        action or "invalid",
                        str(command.get("filename", command.get("path", ""))),
                        response_seconds=time.perf_counter() - started
                    )

        except (ConnectionError, OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"[-] Client {client[0]} disconnected: {exc}")
        finally:
            print(f"[-] Client disconnected: {client[0]}:{client[1]}")

    def do_dir(self, command, started):
        folder = safe_path(command.get("path", "."))
        if not folder.exists() or not folder.is_dir():
            raise ValueError("Directory does not exist.")

        entries = []
        for item in sorted(folder.iterdir(), key=lambda path: path.name.lower()):
            if item.name.endswith(".part"):
                continue
            entries.append({
                "name": item.name,
                "type": "directory" if item.is_dir() else "file",
                "size_bytes": item.stat().st_size if item.is_file() else None
            })

        send_json(self.request, {"status": "OK", "entries": entries})
        record_metric("dir", str(command.get("path", ".")),
                      response_seconds=time.perf_counter() - started)

    def do_mkdir(self, command, started):
        folder = safe_path(command["path"])
        folder.mkdir(parents=True, exist_ok=False)
        send_json(self.request, {"status": "OK", "message": "Subfolder created."})
        record_metric("mkdir", str(command["path"]),
                      response_seconds=time.perf_counter() - started)

    def do_rmdir(self, command, started):
        folder = safe_path(command["path"])
        if not folder.exists() or not folder.is_dir():
            raise ValueError("Subfolder does not exist.")
        folder.rmdir()
        send_json(self.request, {
            "status": "OK",
            "message": "Empty subfolder deleted."
        })
        record_metric("rmdir", str(command["path"]),
                      response_seconds=time.perf_counter() - started)

    def do_upload(self, command, started):
        original_name = Path(command["original_name"]).name
        size = int(command["size"])
        if size < 0:
            raise ValueError("File size cannot be negative.")

        requested_name = command.get("filename")
        if requested_name:
            target = safe_path(requested_name)
            validate_managed_filename(target.name)
            directory = target.parent
        else:
            directory = safe_path(command.get("directory", "."))
            target = None

        if not directory.exists() or not directory.is_dir():
            raise ValueError("Target directory does not exist.")

        # Allocate an automatic ID and reserve its path in one critical section.
        # This prevents two clients from receiving the same next identifier.
        with storage_lock:
            if target is None:
                target = allocate_managed_filename(directory, original_name)

            if target.exists() and target.is_dir():
                raise ValueError("A directory already exists with that name.")

            key = str(target.resolve())
            if key in processing_files:
                raise ValueError("File is currently being processed.")

            processing_files.add(key)

        temporary_path = target.with_name(
            target.name + f".{secrets.token_hex(8)}.part"
        )

        try:
            if target.exists():
                send_json(self.request, {
                    "status": "EXISTS",
                    "message": "File already exists. Overwrite?"
                })
                overwrite = recv_json(self.request).get("overwrite", False)
                if not overwrite:
                    send_json(self.request, {
                        "status": "CANCELLED",
                        "message": "Upload cancelled."
                    })
                    return

            send_json(self.request, {
                "status": "READY",
                "filename": str(target.relative_to(STORAGE.resolve())),
                "message": "Ready to receive file data."
            })

            transferred = 0
            transfer_started = time.perf_counter()

            with temporary_path.open("wb") as output:
                for chunk in receive_exact(self.request, size):
                    output.write(chunk)
                    transferred += len(chunk)
                output.flush()
                os.fsync(output.fileno())

            temporary_path.replace(target)
            elapsed = time.perf_counter() - transfer_started
            response_time = time.perf_counter() - started

            record_metric(
                "upload",
                str(target.relative_to(STORAGE.resolve())),
                transferred,
                elapsed,
                response_time
            )

            send_json(self.request, {
                "status": "OK",
                "message": "Upload complete.",
                "filename": str(target.relative_to(STORAGE.resolve())),
                "size_bytes": transferred,
                "transfer_seconds": round(elapsed, 6),
                "throughput_MBps": round(
                    transferred / (1024 * 1024) / elapsed, 6
                ) if elapsed else 0.0
            })

        except Exception:
            temporary_path.unlink(missing_ok=True)
            raise
        finally:
            temporary_path.unlink(missing_ok=True)
            with storage_lock:
                processing_files.discard(key)

    def do_download(self, command, started):
        target = safe_path(command["filename"])
        if not target.exists() or not target.is_file():
            raise ValueError("File does not exist.")

        key = str(target.resolve())
        with storage_lock:
            if key in processing_files:
                raise ValueError("File is currently being processed.")
            processing_files.add(key)

        try:
            size = target.stat().st_size
            send_json(self.request, {
                "status": "READY",
                "size": size,
                "filename": str(target.relative_to(STORAGE.resolve()))
            })

            transfer_started = time.perf_counter()
            sent = 0

            with target.open("rb") as source:
                while True:
                    chunk = source.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    self.request.sendall(chunk)
                    sent += len(chunk)

            elapsed = time.perf_counter() - transfer_started
            record_metric(
                "download",
                str(target.relative_to(STORAGE.resolve())),
                sent,
                elapsed,
                time.perf_counter() - started
            )
        finally:
            with storage_lock:
                processing_files.discard(key)

    def do_delete(self, command, started):
        target = safe_path(command["filename"])
        if not target.exists() or not target.is_file():
            raise ValueError("File does not exist.")

        key = str(target.resolve())
        with storage_lock:
            if key in processing_files:
                raise ValueError("File is currently being processed.")
            target.unlink()

        send_json(self.request, {"status": "OK", "message": "File deleted."})
        record_metric("delete", str(command["filename"]),
                      response_seconds=time.perf_counter() - started)


class ThreadedTLSServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True
    block_on_close = False

    def __init__(self, address, handler, tls_context):
        self.tls_context = tls_context
        super().__init__(address, handler)

    def get_request(self):
        raw_socket, address = super().get_request()
        try:
            secure_socket = self.tls_context.wrap_socket(
                raw_socket, server_side=True
            )
            return secure_socket, address
        except Exception:
            raw_socket.close()
            raise


def main():
    parser = argparse.ArgumentParser(description="CNT3004 secure cloud file server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5001)
    parser.add_argument("--cert", help="TLS certificate PEM file")
    parser.add_argument("--key", help="TLS private key PEM file")
    parser.add_argument("--create-user", metavar="USERNAME")
    args = parser.parse_args()

    if args.create_user:
        password = getpass.getpass("New password: ")
        confirmation = getpass.getpass("Confirm password: ")
        if password != confirmation:
            raise SystemExit("Passwords do not match.")
        create_user(args.create_user, password)
        return

    if not args.cert or not args.key:
        raise SystemExit(
            "TLS is required. Supply --cert server.crt --key server.key."
        )

    if not USERS_FILE.exists():
        raise SystemExit("Create an account first with --create-user USERNAME.")

    STORAGE.mkdir(parents=True, exist_ok=True)

    tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_context.minimum_version = ssl.TLSVersion.TLSv1_2
    tls_context.load_cert_chain(certfile=args.cert, keyfile=args.key)

    with ThreadedTLSServer(
        (args.host, args.port), ClientHandler, tls_context
    ) as server:
        print(f"TLS file server listening on {args.host}:{args.port}")
        print(f"Storage directory: {STORAGE}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down server.")


if __name__ == "__main__":
    main()
