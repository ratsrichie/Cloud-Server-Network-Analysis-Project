#!/usr/bin/env python3
"""Interactive TLS client for the CNT3004 cloud file-sharing project."""

import argparse
import base64
import getpass
import hashlib
import hmac
import json
import shlex
import socket
import ssl
import time
from pathlib import Path

CHUNK_SIZE = 1024 * 1024
MAX_HEADER = 64 * 1024


def send_json(sock, data):
    sock.sendall(json.dumps(data).encode("utf-8") + b"\n")


def recv_json(sock):
    data = bytearray()
    while not data.endswith(b"\n"):
        chunk = sock.recv(1)
        if not chunk:
            raise ConnectionError("Server closed the connection.")
        data.extend(chunk)
        if len(data) > MAX_HEADER:
            raise ValueError("Server response is too large.")
    return json.loads(data.decode("utf-8"))


def receive_exact_to_file(sock, size, destination):
    remaining = size
    with destination.open("wb") as output:
        while remaining:
            chunk = sock.recv(min(CHUNK_SIZE, remaining))
            if not chunk:
                raise ConnectionError("Download interrupted.")
            output.write(chunk)
            remaining -= len(chunk)


def authenticate(sock):
    response = recv_json(sock)
    if response.get("status") != "AUTH_REQUIRED":
        raise RuntimeError("Unexpected authentication response.")

    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")
    send_json(sock, {"username": username})

    challenge = recv_json(sock)
    if challenge.get("status") != "CHALLENGE":
        raise PermissionError(challenge.get("message", "Authentication failed."))

    salt = base64.b64decode(challenge["salt"])
    nonce = base64.b64decode(challenge["nonce"])
    iterations = int(challenge["iterations"])

    verifier = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations
    )
    proof = hmac.new(verifier, nonce, hashlib.sha256).hexdigest()
    send_json(sock, {"proof": proof})

    result = recv_json(sock)
    if result.get("status") != "OK":
        raise PermissionError(result.get("message", "Authentication failed."))

    print("Authentication successful.")


def show_directory(entries):
    if not entries:
        print("Directory is empty.")
        return

    print(f"{'TYPE':<12} {'SIZE (bytes)':>14}  NAME")
    print("-" * 65)
    for entry in entries:
        size = "-" if entry["size_bytes"] is None else str(entry["size_bytes"])
        print(f"{entry['type']:<12} {size:>14}  {entry['name']}")


def upload_file(sock, local_path, remote_path=None):
    local = Path(local_path).expanduser()
    if not local.is_file():
        print("Local file does not exist.")
        return

    request = {
        "action": "upload",
        "original_name": local.name,
        "filename": remote_path,
        "size": local.stat().st_size
    }
    send_json(sock, request)
    response = recv_json(sock)

    if response["status"] == "EXISTS":
        answer = input("File exists. Overwrite? (y/n): ").strip().lower()
        send_json(sock, {"overwrite": answer == "y"})
        response = recv_json(sock)

    if response["status"] == "CANCELLED":
        print(response.get("message", "Upload cancelled."))
        return

    if response["status"] != "READY":
        print(response.get("message", "Upload could not start."))
        return

    assigned_name = response["filename"]
    started = time.perf_counter()

    with local.open("rb") as source:
        while True:
            chunk = source.read(CHUNK_SIZE)
            if not chunk:
                break
            sock.sendall(chunk)

    result = recv_json(sock)
    elapsed = time.perf_counter() - started

    if result["status"] == "OK":
        print(f"Uploaded as: {result['filename']}")
        print(f"Bytes transferred: {result['size_bytes']}")
        print(f"Client-observed transfer time: {elapsed:.3f} seconds")
        print(f"Server throughput: {result['throughput_MBps']:.3f} MB/s")
    else:
        print(result.get("message", "Upload failed."))


def download_file(sock, remote_path, local_path=None):
    destination = Path(local_path).expanduser() if local_path else Path(Path(remote_path).name)
    send_json(sock, {"action": "download", "filename": remote_path})
    response = recv_json(sock)

    if response["status"] != "READY":
        print(response.get("message", "Download failed."))
        return

    size = int(response["size"])
    started = time.perf_counter()
    receive_exact_to_file(sock, size, destination)
    elapsed = time.perf_counter() - started
    rate = size / (1024 * 1024) / elapsed if elapsed else 0.0

    print(f"Downloaded {size} bytes to {destination}")
    print(f"Transfer time: {elapsed:.3f} seconds")
    print(f"Client-observed throughput: {rate:.3f} MB/s")


def main():
    parser = argparse.ArgumentParser(description="CNT3004 secure file-sharing client")
    parser.add_argument("--host", required=True, help="Server IP address or DNS name")
    parser.add_argument("--port", type=int, default=5001)
    parser.add_argument("--ca-cert", required=True, help="Certificate authority/server certificate PEM")
    parser.add_argument("--server-name", help="DNS name in the server certificate")
    args = parser.parse_args()

    tls_context = ssl.create_default_context(cafile=args.ca_cert)
    tls_context.minimum_version = ssl.TLSVersion.TLSv1_2

    try:
        raw_socket = socket.create_connection((args.host, args.port), timeout=30)
        with raw_socket:
            with tls_context.wrap_socket(
                raw_socket,
                server_hostname=args.server_name or args.host
            ) as sock:
                sock.settimeout(None)
                authenticate(sock)

                print("\nCommands:")
                print("  dir [SERVER_DIRECTORY]")
                print("  upload LOCAL_FILE [SERVER_PATH/TS001_name.txt]")
                print("  download SERVER_PATH [LOCAL_FILE]")
                print("  delete SERVER_PATH")
                print("  subfolder create SERVER_DIRECTORY")
                print("  subfolder delete SERVER_DIRECTORY")
                print("  quit")
                print("\nIf upload has no SERVER_PATH, the server assigns a unique type ID.")

                while True:
                    try:
                        parts = shlex.split(input("\ncloud> ").strip())
                        if not parts:
                            continue

                        command = parts[0].lower()

                        if command == "dir":
                            path = parts[1] if len(parts) > 1 else "."
                            send_json(sock, {"action": "dir", "path": path})
                            result = recv_json(sock)
                            if result["status"] == "OK":
                                show_directory(result["entries"])
                            else:
                                print(result.get("message", "Directory request failed."))

                        elif command == "upload":
                            if len(parts) not in (2, 3):
                                print("Usage: upload LOCAL_FILE [SERVER_PATH]")
                                continue
                            upload_file(
                                sock,
                                parts[1],
                                parts[2] if len(parts) == 3 else None
                            )

                        elif command == "download":
                            if len(parts) not in (2, 3):
                                print("Usage: download SERVER_PATH [LOCAL_FILE]")
                                continue
                            download_file(
                                sock,
                                parts[1],
                                parts[2] if len(parts) == 3 else None
                            )

                        elif command == "delete":
                            if len(parts) != 2:
                                print("Usage: delete SERVER_PATH")
                                continue
                            send_json(sock, {
                                "action": "delete",
                                "filename": parts[1]
                            })
                            result = recv_json(sock)
                            print(result.get("message", result["status"]))

                        elif command == "subfolder":
                            if len(parts) != 3:
                                print("Usage: subfolder create/delete PATH")
                                continue
                            operation = parts[1].lower()
                            if operation == "create":
                                action = "mkdir"
                            elif operation == "delete":
                                action = "rmdir"
                            else:
                                print("Use create or delete.")
                                continue
                            send_json(sock, {
                                "action": action,
                                "path": parts[2]
                            })
                            result = recv_json(sock)
                            print(result.get("message", result["status"]))

                        elif command in ("quit", "exit"):
                            send_json(sock, {"action": "quit"})
                            print(recv_json(sock).get("message", "Disconnected."))
                            break

                        else:
                            print("Unknown command.")

                    except (OSError, ValueError, KeyError, TypeError, ConnectionError) as exc:
                        print(f"Command failed: {exc}")
                        break

    except (OSError, ssl.SSLError, RuntimeError, PermissionError, ValueError) as exc:
        print(f"Connection failed: {exc}")


if __name__ == "__main__":
    main()
