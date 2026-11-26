# Cloud-Server-Network-Analysis-Project

### Project by Mason Lucier, Noah Nguyen, Richard Toms

## Files
- `server.py`: threaded TCP file server, challenge-response authentication, file operations, and server-side performance logging.
- `client.py`: interactive client for connecting, uploading, downloading, listing, deleting, and managing subfolders.
- `analysis.py`: summarizes transfer metrics from the server CSV log.
- `storage/`: server-side file storage.
- `users.json`: generated credential verifier database (do not commit this file).

## Requirements
- Python 3.9 or newer
- No third-party Python packages required

## 1. Create a server account
Run this on the server computer / Google Cloud VM:

```bash
python server.py --create-user YOUR_USERNAME
```

Enter and confirm a password when prompted. The password is not stored in the file; a salted PBKDF2 verifier is stored in `users.json`.

## 2. Start the server

```bash
python server.py --host 0.0.0.0 --port 5001
```

Allow inbound TCP traffic to port 5001 in the VM firewall / cloud firewall, and restrict the source IP ranges to your client machines where possible.

## 3. Connect from a client

```bash
python client.py --host SERVER_PUBLIC_IP --port 5001
```

Enter the account username and password.

## 4. Client commands

```text
dir
dir subfolder
upload local_file.txt
upload C:\Users\Student\Documents\report.pdf reports/report.pdf
download reports/report.pdf
download reports/report.pdf downloaded_report.pdf
delete reports/report.pdf
subfolder create reports
subfolder delete empty_folder
quit
```

Paths supplied to the server are relative to its `storage/` directory. The server prevents paths from escaping that directory. Directory deletion only succeeds when the directory is empty.

## 5. Analyze performance

After uploads/downloads, run:

```bash
python analysis.py
```

The server writes `network_metrics.csv` with operation, filename, bytes transferred, transfer duration, throughput, and response time.

## Important security notes
- Authentication uses a random challenge and HMAC proof; the password itself is not sent over the socket.
- This baseline does not encrypt file contents or command traffic. For use over an untrusted network, deploy the connection through TLS (for example, configure an SSL/TLS wrapper with a trusted certificate) or a protected VPN.
- Do not commit `users.json`, passwords, private keys, or certificates to GitHub. Add `users.json`, `network_metrics.csv`, and temporary files to `.gitignore`.
- Use only test files and accounts approved for your class project.
- The assignment's large-file size targets should be tested with generated test files. Avoid committing multi-gigabyte test files to Git.

