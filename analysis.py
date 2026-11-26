#!/usr/bin/env python3
"""Offline analysis of server-side transfer and response-time measurements."""

import argparse
import csv
import statistics
from collections import defaultdict
from pathlib import Path


def load_metrics(csv_path):
    rows = []
    with Path(csv_path).open("r", newline="", encoding="utf-8") as file:
        for row in csv.DictReader(file):
            try:
                rows.append({
                    "timestamp": row.get("timestamp", ""),
                    "operation": row["operation"],
                    "filename": row.get("filename", ""),
                    "size_bytes": int(row.get("size_bytes") or 0),
                    "transfer_seconds": float(row.get("transfer_seconds") or 0),
                    "throughput_MBps": float(row.get("throughput_MBps") or 0),
                    "response_seconds": float(row.get("response_seconds") or 0)
                })
            except (KeyError, ValueError):
                continue
    return rows


def average(values):
    return statistics.mean(values) if values else 0.0


def report(rows):
    if not rows:
        print("No metrics have been recorded yet.")
        return

    print("\nCNT3004 NETWORK PERFORMANCE REPORT")
    print("=" * 52)
    print(f"Total recorded operations: {len(rows)}")

    grouped = defaultdict(list)
    for row in rows:
        grouped[row["operation"]].append(row)

    for operation in ("upload", "download"):
        selected = grouped.get(operation, [])
        if not selected:
            print(f"\nNo {operation} records found.")
            continue

        sizes = [row["size_bytes"] for row in selected]
        durations = [row["transfer_seconds"] for row in selected]
        rates = [row["throughput_MBps"] for row in selected]
        responses = [row["response_seconds"] for row in selected]

        print(f"\n{operation.upper()} PERFORMANCE")
        print("-" * 52)
        print(f"Number of transfers:       {len(selected)}")
        print(f"Total data transferred:    {sum(sizes) / (1024 ** 2):.2f} MB")
        print(f"Average transfer time:     {average(durations):.4f} seconds")
        print(f"Average throughput:        {average(rates):.4f} MB/s")
        print(f"Median throughput:         {statistics.median(rates):.4f} MB/s")
        print(f"Average response time:     {average(responses):.4f} seconds")

    other_operations = [
        row for row in rows if row["operation"] not in ("upload", "download")
    ]
    if other_operations:
        response_times = [row["response_seconds"] for row in other_operations]
        print("\nOTHER COMMAND RESPONSE TIMES")
        print("-" * 52)
        print(f"Number of commands:        {len(other_operations)}")
        print(f"Average response time:     {average(response_times):.6f} seconds")

    print("\nINDIVIDUAL TRANSFERS")
    print("-" * 80)
    print(f"{'OPERATION':<12} {'FILE':<32} {'MB':>10} {'SECONDS':>12} {'MB/s':>10}")
    for row in rows:
        if row["operation"] in ("upload", "download"):
            print(
                f"{row['operation']:<12} "
                f"{row['filename'][:32]:<32} "
                f"{row['size_bytes'] / (1024 ** 2):>10.2f} "
                f"{row['transfer_seconds']:>12.4f} "
                f"{row['throughput_MBps']:>10.3f}"
            )


def main():
    parser = argparse.ArgumentParser(description="Analyze CNT3004 network metrics")
    parser.add_argument(
        "--file",
        default=str(Path(__file__).resolve().parent / "network_metrics.csv")
    )
    args = parser.parse_args()

    csv_path = Path(args.file)
    if not csv_path.exists():
        raise SystemExit(f"Metrics file not found: {csv_path}")

    report(load_metrics(csv_path))


if __name__ == "__main__":
    main()
