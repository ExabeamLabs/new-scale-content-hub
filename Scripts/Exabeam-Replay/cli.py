#!/usr/bin/env python3
"""Command-line interface for raw collector replay."""
from __future__ import annotations

import argparse
import json
import queue
from pathlib import Path

from replay_core import ReplayEngine, prepare_source


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "Replay raw log records without parsing or rewriting their message content. "
            "Syslog TCP/TLS use RFC 6587 octet-counting framing."
        )
    )
    p.add_argument("source", type=Path, help="Input log file; replayed from disk as raw records")
    p.add_argument(
        "--destination",
        default="dry-run",
        choices=["dry-run", "webhook-collector", "syslog-udp", "syslog-tcp", "syslog-tls"],
    )
    p.add_argument("--webhook-url", default="", help="Webhook Cloud Collector URL")
    p.add_argument("--token", default="", help="Webhook bearer token")
    p.add_argument("--host", default="", help="Syslog collector host")
    p.add_argument("--port", type=int, default=None, help="Syslog collector port")
    p.add_argument("--insecure-tls", action="store_true", help="Disable certificate verification for Syslog TLS")
    p.add_argument("--ca-file", default="", help="Optional CA bundle for Syslog TLS")
    p.add_argument("--batch-size", type=int, default=1, help="Physical source records per send operation")
    p.add_argument("--eps-cap", type=int, default=0, help="Physical source records per second; 0 is unlimited")
    p.add_argument("--loops", type=int, default=1, help="Number of complete passes; 0 means infinite")
    p.add_argument("--timeout", type=int, default=15)
    p.add_argument("--report-dir", default="reports")
    p.add_argument("--validate", action="store_true", help="Verify source access and print exact-byte metadata")
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.port is None:
        args.port = 514 if args.destination in {"syslog-udp", "syslog-tcp"} else 6514

    config = {
        "source_path": str(args.source),
        "exact_passthrough": True,
        "format": "exact-bytes",
        "boundary": "physical-line",
        "destination": ("webhook" if args.destination == "webhook-collector" else args.destination.replace("-", "_")) if args.destination != "dry-run" else "syslog_tls",
        "dry_run": args.destination == "dry-run",
        "webhook_url": args.webhook_url,
        "webhook_token": args.token,
        "webhook_content_type": "application/octet-stream",
        "host": args.host,
        "port": args.port,
        "framing": "none",
        "verify_tls": True if args.destination == "webhook-collector" else not args.insecure_tls,
        "ca_file": "" if args.destination == "webhook-collector" else args.ca_file,
        "batch_size": args.batch_size,
        "speed": 1.0,
        "eps_cap": args.eps_cap,
        "ts_rewrite": False,
        "loop": args.loops != 1,
        "loop_max": args.loops,
        "timeout": args.timeout,
        "retries": 0,
        "stop_on_failure": True,
        "report_dir": args.report_dir,
    }
    if args.validate:
        _, count, _, source_hash, mode = prepare_source(config)
        print(
            json.dumps(
                {
                    "mode": mode,
                    "records": count,
                    "bytes": args.source.stat().st_size,
                    "sha256": source_hash,
                    "source_modifications": "none",
                    "stream_boundary": "Syslog TCP/TLS use RFC 6587 octet counting; UDP and Webhook preserve source payload bytes",
                },
                indent=2,
            )
        )
        return 0

    events = queue.Queue()
    engine = ReplayEngine(config, events)
    engine.start()
    while engine.alive or not events.empty():
        try:
            item = events.get(timeout=0.1)
        except queue.Empty:
            continue
        if item["kind"] == "log":
            print(f"[{item['level'].upper()}] {item['msg']}")
        elif item["kind"] == "progress":
            print(
                f"\r{item['current_index']}/{item['total']} "
                f"sent={item['sent']} failed={item['errors']}",
                end="",
                flush=True,
            )
        elif item["kind"] == "done":
            print()
            print(json.dumps(item["summary"], indent=2))
    engine.join()
    return 0 if engine.summary and engine.summary.status == "completed" and engine.summary.records_failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
