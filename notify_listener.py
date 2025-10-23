#!/usr/bin/env python3
"""
Prototype: Listen for Qumulo filesystem change notifications.

Usage:
    ./notify_listener.py --host music.eng.qumulo.com --path /home --recursive
"""

import argparse
import asyncio
import json
import ssl
import sys
import time
from datetime import datetime
from typing import Optional
from urllib.parse import quote

try:
    import aiohttp
except ImportError:
    print("[ERROR] aiohttp not installed. Install with: pip install aiohttp", file=sys.stderr)
    sys.exit(1)

# Import authentication from grumpwalk modules
from modules.credentials import get_credentials, credential_store_filename


class QumuloNotificationListener:
    """Listen to Qumulo SSE notification stream."""

    def __init__(self, host: str, port: int, bearer_token: str, verbose: bool = False):
        self.host = host
        self.port = port
        self.base_url = f"https://{host}:{port}"
        self.bearer_token = bearer_token
        self.verbose = verbose

        # SSL context for self-signed certs
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE

        self.headers = {
            "Accept": "text/event-stream",
            "Authorization": f"Bearer {bearer_token}",
        }

        self.event_count = 0
        self.start_time = time.time()

    async def listen(
        self,
        path: str,
        recursive: bool = True,
        event_filter: Optional[list] = None,
    ):
        """
        Listen for filesystem change notifications.

        Args:
            path: Directory path to monitor
            recursive: Monitor entire tree vs immediate children
            event_filter: List of event types to receive (None = all)
        """
        # URL encode the path
        encoded_path = quote(path, safe='')

        url = f"{self.base_url}/v1/files/{encoded_path}/notify"
        params = {"recursive": str(recursive).lower()}

        if event_filter:
            params["filter"] = ",".join(event_filter)

        print(f"[INFO] Connecting to {url}", file=sys.stderr)
        print(f"[INFO] Parameters: {params}", file=sys.stderr)
        print(f"[INFO] Monitoring: {path} (recursive={recursive})", file=sys.stderr)
        print("=" * 80, file=sys.stderr)

        connector = aiohttp.TCPConnector(ssl=self.ssl_context)

        async with aiohttp.ClientSession(connector=connector) as session:
            try:
                async with session.get(
                    url,
                    headers=self.headers,
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=None),  # No timeout for SSE
                ) as response:
                    print(f"[INFO] Connected! Status: {response.status}", file=sys.stderr)

                    if response.status != 200:
                        error_text = await response.text()
                        print(f"[ERROR] Response: {error_text}", file=sys.stderr)
                        return

                    print(f"[INFO] Listening for events... (Press Ctrl+C to stop)", file=sys.stderr)
                    print("=" * 80, file=sys.stderr)

                    # Parse SSE stream
                    async for line in response.content:
                        line = line.decode('utf-8').strip()

                        if not line:
                            continue

                        # SSE format: "data: <json>"
                        if line.startswith('data: '):
                            data = line[6:]  # Remove "data: " prefix
                            try:
                                events = json.loads(data)
                                # API returns array of events
                                if isinstance(events, list):
                                    for event in events:
                                        self.handle_event(event)
                                else:
                                    self.handle_event(events)
                            except json.JSONDecodeError as e:
                                print(f"[ERROR] Failed to parse event: {e}", file=sys.stderr)
                                if self.verbose:
                                    print(f"[DEBUG] Raw data: {data}", file=sys.stderr)
                                continue

            except aiohttp.ClientError as e:
                print(f"[ERROR] Connection error: {e}", file=sys.stderr)
            except asyncio.CancelledError:
                print(f"\n[INFO] Listener stopped by user", file=sys.stderr)
            except Exception as e:
                print(f"[ERROR] Unexpected error: {e}", file=sys.stderr)
                raise

    def handle_event(self, event: dict):
        """Process and display a single event."""
        self.event_count += 1

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        event_type = event.get("type", "unknown")
        path = event.get("path", "")
        stream_name = event.get("stream_name", "")

        # Format event for display
        print(f"[{timestamp}] Event #{self.event_count}")
        print(f"  Type: {event_type}")
        print(f"  Path: {path}")
        if stream_name:
            print(f"  Stream: {stream_name}")

        if self.verbose:
            print(f"  Raw: {json.dumps(event)}")

        print()
        sys.stdout.flush()

    def print_stats(self):
        """Print statistics about events received."""
        elapsed = time.time() - self.start_time
        rate = self.event_count / elapsed if elapsed > 0 else 0

        print("\n" + "=" * 80, file=sys.stderr)
        print(f"[STATS] Total events: {self.event_count}", file=sys.stderr)
        print(f"[STATS] Elapsed time: {elapsed:.1f}s", file=sys.stderr)
        print(f"[STATS] Event rate: {rate:.2f} events/sec", file=sys.stderr)
        print("=" * 80, file=sys.stderr)


async def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Listen for Qumulo filesystem change notifications"
    )
    parser.add_argument("--host", required=True, help="Qumulo cluster hostname")
    parser.add_argument("--port", type=int, default=8000, help="API port (default: 8000)")
    parser.add_argument("--path", required=True, help="Directory path to monitor")
    parser.add_argument(
        "--recursive",
        action="store_true",
        default=False,
        help="Monitor entire directory tree (default: immediate children only)",
    )
    parser.add_argument(
        "--filter",
        nargs="+",
        help="Event types to monitor (e.g., child_file_added child_file_removed)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output (show raw events)",
    )

    args = parser.parse_args()

    # Get authentication token from credentials file
    print(f"[INFO] Loading credentials...", file=sys.stderr)
    try:
        token = get_credentials(credential_store_filename())
        if not token:
            print(f"[ERROR] No credentials found. Please run grumpwalk.py first to authenticate.", file=sys.stderr)
            sys.exit(1)
        print(f"[INFO] Credentials loaded successfully", file=sys.stderr)
    except Exception as e:
        print(f"[ERROR] Failed to load credentials: {e}", file=sys.stderr)
        sys.exit(1)

    # Create listener
    listener = QumuloNotificationListener(
        args.host,
        args.port,
        token,
        verbose=args.verbose,
    )

    # Start listening
    try:
        await listener.listen(
            args.path,
            recursive=args.recursive,
            event_filter=args.filter,
        )
    except KeyboardInterrupt:
        print("\n[INFO] Interrupted by user", file=sys.stderr)
    finally:
        listener.print_stats()


if __name__ == "__main__":
    asyncio.run(main())
