# Parquet Index Maintenance via Qumulo Change Notifications

**IMPORTANT: No emojis anywhere in this project - code, comments, output, or documentation.**

## Overview

This document outlines the design for maintaining a live parquet index of a Qumulo filesystem using the `/v1/files/{ref}/notify` API endpoint. After the initial expensive crawl with `grumpwalk.py`, this system will keep the 1.3GB parquet index current by listening for change notifications and updating only affected entries.

## API Analysis

### Endpoint: `/v1/files/{ref}/notify`

**Method:** GET
**Protocol:** Server-Sent Events (SSE)
**Authentication:** Bearer token

**Parameters:**
- `ref` (required): File ID or absolute path (URL-encoded) to monitor
- `filter` (optional): CSV list of event types to receive
- `recursive` (optional): Boolean - monitor entire directory tree vs immediate children only

**Event Types Available:**
```
File/Directory Operations:
- child_file_added
- child_dir_added
- child_file_removed
- child_dir_removed
- child_file_moved_from
- child_file_moved_to
- child_dir_moved_from
- child_dir_moved_to

Metadata Changes:
- child_btime_changed (birth time)
- child_mtime_changed (modification time)
- child_atime_changed (access time)
- child_size_changed
- child_extra_attrs_changed
- child_acl_changed
- child_owner_changed
- child_group_changed

Data Operations:
- child_data_written

Stream Operations:
- child_stream_added
- child_stream_removed
- child_stream_moved_from
- child_stream_moved_to
- child_stream_size_changed
- child_stream_data_written

Other:
- self_removed (monitored directory deleted)
```

**Response Format:**
SSE stream with JSON events: `[{"type": <string>, "path": <string>, "stream_name": <optional string>}]`

## Architecture Options

### Option 1: Simple Parquet Append/Rewrite (Simplest)

**Approach:** Maintain a "changelog" parquet file and periodically merge with main dataset.

**Pros:**
- Simple implementation
- No external dependencies
- Works with existing tooling

**Cons:**
- Query complexity increases (need to UNION changelog)
- Periodic compaction required
- Deletions handled via tombstone records
- Not real-time for queries

**Implementation:**
```python
# 1. Listen for events
# 2. Fetch attributes via grumpwalk or direct API
# 3. Append to changelog.parquet
# 4. Periodic merge: read main + changelog, dedupe, rewrite
```

### Option 2: Apache Iceberg (Best for Production)

**Approach:** Use Apache Iceberg for ACID transactions and time-travel on parquet files.

**Pros:**
- True ACID updates/deletes
- Schema evolution support
- Time-travel queries
- Efficient incremental updates
- Snapshot isolation
- No need to rewrite entire files

**Cons:**
- Requires Iceberg library (`pip install pyiceberg`)
- More complex initial setup
- Needs metadata catalog (can be local filesystem)

**Implementation:**
```python
from pyiceberg.catalog import load_catalog
from pyiceberg.table import Table

# 1. Convert existing parquet to Iceberg table
# 2. Listen for events
# 3. Use Iceberg API for updates/deletes
# 4. Queries automatically see latest snapshot
```

### Option 3: Delta Lake (Alternative to Iceberg)

**Approach:** Use Delta Lake for versioned parquet storage.

**Pros:**
- ACID transactions
- Time travel
- Schema enforcement
- Good Python support (`pip install deltalake`)

**Cons:**
- Similar complexity to Iceberg
- Another framework choice

### Option 4: DuckDB Persistent Database (Hybrid)

**Approach:** Use DuckDB as persistent storage, export to parquet periodically.

**Pros:**
- Efficient updates/deletes
- SQL-based operations
- Can still export to parquet
- Simple schema

**Cons:**
- Different storage format during updates
- Need export step for parquet

## Recommended Architecture: Apache Iceberg

I recommend **Apache Iceberg** for the following reasons:

1. **Native Parquet Support:** Iceberg is built on top of parquet, no format conversion
2. **ACID Operations:** True updates and deletes without rewriting entire files
3. **Efficient:** Only writes changed data
4. **Query Compatible:** DuckDB can query Iceberg tables directly
5. **Production Ready:** Used by major companies (Netflix, Apple, Adobe)
6. **Time Travel:** Can query index at any point in time

## Implementation Plan

### Phase 1: Notification Listener

Create `notify_listener.py`:

```python
#!/usr/bin/env python3
"""
Listen for Qumulo filesystem change notifications and maintain parquet index.
"""

import asyncio
import aiohttp
import ssl
import json
from typing import AsyncIterator, Dict, Any
from pathlib import Path

class QumuloNotificationListener:
    """Listen to Qumulo SSE notification stream."""

    def __init__(self, host: str, port: int, bearer_token: str):
        self.host = host
        self.port = port
        self.base_url = f"https://{host}:{port}"
        self.bearer_token = bearer_token

        # SSL context for self-signed certs
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE

        self.headers = {
            "Accept": "text/event-stream",
            "Authorization": f"Bearer {bearer_token}",
        }

    async def listen(
        self,
        path: str,
        recursive: bool = True,
        event_filter: list[str] | None = None,
    ) -> AsyncIterator[Dict[str, Any]]:
        """
        Listen for filesystem change notifications.

        Args:
            path: Directory path to monitor
            recursive: Monitor entire tree vs immediate children
            event_filter: List of event types to receive (None = all)

        Yields:
            Parsed JSON event dictionaries
        """
        # URL encode the path
        from urllib.parse import quote
        encoded_path = quote(path, safe='')

        url = f"{self.base_url}/v1/files/{encoded_path}/notify"
        params = {"recursive": str(recursive).lower()}

        if event_filter:
            params["filter"] = ",".join(event_filter)

        async with aiohttp.ClientSession() as session:
            async with session.get(
                url,
                headers=self.headers,
                ssl=self.ssl_context,
                params=params,
                timeout=aiohttp.ClientTimeout(total=None),  # No timeout for SSE
            ) as response:
                response.raise_for_status()

                # Parse SSE stream
                async for line in response.content:
                    line = line.decode('utf-8').strip()

                    # SSE format: "data: <json>"
                    if line.startswith('data: '):
                        data = line[6:]  # Remove "data: " prefix
                        try:
                            events = json.loads(data)
                            # API returns array of events
                            if isinstance(events, list):
                                for event in events:
                                    yield event
                            else:
                                yield events
                        except json.JSONDecodeError as e:
                            print(f"Failed to parse event: {e}")
                            continue
```

### Phase 2: Attribute Fetcher

Reuse grumpwalk's client or add direct attribute fetching:

```python
from modules.client import AsyncQumuloClient

class AttributeFetcher:
    """Fetch file attributes for changed files."""

    def __init__(self, client: AsyncQumuloClient):
        self.client = client

    async def get_attributes(self, session: aiohttp.ClientSession, path: str) -> Dict[str, Any]:
        """
        Fetch full attributes for a file path.

        Returns attributes in grumpwalk --json --all-attributes format.
        """
        # Use existing get_file_attributes method or similar
        # This should return the same schema as grumpwalk.py outputs
        from urllib.parse import quote
        encoded_path = quote(path, safe='')
        url = f"{self.client.base_url}/v1/files/{encoded_path}/info/attributes"

        async with session.get(url, headers=self.client.headers, ssl=self.client.ssl_context) as resp:
            resp.raise_for_status()
            return await resp.json()
```

### Phase 3: Iceberg Index Updater

```python
from pyiceberg.catalog import load_catalog
from pyiceberg.table import Table
import pyarrow as pa
from parquet_ingest import coerce_record, arrow_schema
import time

class IcebergIndexUpdater:
    """Update Iceberg table based on filesystem events."""

    def __init__(self, catalog_path: Path, table_name: str = "fs_index"):
        # Initialize Iceberg catalog (local filesystem)
        self.catalog = load_catalog(
            "local",
            **{
                "type": "rest",
                "uri": f"file://{catalog_path}",
            }
        )
        self.table_name = table_name
        self.table = None

    def init_table(self, parquet_dir: Path):
        """Initialize Iceberg table from existing parquet files."""
        # Convert existing parquet dataset to Iceberg
        # This is a one-time operation
        self.table = self.catalog.create_table_from_parquet(
            identifier=self.table_name,
            file_paths=[str(f) for f in parquet_dir.glob("*.parquet")],
            schema=arrow_schema(),
        )

    async def handle_event(self, event: Dict[str, Any], fetcher: AttributeFetcher, session):
        """Process a single filesystem event and update index."""
        event_type = event["type"]
        path = event["path"]

        if event_type in ["child_file_added", "child_dir_added"]:
            # Fetch attributes and insert
            attrs = await fetcher.get_attributes(session, path)
            record = coerce_record(attrs, now_ns=time.time_ns())

            # Insert into Iceberg table
            df = pa.Table.from_pylist([record], schema=arrow_schema())
            self.table.append(df)

        elif event_type in ["child_file_removed", "child_dir_removed", "self_removed"]:
            # Delete from Iceberg table
            self.table.delete(f"path = '{path}'")

        elif event_type in ["child_file_moved_from", "child_dir_moved_from"]:
            # Mark old path as deleted (will get added event for new path)
            self.table.delete(f"path = '{path}'")

        elif event_type in ["child_file_moved_to", "child_dir_moved_to"]:
            # Fetch and insert at new location
            attrs = await fetcher.get_attributes(session, path)
            record = coerce_record(attrs, now_ns=time.time_ns())
            df = pa.Table.from_pylist([record], schema=arrow_schema())
            self.table.append(df)

        elif event_type in [
            "child_size_changed",
            "child_mtime_changed",
            "child_btime_changed",
            "child_atime_changed",
            "child_owner_changed",
            "child_group_changed",
            "child_acl_changed",
            "child_extra_attrs_changed",
        ]:
            # Update record - fetch new attributes
            attrs = await fetcher.get_attributes(session, path)
            record = coerce_record(attrs, now_ns=time.time_ns())

            # Iceberg update: delete old + insert new (copy-on-write)
            self.table.delete(f"path = '{path}'")
            df = pa.Table.from_pylist([record], schema=arrow_schema())
            self.table.append(df)
```

### Phase 4: Main Application

```python
async def main():
    """Main event loop."""
    import argparse
    from modules.auth import get_bearer_token

    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--path", required=True, help="Directory to monitor")
    parser.add_argument("--recursive", action="store_true", default=True)
    parser.add_argument("--index-dir", required=True, help="Iceberg catalog directory")
    parser.add_argument("--init", action="store_true", help="Initialize from existing parquet")
    parser.add_argument("--parquet-dir", help="Existing parquet directory (for --init)")
    args = parser.parse_args()

    # Get authentication token
    token = get_bearer_token(args.host, args.port)

    # Initialize components
    listener = QumuloNotificationListener(args.host, args.port, token)
    client = AsyncQumuloClient(args.host, args.port, token)
    fetcher = AttributeFetcher(client)
    updater = IcebergIndexUpdater(Path(args.index_dir))

    # Initialize table if requested
    if args.init:
        if not args.parquet_dir:
            print("--parquet-dir required with --init")
            return
        updater.init_table(Path(args.parquet_dir))
        print(f"Initialized Iceberg table from {args.parquet_dir}")

    # Start listening
    print(f"Monitoring {args.path} (recursive={args.recursive})")

    async with client.create_session() as session:
        async for event in listener.listen(args.path, recursive=args.recursive):
            try:
                await updater.handle_event(event, fetcher, session)
                print(f"Processed: {event['type']} - {event['path']}")
            except Exception as e:
                print(f"Error processing event {event}: {e}")
                # Continue processing other events

if __name__ == "__main__":
    asyncio.run(main())
```

## Alternative: Simpler Append-Only Approach (No Iceberg)

If Iceberg is too complex, here's a simpler approach:

```python
class SimpleParquetUpdater:
    """Simpler approach: append to changelog, periodic compaction."""

    def __init__(self, dataset_dir: Path):
        self.dataset_dir = dataset_dir
        self.changelog_dir = dataset_dir / "changelog"
        self.changelog_dir.mkdir(exist_ok=True)
        self.batch = []
        self.batch_size = 1000

    async def handle_event(self, event: Dict, fetcher, session):
        """Append event to changelog."""
        event_type = event["type"]
        path = event["path"]

        if event_type.endswith("_removed"):
            # Write tombstone record
            record = {
                "path": path,
                "_deleted": True,
                "ingest_ts": time.time_ns(),
            }
        else:
            # Fetch attributes
            attrs = await fetcher.get_attributes(session, path)
            record = coerce_record(attrs, now_ns=time.time_ns())
            record["_deleted"] = False

        self.batch.append(record)

        if len(self.batch) >= self.batch_size:
            self.flush_batch()

    def flush_batch(self):
        """Write batch to changelog parquet."""
        if not self.batch:
            return

        table = pa.Table.from_pylist(self.batch, schema=arrow_schema())
        fname = self.changelog_dir / f"changelog-{int(time.time()*1000)}.parquet"
        pq.write_table(table, fname, compression="zstd")

        print(f"Wrote {len(self.batch)} changes to {fname}")
        self.batch.clear()

    def compact(self):
        """Periodic compaction: merge changelog with main dataset."""
        import duckdb

        # Query that deduplicates and handles deletions
        con = duckdb.connect()
        con.execute(f"""
            CREATE OR REPLACE TABLE merged AS
            WITH all_records AS (
                -- Main dataset
                SELECT *, false as _deleted
                FROM read_parquet('{self.dataset_dir}/*.parquet')

                UNION ALL

                -- Changelog
                SELECT *
                FROM read_parquet('{self.changelog_dir}/*.parquet')
            ),
            latest AS (
                SELECT *, ROW_NUMBER() OVER (PARTITION BY path ORDER BY ingest_ts DESC) as rn
                FROM all_records
            )
            SELECT * EXCLUDE(rn, _deleted)
            FROM latest
            WHERE rn = 1 AND NOT _deleted
        """)

        # Write compacted result
        compacted_dir = self.dataset_dir / "compacted"
        compacted_dir.mkdir(exist_ok=True)

        con.execute(f"""
            COPY merged TO '{compacted_dir}' (FORMAT PARQUET, PARTITION_BY (date_trunc('month', modification_time)))
        """)

        print(f"Compacted to {compacted_dir}")
```

## Query Integration

### With Iceberg:
```python
# DuckDB can query Iceberg tables directly
import duckdb
con = duckdb.connect()
con.execute("INSTALL iceberg; LOAD iceberg;")
con.execute("SELECT * FROM iceberg_scan('path/to/catalog', 'fs_index') WHERE size > 1000000")
```

### With Simple Approach:
```python
# Query with changelog merged
con.execute("""
    WITH all_data AS (
        SELECT *, false as _deleted FROM read_parquet('dataset/*.parquet')
        UNION ALL
        SELECT * FROM read_parquet('dataset/changelog/*.parquet')
    ),
    latest AS (
        SELECT *, ROW_NUMBER() OVER (PARTITION BY path ORDER BY ingest_ts DESC) as rn
        FROM all_data
    )
    SELECT * FROM latest WHERE rn = 1 AND NOT _deleted
""")
```

## Deployment Considerations

1. **Resilience:** Use systemd or supervisor to keep listener running
2. **Reconnection:** Handle SSE disconnections and reconnect automatically
3. **Logging:** Log all events for debugging
4. **Monitoring:** Track event processing rate, backlog size
5. **Checkpointing:** Track last processed event to resume after restart
6. **Error Handling:** Retry failed attribute fetches
7. **Rate Limiting:** If events come too fast, batch updates

## Recommended Next Steps

1. **Prototype:** Implement simple notification listener (Phase 1)
2. **Test:** Connect to your cluster and verify events are received
3. **Choose Storage:** Decide between Iceberg (recommended) or simple append
4. **Integration:** Connect with parquet_ingest.py schema
5. **Deploy:** Run continuously, monitor for 24-48 hours
6. **Optimize:** Add batching, error handling, reconnection logic

## Conclusion

The Qumulo `/v1/files/{ref}/notify` API provides a robust foundation for maintaining a live parquet index. Apache Iceberg is the recommended storage layer for production use, offering ACID transactions and efficient updates. For simpler use cases, an append-only changelog with periodic compaction is a viable alternative.

The implementation can reuse existing grumpwalk infrastructure for authentication and attribute fetching, minimizing new code while providing real-time index maintenance.
