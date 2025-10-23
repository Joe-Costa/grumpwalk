#!/usr/bin/env python3
"""
Test script for updating Iceberg table from Qumulo change notifications.

This is a simplified proof-of-concept that:
1. Creates an Iceberg table from existing parquet files
2. Listens for filesystem change events
3. Updates the Iceberg table based on events

Usage:
    # Initialize Iceberg table from existing parquet
    ./iceberg_updater_test.py --init --parquet-dir dataset4 --catalog ./iceberg_catalog

    # Listen for events and update table
    ./iceberg_updater_test.py --host music.eng.qumulo.com --path /home --catalog ./iceberg_catalog
"""

import argparse
import asyncio
import json
import logging
import ssl
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import quote

import aiohttp
import pyarrow as pa
import pyarrow.parquet as pq
from pyiceberg.catalog.sql import SqlCatalog
from pyiceberg.schema import Schema
from pyiceberg.types import (
    BooleanType,
    IntegerType,
    LongType,
    NestedField,
    StringType,
    TimestampType,
)

# Import from existing modules
from modules.credentials import credential_store_filename, get_credentials
from parquet_ingest_improved import arrow_schema, coerce_record

logging.basicConfig(
    level=logging.INFO, format="[%(levelname)s] %(message)s", stream=sys.stderr
)
logger = logging.getLogger(__name__)


class IcebergIndexUpdater:
    """Manage Iceberg table for filesystem index."""

    def __init__(self, catalog_path: Path, table_name: str = "fs_index"):
        self.catalog_path = catalog_path
        self.table_name = table_name
        self.catalog = None
        self.table = None

    def init_catalog(self):
        """Initialize SQLite-based Iceberg catalog."""
        self.catalog_path.mkdir(parents=True, exist_ok=True)
        db_path = self.catalog_path / "iceberg_catalog.db"

        logger.info(f"Initializing Iceberg catalog at {db_path}")

        self.catalog = SqlCatalog(
            "local",
            **{
                "uri": f"sqlite:///{db_path}",
                "warehouse": str(self.catalog_path / "warehouse"),
            },
        )

    def convert_arrow_schema_to_iceberg(self, arrow_schema: pa.Schema) -> Schema:
        """Convert PyArrow schema to Iceberg schema."""
        # Map PyArrow types to Iceberg types
        iceberg_fields = []
        field_id = 1

        type_mapping = {
            pa.types.is_string: lambda: StringType(),
            pa.types.is_large_string: lambda: StringType(),
            pa.types.is_int32: lambda: IntegerType(),
            pa.types.is_int64: lambda: LongType(),
            pa.types.is_boolean: lambda: BooleanType(),
            pa.types.is_timestamp: lambda: TimestampType(),
        }

        for field in arrow_schema:
            iceberg_type = None
            for check_func, type_func in type_mapping.items():
                if check_func(field.type):
                    iceberg_type = type_func()
                    break

            if iceberg_type is None:
                logger.warning(f"Skipping unsupported field type: {field.name} ({field.type})")
                continue

            iceberg_fields.append(
                NestedField(
                    field_id=field_id,
                    name=field.name,
                    field_type=iceberg_type,
                    required=False,
                )
            )
            field_id += 1

        return Schema(*iceberg_fields)

    def _convert_timestamps_to_us(self, table: pa.Table) -> pa.Table:
        """Convert timestamp columns from nanoseconds to microseconds for Iceberg compatibility."""
        import pyarrow.compute as pc

        schema = table.schema
        new_columns = []
        new_fields = []

        for i, field in enumerate(schema):
            column = table.column(i)
            if pa.types.is_timestamp(field.type):
                # Cast timestamp from ns to us
                new_column = pc.cast(column, pa.timestamp("us", tz=field.type.tz))
                new_columns.append(new_column)
                new_fields.append(pa.field(field.name, pa.timestamp("us", tz=field.type.tz)))
            else:
                new_columns.append(column)
                new_fields.append(field)

        return pa.Table.from_arrays(new_columns, schema=pa.schema(new_fields))

    def init_table_from_parquet(self, parquet_dir: Path):
        """Initialize Iceberg table from existing parquet files."""
        if self.catalog is None:
            self.init_catalog()

        # Get schema from parquet files
        arrow_sch = arrow_schema()
        iceberg_schema = self.convert_arrow_schema_to_iceberg(arrow_sch)

        # Create namespace and table
        namespace = ("default",)
        try:
            self.catalog.create_namespace(namespace)
            logger.info(f"Created namespace: {namespace}")
        except Exception as e:
            logger.debug(f"Namespace may already exist: {e}")

        table_identifier = f"default.{self.table_name}"

        try:
            # Create empty table with schema
            self.table = self.catalog.create_table(
                identifier=table_identifier, schema=iceberg_schema
            )
            logger.info(f"Created Iceberg table: {table_identifier}")

            # Load existing parquet data
            parquet_files = list(parquet_dir.glob("*.parquet"))
            logger.info(f"Found {len(parquet_files)} parquet files to import")

            # Read and append data in batches
            batch_size = 10
            for i in range(0, len(parquet_files), batch_size):
                batch = parquet_files[i : i + batch_size]
                logger.info(f"Loading batch {i//batch_size + 1}: {len(batch)} files")

                for pf in batch:
                    try:
                        table = pq.read_table(pf)
                        # Convert timestamp columns from ns to us (microseconds)
                        # Iceberg has better support for microsecond timestamps
                        table = self._convert_timestamps_to_us(table)
                        self.table.append(table)
                        logger.debug(f"Appended {pf.name}: {len(table)} rows")
                    except Exception as e:
                        logger.error(f"Failed to append {pf.name}: {e}")

            logger.info(f"Successfully initialized Iceberg table with data from {parquet_dir}")

        except Exception as e:
            logger.error(f"Failed to create/populate table: {e}")
            raise

    def load_table(self):
        """Load existing Iceberg table."""
        if self.catalog is None:
            self.init_catalog()

        table_identifier = f"default.{self.table_name}"
        try:
            self.table = self.catalog.load_table(table_identifier)
            logger.info(f"Loaded existing Iceberg table: {table_identifier}")
        except Exception as e:
            logger.error(f"Failed to load table {table_identifier}: {e}")
            raise

    def handle_file_added(self, path: str, attrs: dict):
        """Handle file/directory addition event."""
        try:
            record = coerce_record(attrs, now_ns=time.time_ns())
            table_data = pa.Table.from_pylist([record], schema=arrow_schema())
            table_data = self._convert_timestamps_to_us(table_data)
            self.table.append(table_data)
            logger.info(f"Added: {path}")
        except Exception as e:
            logger.error(f"Failed to add {path}: {e}")

    def handle_file_removed(self, path: str):
        """Handle file/directory removal event."""
        try:
            # Delete records matching the path
            self.table.delete(f"path = '{path}'")
            logger.info(f"Deleted: {path}")
        except Exception as e:
            logger.error(f"Failed to delete {path}: {e}")

    def handle_file_modified(self, path: str, attrs: dict):
        """Handle file modification event."""
        try:
            # Delete old record and insert new one (copy-on-write)
            self.table.delete(f"path = '{path}'")
            record = coerce_record(attrs, now_ns=time.time_ns())
            table_data = pa.Table.from_pylist([record], schema=arrow_schema())
            table_data = self._convert_timestamps_to_us(table_data)
            self.table.append(table_data)
            logger.info(f"Updated: {path}")
        except Exception as e:
            logger.error(f"Failed to update {path}: {e}")


class QumuloNotificationListener:
    """Listen to Qumulo SSE notification stream (simplified for testing)."""

    def __init__(self, host: str, port: int, bearer_token: str):
        self.host = host
        self.port = port
        self.base_url = f"https://{host}:{port}"
        self.bearer_token = bearer_token

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
        self, path: str, recursive: bool = True, event_filter: Optional[list] = None
    ):
        """Listen for filesystem change notifications and yield events."""
        encoded_path = quote(path, safe="")
        url = f"{self.base_url}/v1/files/{encoded_path}/notify"
        params = {"recursive": str(recursive).lower()}

        if event_filter:
            params["filter"] = ",".join(event_filter)

        logger.info(f"Connecting to {url}")
        logger.info(f"Monitoring: {path} (recursive={recursive})")

        connector = aiohttp.TCPConnector(ssl=self.ssl_context)

        async with aiohttp.ClientSession(connector=connector) as session:
            try:
                async with session.get(
                    url,
                    headers=self.headers,
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=None),
                ) as response:
                    logger.info(f"Connected! Status: {response.status}")

                    if response.status != 200:
                        error_text = await response.text()
                        logger.error(f"Response: {error_text}")
                        return

                    logger.info("Listening for events... (Press Ctrl+C to stop)")

                    async for line in response.content:
                        line = line.decode("utf-8").strip()

                        if not line or not line.startswith("data: "):
                            continue

                        data = line[6:]
                        try:
                            events = json.loads(data)
                            if isinstance(events, list):
                                for event in events:
                                    self.event_count += 1
                                    yield event
                            else:
                                self.event_count += 1
                                yield events
                        except json.JSONDecodeError as e:
                            logger.error(f"Failed to parse event: {e}")
                            continue

            except aiohttp.ClientError as e:
                logger.error(f"Connection error: {e}")
            except asyncio.CancelledError:
                logger.info("Listener stopped by user")


async def fetch_file_attributes(
    session: aiohttp.ClientSession, host: str, port: int, path: str, bearer_token: str
) -> Optional[dict]:
    """Fetch file attributes from Qumulo API."""
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    encoded_path = quote(path, safe="")
    url = f"https://{host}:{port}/v1/files/{encoded_path}/info/attributes"

    headers = {"Authorization": f"Bearer {bearer_token}"}

    try:
        async with session.get(url, headers=headers, ssl=ssl_context) as resp:
            if resp.status == 200:
                return await resp.json()
            else:
                logger.error(f"Failed to fetch attributes for {path}: {resp.status}")
                return None
    except Exception as e:
        logger.error(f"Error fetching attributes for {path}: {e}")
        return None


async def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Test Iceberg table updates from Qumulo notifications"
    )
    parser.add_argument("--init", action="store_true", help="Initialize Iceberg table")
    parser.add_argument("--parquet-dir", help="Parquet directory for initialization")
    parser.add_argument("--catalog", required=True, help="Iceberg catalog directory")
    parser.add_argument("--host", help="Qumulo cluster hostname")
    parser.add_argument("--port", type=int, default=8000, help="API port (default: 8000)")
    parser.add_argument("--path", help="Directory path to monitor")
    parser.add_argument(
        "--recursive",
        action="store_true",
        default=True,
        help="Monitor entire directory tree",
    )
    parser.add_argument("--limit", type=int, help="Limit number of events to process")

    args = parser.parse_args()

    catalog_path = Path(args.catalog)
    updater = IcebergIndexUpdater(catalog_path)

    # Initialize mode
    if args.init:
        if not args.parquet_dir:
            logger.error("--parquet-dir required with --init")
            sys.exit(1)

        parquet_dir = Path(args.parquet_dir)
        if not parquet_dir.exists():
            logger.error(f"Parquet directory not found: {parquet_dir}")
            sys.exit(1)

        updater.init_table_from_parquet(parquet_dir)
        logger.info("Initialization complete!")
        return

    # Listen mode
    if not args.host or not args.path:
        logger.error("--host and --path required for listening mode")
        sys.exit(1)

    # Load credentials
    try:
        token = get_credentials(credential_store_filename())
        if not token:
            logger.error("No credentials found. Please run grumpwalk.py first.")
            sys.exit(1)
    except Exception as e:
        logger.error(f"Failed to load credentials: {e}")
        sys.exit(1)

    # Load existing table
    updater.load_table()

    # Create listener
    listener = QumuloNotificationListener(args.host, args.port, token)

    # Process events
    event_count = 0
    connector = aiohttp.TCPConnector(ssl=listener.ssl_context)

    try:
        async with aiohttp.ClientSession(connector=connector) as session:
            async for event in listener.listen(args.path, recursive=args.recursive):
                event_count += 1
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                event_type = event.get("type", "unknown")
                path = event.get("path", "")

                logger.info(f"[{timestamp}] Event #{event_count}: {event_type} - {path}")

                # Process event based on type
                if event_type in ["child_file_added", "child_dir_added"]:
                    # Fetch attributes and add to table
                    attrs = await fetch_file_attributes(
                        session, args.host, args.port, path, token
                    )
                    if attrs:
                        updater.handle_file_added(path, attrs)

                elif event_type in ["child_file_removed", "child_dir_removed", "self_removed"]:
                    updater.handle_file_removed(path)

                elif event_type in ["child_file_moved_from", "child_dir_moved_from"]:
                    updater.handle_file_removed(path)

                elif event_type in ["child_file_moved_to", "child_dir_moved_to"]:
                    attrs = await fetch_file_attributes(
                        session, args.host, args.port, path, token
                    )
                    if attrs:
                        updater.handle_file_added(path, attrs)

                elif event_type in [
                    "child_size_changed",
                    "child_mtime_changed",
                    "child_btime_changed",
                    "child_atime_changed",
                    "child_owner_changed",
                    "child_group_changed",
                    "child_acl_changed",
                    "child_extra_attrs_changed",
                    "child_data_written",
                ]:
                    attrs = await fetch_file_attributes(
                        session, args.host, args.port, path, token
                    )
                    if attrs:
                        updater.handle_file_modified(path, attrs)

                # Check limit
                if args.limit and event_count >= args.limit:
                    logger.info(f"Reached event limit ({args.limit}), stopping...")
                    break

    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    finally:
        elapsed = time.time() - listener.start_time
        rate = event_count / elapsed if elapsed > 0 else 0
        logger.info(f"Processed {event_count} events in {elapsed:.1f}s ({rate:.2f} events/sec)")


if __name__ == "__main__":
    asyncio.run(main())
