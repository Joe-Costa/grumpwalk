#!/usr/bin/env python3
"""
parquet_ingest.py - Ingest file-crawler NDJSON to Parquet and run fast queries.

Features:
- Ingest NDJSON lines (stdin or files), coerce to a strong schema, write Parquet (ZSTD).
- Roll large ingests into multiple Parquet files (configurable batch size).
- Query Parquet directly with DuckDB SQL (no DB server; scans Parquet in-place).

Usage examples (assuming Python 3.10+):

  # 1) Ingest from a file to a dataset directory (creates .parquet files)
  python parquet_ingest.py ingest \
      --input crawl.ndjson \
      --out-dir ./dataset \
      --rows-per-file 250000

  # Or pipe from rsyslog/your crawler:
  cat crawl.ndjson | python parquet_ingest.py ingest --out-dir ./dataset

  # 2) Run a SQL query (results to stdout)
  python parquet_ingest.py query \
      --data ./dataset \
      --sql "SELECT name, size, owner FROM files ORDER BY size DESC LIMIT 20"

  # 3) Write query results to CSV
  python parquet_ingest.py query \
      --data ./dataset \
      --sql "SELECT date_trunc('day', access_time) AS day, count(*) AS files \
             FROM files GROUP BY day ORDER BY day DESC LIMIT 30" \
      --out-csv top_by_day.csv

  # 4) Show dataset statistics
  python parquet_ingest.py stats --data ./dataset
"""

from __future__ import annotations
import argparse
import datetime as dt
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import pyarrow as pa
import pyarrow.parquet as pq
import duckdb

# Try to use ujson for faster parsing (like grumpwalk does)
try:
    import ujson as json
except ImportError:
    import json

# pandas used in query command
import pandas as pd

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s',
    stream=sys.stderr
)
logger = logging.getLogger(__name__)


# -----------------------------
# Schema & coercion
# -----------------------------


def arrow_schema() -> pa.schema:
    """Return the Arrow schema used for Parquet writing."""
    return pa.schema(
        [
            ("path", pa.large_string()),
            ("name", pa.large_string()),
            ("num_links", pa.int32()),
            ("type", pa.string()),
            ("major_minor_major", pa.int32()),
            ("major_minor_minor", pa.int32()),
            ("symlink_target_type", pa.string()),
            ("id", pa.large_string()),
            ("file_number", pa.large_string()),
            ("mode", pa.int32()),
            ("owner", pa.int64()),
            ("owner_id_type", pa.string()),
            ("owner_id_value", pa.large_string()),
            ("group", pa.int64()),
            ("group_id_type", pa.string()),
            ("group_id_value", pa.large_string()),
            ("blocks", pa.int64()),
            ("datablocks", pa.int64()),
            ("metablocks", pa.int64()),
            ("size", pa.int64()),
            ("access_time", pa.timestamp("ns")),
            ("modification_time", pa.timestamp("ns")),
            ("change_time", pa.timestamp("ns")),
            ("creation_time", pa.timestamp("ns")),
            ("child_count", pa.int32()),
            ("ea_read_only", pa.bool_()),
            ("ea_hidden", pa.bool_()),
            ("ea_system", pa.bool_()),
            ("ea_archive", pa.bool_()),
            ("ea_temporary", pa.bool_()),
            ("ea_compressed", pa.bool_()),
            ("ea_not_content_indexed", pa.bool_()),
            ("ea_sparse_file", pa.bool_()),
            ("ea_offline", pa.bool_()),
            ("directory_entry_hash_policy", pa.string()),
            ("data_revision", pa.int64()),
            ("user_metadata_revision", pa.int64()),
            ("ingest_ts", pa.timestamp("ns")),
        ]
    )


def _parse_int(s: Any) -> Optional[int]:
    """Parse value to integer, return None on failure."""
    if s is None:
        return None
    if isinstance(s, int):
        return s
    if isinstance(s, str) and s.strip() != "":
        try:
            return int(s)
        except ValueError:
            return None
    return None


def _parse_octal_mode(s: Any) -> Optional[int]:
    """Convert mode strings like '0777' to int(0o777)."""
    if s is None:
        return None
    if isinstance(s, int):
        return s
    if isinstance(s, str):
        try:
            return int(s, 8)  # Works for both '0777' and '777'
        except ValueError:
            return None
    return None


def _parse_ts(iso: Any) -> Optional[dt.datetime]:
    """Parse ISO 8601 / RFC 3339 timestamp with nanoseconds."""
    if not iso or not isinstance(iso, str):
        return None
    try:
        if iso.endswith("Z"):
            iso = iso[:-1] + "+00:00"
        # Python can parse up to 6 microseconds; trim nanoseconds if present
        if "." in iso:
            head, tail = iso.split(".", 1)
            tz_part = ""
            if "+" in tail or "-" in tail:
                for i in range(len(tail) - 1, -1, -1):
                    if tail[i] in "+-":
                        frac = tail[:i]
                        tz_part = tail[i:]
                        break
                else:
                    frac = tail
            else:
                frac = tail
            frac = (frac + "000000")[:6]
            iso = f"{head}.{frac}{tz_part}"
        return dt.datetime.fromisoformat(iso)
    except Exception:
        return None


def coerce_record(d: Dict[str, Any], now_ns: int) -> Dict[str, Any]:
    """Map the crawler JSON to our flattened schema with correct types."""
    mm = d.get("major_minor_numbers") or {}
    owner_details = d.get("owner_details") or {}
    group_details = d.get("group_details") or {}
    ea = d.get("extended_attributes") or {}

    # Deduplicate id and file_number if identical
    id_str = d.get("id")
    file_number_str = d.get("file_number")
    if id_str == file_number_str:
        file_number_str = None

    out = {
        "path": d.get("path"),
        "name": d.get("name"),
        "num_links": _parse_int(d.get("num_links")),
        "type": d.get("type"),
        "major_minor_major": _parse_int(mm.get("major")),
        "major_minor_minor": _parse_int(mm.get("minor")),
        "symlink_target_type": d.get("symlink_target_type"),
        "id": id_str,
        "file_number": file_number_str,
        "mode": _parse_octal_mode(d.get("mode")),
        "owner": _parse_int(d.get("owner")),
        "owner_id_type": owner_details.get("id_type"),
        "owner_id_value": owner_details.get("id_value"),
        "group": _parse_int(d.get("group")),
        "group_id_type": group_details.get("id_type"),
        "group_id_value": group_details.get("id_value"),
        "blocks": _parse_int(d.get("blocks")),
        "datablocks": _parse_int(d.get("datablocks")),
        "metablocks": _parse_int(d.get("metablocks")),
        "size": _parse_int(d.get("size")),
        "access_time": _parse_ts(d.get("access_time")),
        "modification_time": _parse_ts(d.get("modification_time")),
        "change_time": _parse_ts(d.get("change_time")),
        "creation_time": _parse_ts(d.get("creation_time")),
        "child_count": _parse_int(d.get("child_count")),
        "ea_read_only": ea.get("read_only"),
        "ea_hidden": ea.get("hidden"),
        "ea_system": ea.get("system"),
        "ea_archive": ea.get("archive"),
        "ea_temporary": ea.get("temporary"),
        "ea_compressed": ea.get("compressed"),
        "ea_not_content_indexed": ea.get("not_content_indexed"),
        "ea_sparse_file": ea.get("sparse_file"),
        "ea_offline": ea.get("offline"),
        "directory_entry_hash_policy": d.get("directory_entry_hash_policy"),
        "data_revision": _parse_int(d.get("data_revision")),
        "user_metadata_revision": _parse_int(d.get("user_metadata_revision")),
        "ingest_ts": dt.datetime.fromtimestamp(now_ns / 1e9, tz=dt.timezone.utc),
    }
    return out


# -----------------------------
# Ingest
# -----------------------------


def write_parquet_batch(
    rows: List[Dict[str, Any]],
    out_dir: Path,
    compression: str = "zstd",
    schema: Optional[pa.Schema] = None,
) -> Path:
    """Write one batch to a new Parquet file under out_dir."""
    out_dir.mkdir(parents=True, exist_ok=True)
    table = pa.Table.from_pylist(rows, schema=schema or arrow_schema())
    fname = out_dir / f"part-{int(time.time()*1000)}-{os.getpid()}.parquet"
    pq.write_table(
        table,
        fname,
        compression=compression,
        use_dictionary=True,
        data_page_size=1024 * 1024,
        write_batch_size=64_000,
    )
    return fname


def cmd_ingest(args: argparse.Namespace) -> None:
    """Ingest NDJSON to Parquet files."""
    out_dir = Path(args.out_dir)
    rows_per_file = int(args.rows_per_file)
    schema = arrow_schema()

    # Configure logging level
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    inputs: List[str] = []
    if args.input:
        inputs = [args.input]
    else:
        inputs = ["-"]  # stdin

    batch: List[Dict[str, Any]] = []
    total = 0
    files_written = 0
    errors = 0
    line_num = 0

    def flush():
        nonlocal batch, total, files_written
        if not batch:
            return
        try:
            path = write_parquet_batch(
                batch, out_dir, compression=args.compression, schema=schema
            )
            files_written += 1
            total += len(batch)
            logger.info(f"wrote {len(batch)} rows → {path}")
            batch.clear()
        except Exception as e:
            logger.error(f"Failed to write batch: {e}")
            raise

    for src in inputs:
        line_num = 0
        try:
            if src == "-":
                fh = sys.stdin
                logger.info("Reading from stdin...")
            else:
                fh = open(src, "r", encoding="utf-8")
                logger.info(f"Reading from {src}...")

            with fh:
                for line in fh:
                    line_num += 1
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError as e:
                        errors += 1
                        if args.verbose:
                            logger.warning(f"Line {line_num}: JSON parse error: {e}")
                        continue

                    coerced = coerce_record(rec, now_ns=time.time_ns())
                    batch.append(coerced)

                    if len(batch) >= rows_per_file:
                        flush()

                    # Progress reporting
                    if args.verbose and total > 0 and total % 100000 == 0:
                        logger.debug(f"Processed {total:,} records...")

        except IOError as e:
            logger.error(f"Failed to read {src}: {e}")
            sys.exit(1)

    flush()
    logger.info(
        f"done. rows={total:,}, files={files_written}, errors={errors}, out_dir={out_dir}"
    )


# -----------------------------
# Query
# -----------------------------


def cmd_query(args: argparse.Namespace) -> None:
    """Query Parquet dataset with SQL."""
    data_path = Path(args.data)
    if not data_path.exists():
        logger.error(f"Data path not found: {data_path}")
        sys.exit(2)

    # Build a DuckDB view that points at all parquet files
    parquet_glob = str((data_path / "**" / "*.parquet").as_posix())
    con = duckdb.connect(database=":memory:")

    try:
        schema = arrow_schema()
        cols = ",\n  ".join(f'"{f.name}"' for f in schema)
        con.execute(
            f"""
            CREATE VIEW files AS
            SELECT {cols}
            FROM read_parquet('{parquet_glob}');
        """
        )

        # Execute user SQL
        try:
            rel = con.execute(args.sql)
        except duckdb.Error as e:
            logger.error(f"SQL error: {e}")
            sys.exit(2)

        if args.out_csv:
            con.execute(
                f"COPY ({args.sql}) TO '{args.out_csv}' (HEADER, DELIMITER ',');"
            )
            logger.info(f"Wrote CSV: {args.out_csv}")
        else:
            # Pretty print to stdout
            df = rel.df()
            if df.empty:
                print("(no rows)")
            else:
                pd.set_option("display.max_rows", 200)
                pd.set_option("display.max_columns", 200)
                pd.set_option("display.width", 160)
                print(df.to_string(index=False))

    finally:
        con.close()


# -----------------------------
# Stats
# -----------------------------


def cmd_stats(args: argparse.Namespace) -> None:
    """Show dataset statistics."""
    data_path = Path(args.data)
    if not data_path.exists():
        logger.error(f"Data path not found: {data_path}")
        sys.exit(2)

    parquet_files = list(data_path.glob("**/*.parquet"))
    if not parquet_files:
        logger.error(f"No parquet files found in {data_path}")
        sys.exit(2)

    logger.info(f"Analyzing dataset in {data_path}...")

    # Collect file statistics
    total_size = 0
    file_count = len(parquet_files)

    for pfile in parquet_files:
        total_size += pfile.stat().st_size

    # Query dataset for record counts
    parquet_glob = str((data_path / "**" / "*.parquet").as_posix())
    con = duckdb.connect(database=":memory:")

    try:
        # Total rows
        result = con.execute(f"SELECT COUNT(*) FROM read_parquet('{parquet_glob}')").fetchone()
        total_rows = result[0]

        # File types
        type_counts = con.execute(
            f"""
            SELECT type, COUNT(*) as count
            FROM read_parquet('{parquet_glob}')
            GROUP BY type
            ORDER BY count DESC
        """
        ).fetchall()

        # Disk usage
        disk_usage = con.execute(
            f"""
            SELECT
                SUM(size)/1024.0/1024/1024/1024 as logical_tb,
                SUM(CAST(blocks AS BIGINT) * 512)/1024.0/1024/1024/1024 as actual_tb
            FROM read_parquet('{parquet_glob}')
            WHERE type = 'FS_FILE_TYPE_FILE'
        """
        ).fetchone()

        print("\n=== Dataset Statistics ===")
        print(f"Location: {data_path}")
        print(f"Parquet files: {file_count:,}")
        print(f"Parquet size: {total_size / 1024 / 1024:.1f} MB")
        print(f"Total records: {total_rows:,}")
        print()
        print("File types:")
        for ftype, count in type_counts:
            print(f"  {ftype:25s} {count:>15,}")
        print()
        if disk_usage:
            logical_tb, actual_tb = disk_usage
            print(f"Logical size: {logical_tb:,.2f} TB")
            print(f"Actual disk usage: {actual_tb:,.2f} TB")
            if logical_tb > actual_tb:
                sparse_pct = ((logical_tb - actual_tb) / logical_tb * 100) if logical_tb > 0 else 0
                print(f"Sparse space: {sparse_pct:.1f}%")

    finally:
        con.close()


# -----------------------------
# CLI
# -----------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Ingest crawler NDJSON to Parquet; query with SQL."
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    # Ingest command
    p_ing = sub.add_parser("ingest", help="Ingest NDJSON and write Parquet")
    p_ing.add_argument("--input", "-i", help="Input NDJSON file (default: stdin)")
    p_ing.add_argument(
        "--out-dir", "-o", required=True, help="Output directory for Parquet files"
    )
    p_ing.add_argument(
        "--rows-per-file",
        type=int,
        default=250_000,
        help="Max rows per Parquet file (default: 250k)",
    )
    p_ing.add_argument(
        "--compression",
        default="zstd",
        choices=["zstd", "snappy", "gzip", "brotli", "lz4", "none"],
        help="Parquet compression codec (default: zstd)",
    )
    p_ing.add_argument(
        "-v", "--verbose", action="store_true", help="Verbose output"
    )
    p_ing.set_defaults(func=cmd_ingest)

    # Query command
    p_q = sub.add_parser("query", help="Run DuckDB SQL over the Parquet dataset")
    p_q.add_argument(
        "--data",
        "-d",
        required=True,
        help="Dataset directory (root with .parquet files)",
    )
    p_q.add_argument(
        "--sql", "-q", required=True, help="SQL to run (table name is `files`)"
    )
    p_q.add_argument("--out-csv", help="Optional CSV output path")
    p_q.set_defaults(func=cmd_query)

    # Stats command
    p_stats = sub.add_parser("stats", help="Show dataset statistics")
    p_stats.add_argument(
        "--data",
        "-d",
        required=True,
        help="Dataset directory (root with .parquet files)",
    )
    p_stats.set_defaults(func=cmd_stats)

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
