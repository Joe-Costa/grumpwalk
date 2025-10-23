#!/usr/bin/env python3
"""
fsindex_tool.py — Ingest file-crawler NDJSON → Parquet and run fast queries.

Features:
- Ingest NDJSON lines (stdin or files), coerce to a strong schema, write Parquet (ZSTD).
- Roll large ingests into multiple Parquet files (configurable batch size).
- Query Parquet directly with DuckDB SQL (no DB server; scans Parquet in-place).

Usage examples (assuming Python 3.10+):

  # 1) Ingest from a file to a dataset directory (creates .parquet files)
  python fsindex_tool.py ingest \
      --input crawl.ndjson \
      --out-dir ./dataset \
      --rows-per-file 250000

  # Or pipe from rsyslog/your crawler:
  cat crawl.ndjson | python fsindex_tool.py ingest --out-dir ./dataset

  # 2) Run a SQL query (results to stdout)
  python fsindex_tool.py query \
      --data ./dataset \
      --sql "SELECT name, size, owner FROM files ORDER BY size DESC LIMIT 20"

  # 3) Write query results to CSV
  python fsindex_tool.py query \
      --data ./dataset \
      --sql "SELECT date_trunc('day', access_time) AS day, count(*) AS files \
             FROM files GROUP BY day ORDER BY day DESC LIMIT 30" \
      --out-csv top_by_day.csv
"""

from __future__ import annotations
import argparse
import datetime as dt
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import pyarrow as pa
import pyarrow.parquet as pq

# DuckDB is used for fast SQL over Parquet
import duckdb


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
            # Keep exactly one identifier column; prefer "id". We'll also optionally store file_number if it's different.
            ("id", pa.large_string()),
            ("file_number", pa.large_string()),
            ("mode", pa.int32()),  # store as integer, parsed from octal string once
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
            # Extended attributes (packed efficiently as bools)
            ("ea_read_only", pa.bool_()),
            ("ea_hidden", pa.bool_()),
            ("ea_system", pa.bool_()),
            ("ea_archive", pa.bool_()),
            ("ea_temporary", pa.bool_()),
            ("ea_compressed", pa.bool_()),
            ("ea_not_content_indexed", pa.bool_()),
            ("ea_sparse_file", pa.bool_()),
            ("ea_offline", pa.bool_()),
            # Optional / misc
            ("directory_entry_hash_policy", pa.string()),
            ("data_revision", pa.int64()),
            ("user_metadata_revision", pa.int64()),
            # Ingest metadata
            ("ingest_ts", pa.timestamp("ns")),
        ]
    )


def _parse_int(s: Any) -> Optional[int]:
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
    """Convert mode strings like '0777' → int(0o777)."""
    if s is None:
        return None
    if isinstance(s, int):
        return s
    if isinstance(s, str):
        try:
            # handle strings like "0777" or "777"
            if s.startswith("0"):
                return int(s, 8)
            return int(s, 8)
        except ValueError:
            return None
    return None


def _parse_ts(iso: Any) -> Optional[dt.datetime]:
    if not iso or not isinstance(iso, str):
        return None
    # Handle RFC 3339 / ISO 8601 with 'Z' and possible nanoseconds
    try:
        if iso.endswith("Z"):
            iso = iso[:-1] + "+00:00"
        # Python can parse up to 6 microseconds; if we see more, trim to microseconds.
        # e.g., 2025-10-16T19:18:47.928643896Z
        # split on '.' then rebuild with microseconds
        if "." in iso:
            head, tail = iso.split(".", 1)
            # tail may include offset like '928643896+00:00'
            tz_part = ""
            if "+" in tail or "-" in tail:
                # find last + or - (timezone)
                for i in range(len(tail) - 1, -1, -1):
                    if tail[i] in "+-":
                        frac = tail[:i]
                        tz_part = tail[i:]
                        break
                else:
                    frac = tail
                    tz_part = ""
            else:
                frac = tail
            # pad/truncate to 6 for microseconds
            frac = (frac + "000000")[:6]
            iso = f"{head}.{frac}{tz_part}"
        return dt.datetime.fromisoformat(iso)
    except Exception:
        return None


def _get_nested(d: Dict[str, Any], *keys: str) -> Any:
    cur = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return None
        cur = cur[k]
    return cur


def coerce_record(d: Dict[str, Any], now_ns: int) -> Dict[str, Any]:
    """Map the crawler JSON to our flattened schema with correct types."""
    mm = d.get("major_minor_numbers") or {}
    owner_details = d.get("owner_details") or {}
    group_details = d.get("group_details") or {}
    ea = d.get("extended_attributes") or {}

    # If id and file_number are identical, keep "id" and set "file_number" to None to avoid duplication.
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


def write_parquet_batches(
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
    out_dir = Path(args.out_dir)
    rows_per_file = int(args.rows_per_file)
    schema = arrow_schema()

    inputs: List[str] = []
    if args.input:
        inputs = [args.input]
    else:
        inputs = ["-"]  # stdin

    batch: List[Dict[str, Any]] = []
    total = 0
    files_written = 0

    def flush():
        nonlocal batch, total, files_written
        if not batch:
            return
        path = write_parquet_batches(
            batch, out_dir, compression=args.compression, schema=schema
        )
        files_written += 1
        total += len(batch)
        print(f"[ingest] wrote {len(batch)} rows → {path}", file=sys.stderr)
        batch.clear()

    for src in inputs:
        if src == "-":
            fh = sys.stdin
        else:
            fh = open(src, "r", encoding="utf-8")
        with fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    # Skip malformed lines, optionally log
                    continue
                coerced = coerce_record(rec, now_ns=time.time_ns())
                batch.append(coerced)
                if len(batch) >= rows_per_file:
                    flush()

    flush()
    print(
        f"[ingest] done. rows={total}, files={files_written}, out_dir={out_dir}",
        file=sys.stderr,
    )


# -----------------------------
# Query
# -----------------------------


def cmd_query(args: argparse.Namespace) -> None:
    data_path = Path(args.data)
    if not data_path.exists():
        print(f"Data path not found: {data_path}", file=sys.stderr)
        sys.exit(2)

    # Build a tiny DuckDB view that points at all parquet files as a table named `files`
    parquet_glob = str((data_path / "**" / "*.parquet").as_posix())
    con = duckdb.connect(database=":memory:")
    # The projection lists columns with stable types to avoid name surprises
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
        print(f"SQL error: {e}", file=sys.stderr)
        sys.exit(2)

    if args.out_csv:
        con.execute(f"COPY ({args.sql}) TO '{args.out_csv}' (HEADER, DELIMITER ',');")
        print(f"Wrote CSV: {args.out_csv}")
    else:
        # Pretty print to stdout
        df = rel.df()  # small/medium results
        # For very large results, consider streaming or LIMIT ... here.
        if df.empty:
            print("(no rows)")
        else:
            # Light, readable tabular output
            # Avoid bringing in extra deps; format via pandas' to_string
            import pandas as pd  # duckdb returns a pandas df

            pd.set_option("display.max_rows", 200)
            pd.set_option("display.max_columns", 200)
            pd.set_option("display.width", 160)
            print(df.to_string(index=False))


# -----------------------------
# CLI
# -----------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Ingest crawler NDJSON → Parquet; query with SQL."
    )
    sub = p.add_subparsers(dest="cmd", required=True)

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
    p_ing.set_defaults(func=cmd_ingest)

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

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
