"""
Output handling classes for grumpwalk.

This module contains classes for progress tracking, batched output handling,
and performance profiling.
"""

import asyncio
import sys
import time
from typing import Optional, TYPE_CHECKING

# Import utility functions from the utils module
from .utils import format_time, format_owner_name

# Try to use ujson for faster parsing
try:
    import ujson as json_parser
except ImportError:
    import json as json_parser

# Avoid circular imports with type hints
if TYPE_CHECKING:
    from grumpwalk import AsyncQumuloClient


class ProgressTracker:
    """Track progress of async tree walking with real-time updates."""

    def __init__(self, verbose: bool = False, limit: Optional[int] = None):
        self.total_objects = 0
        self.total_dirs = 0
        self.matches = 0
        self.skipped_dirs = 0  # Count of directories skipped via smart skipping
        self.skipped_files = 0  # Count of files avoided by smart skipping
        self.skipped_subdirs = 0  # Count of subdirectories avoided by smart skipping
        self.start_time = time.time()
        self.verbose = verbose
        self.last_update = time.time()
        self.lock = asyncio.Lock()
        self.limit = limit
        self.limit_reached = False
        self.output_count = 0  # Track how many results have been output (for streaming)

    async def update(self, objects: int, dirs: int = 0, matches: int = 0):
        """Update progress counters and check if limit reached."""
        async with self.lock:
            self.total_objects += objects
            self.total_dirs += dirs
            self.matches += matches

            # Check if limit reached
            if self.limit and self.matches >= self.limit and not self.limit_reached:
                self.limit_reached = True
                if self.verbose:
                    print(
                        f"\r[INFO] Limit reached: {self.matches} matches (limit: {self.limit})",
                        file=sys.stderr,
                        flush=True,
                    )

            # Print progress every 0.5 seconds
            if self.verbose and time.time() - self.last_update > 0.5:
                elapsed = time.time() - self.start_time
                rate = self.total_objects / elapsed if elapsed > 0 else 0
                time_str = format_time(elapsed)
                print(
                    f"\r[PROGRESS] {self.total_objects:,} objects processed | "
                    f"{self.matches:,} matches | "
                    f"Smart Skip: {self.skipped_dirs:,} dirs ({self.skipped_files:,} files, {self.skipped_subdirs:,} subdirs) | "
                    f"{rate:.1f} obj/sec | "
                    f"Run time: {time_str}",
                    end="",
                    file=sys.stderr,
                    flush=True,
                )
                self.last_update = time.time()

    async def increment_skipped(self, files_skipped: int = 0, subdirs_skipped: int = 0):
        """
        Increment the skipped directory counter.

        Args:
            files_skipped: Number of files in the skipped directory
            subdirs_skipped: Number of subdirectories in the skipped directory
        """
        async with self.lock:
            self.skipped_dirs += 1
            self.skipped_files += files_skipped
            self.skipped_subdirs += subdirs_skipped

    def should_stop(self) -> bool:
        """Check if processing should stop due to limit."""
        return self.limit_reached

    def can_output(self) -> bool:
        """Check if we can output more results (for streaming mode)."""
        if not self.limit:
            return True
        return self.output_count < self.limit

    async def increment_output(self):
        """Increment output counter (for streaming mode)."""
        async with self.lock:
            self.output_count += 1
            # Update limit_reached based on output count for streaming
            if self.limit and self.output_count >= self.limit and not self.limit_reached:
                self.limit_reached = True
                if self.verbose:
                    print(
                        f"\r[INFO] Output limit reached: {self.output_count} results (limit: {self.limit})",
                        file=sys.stderr,
                        flush=True,
                    )

    def final_report(self):
        """Print final progress report."""
        if self.verbose:
            elapsed = time.time() - self.start_time
            rate = self.total_objects / elapsed if elapsed > 0 else 0
            time_str = format_time(elapsed)
            print(
                f"\r[PROGRESS] FINAL: {self.total_objects:,} objects processed | "
                f"{self.matches:,} matches | "
                f"Smart Skip: {self.skipped_dirs:,} dirs ({self.skipped_files:,} files, {self.skipped_subdirs:,} subdirs) | "
                f"{rate:.1f} obj/sec | "
                f"Run time: {time_str}",
                file=sys.stderr,
            )


class BatchedOutputHandler:
    """Handle batched output with identity resolution for --show-owner and --show-group streaming."""

    def __init__(
        self,
        client: "AsyncQumuloClient",
        batch_size: int = 100,
        show_owner: bool = False,
        show_group: bool = False,
        output_format: str = "text",
        progress: Optional["ProgressTracker"] = None,
        all_attributes: bool = False,
    ):
        self.client = client
        self.batch_size = batch_size
        self.show_owner = show_owner
        self.show_group = show_group
        self.output_format = output_format  # 'text' or 'json'
        self.batch = []
        self.lock = asyncio.Lock()
        self.progress = progress
        self.all_attributes = all_attributes

    async def add_entry(self, entry: dict):
        """Add entry to batch and flush if batch is full."""
        async with self.lock:
            self.batch.append(entry)

            if len(self.batch) >= self.batch_size:
                await self._flush_batch()

    async def _flush_batch(self):
        """Resolve identities for current batch and output."""
        if not self.batch:
            return

        identity_cache = {}

        # Collect unique auth_ids (owners and/or groups) from batch
        unique_auth_ids = set()

        if self.show_owner:
            for entry in self.batch:
                owner_details = entry.get("owner_details", {})
                owner_auth_id = owner_details.get("auth_id") or entry.get("owner")
                if owner_auth_id:
                    unique_auth_ids.add(owner_auth_id)

        if self.show_group:
            for entry in self.batch:
                group_details = entry.get("group_details", {})
                group_auth_id = group_details.get("auth_id") or entry.get("group")
                if group_auth_id:
                    unique_auth_ids.add(group_auth_id)

        # Resolve all identities in parallel
        if unique_auth_ids:
            async with self.client.create_session() as session:
                identity_cache = await self.client.resolve_multiple_identities(
                    session, list(unique_auth_ids)
                )

        # Output batch
        for entry in self.batch:
            # Check if we can output more results (respects --limit)
            if self.progress and not self.progress.can_output():
                break

            if self.output_format == "json":
                if self.all_attributes:
                    # Output full entry with all attributes
                    output_entry = entry
                else:
                    # Create minimal entry with path + owner/group
                    output_entry = {"path": entry["path"]}

                    if self.show_owner:
                        owner_details = entry.get("owner_details", {})
                        owner_auth_id = owner_details.get("auth_id") or entry.get("owner")
                        if owner_auth_id and owner_auth_id in identity_cache:
                            identity = identity_cache[owner_auth_id]
                            output_entry["owner"] = format_owner_name(identity)
                        else:
                            output_entry["owner"] = "Unknown"

                    if self.show_group:
                        group_details = entry.get("group_details", {})
                        group_auth_id = group_details.get("auth_id") or entry.get("group")
                        if group_auth_id and group_auth_id in identity_cache:
                            identity = identity_cache[group_auth_id]
                            output_entry["group"] = format_owner_name(identity)
                        else:
                            output_entry["group"] = "Unknown"

                # Use escape_forward_slashes=False for ujson to avoid \/
                try:
                    print(json_parser.dumps(output_entry, escape_forward_slashes=False))
                except TypeError:
                    # Standard json doesn't have escape_forward_slashes parameter
                    print(json_parser.dumps(output_entry))
            else:
                # Plain text
                output_line = entry["path"]

                if self.show_owner:
                    owner_details = entry.get("owner_details", {})
                    owner_auth_id = owner_details.get("auth_id") or entry.get("owner")
                    if owner_auth_id and owner_auth_id in identity_cache:
                        identity = identity_cache[owner_auth_id]
                        owner_name = format_owner_name(identity)
                        output_line = f"{output_line}\t{owner_name}"
                    else:
                        output_line = f"{output_line}\tUnknown"

                if self.show_group:
                    group_details = entry.get("group_details", {})
                    group_auth_id = group_details.get("auth_id") or entry.get("group")
                    if group_auth_id and group_auth_id in identity_cache:
                        identity = identity_cache[group_auth_id]
                        group_name = format_owner_name(identity)
                        output_line = f"{output_line}\t{group_name}"
                    else:
                        output_line = f"{output_line}\tUnknown"

                print(output_line)
            sys.stdout.flush()

            # Increment output counter
            if self.progress:
                await self.progress.increment_output()

        # Clear batch
        self.batch = []

    async def flush(self):
        """Flush any remaining entries in batch."""
        async with self.lock:
            await self._flush_batch()


# Canonical field order for Qumulo API file entries
# Used for CSV headers when --all-attributes is specified
CANONICAL_FILE_FIELDS = [
    # Core identity
    "path",
    "name",
    "type",
    "id",
    "file_number",
    # Size and blocks
    "size",
    "blocks",
    "datablocks",
    "metablocks",
    # Ownership
    "owner",
    "owner_details",
    "group",
    "group_details",
    # Timestamps
    "creation_time",
    "modification_time",
    "access_time",
    "change_time",
    # Permissions and links
    "mode",
    "num_links",
    # Extended info
    "child_count",
    "symlink_target_type",
    "major_minor_numbers",
    "extended_attributes",
    "directory_entry_hash_policy",
    "data_revision",
    "user_metadata_revision",
]


class StreamingFileOutputHandler:
    """
    Memory-efficient streaming output handler for CSV and JSON file output.

    Writes entries to file as they arrive, batching only for identity resolution.
    Memory usage is O(batch_size) regardless of total file count.

    This solves the OOM issue where --csv-out with millions of files would
    accumulate all entries in memory before writing.
    """

    def __init__(
        self,
        client: "AsyncQumuloClient",
        output_path: str,
        output_format: str = "csv",
        batch_size: int = 1000,
        show_owner: bool = False,
        show_group: bool = False,
        all_attributes: bool = False,
        progress: Optional["ProgressTracker"] = None,
        args=None,
    ):
        """
        Initialize streaming file output handler.

        Args:
            client: AsyncQumuloClient for identity resolution
            output_path: Path to output file
            output_format: 'csv' or 'json'
            batch_size: Number of entries to batch for identity resolution
            show_owner: Resolve and include owner names
            show_group: Resolve and include group names
            all_attributes: Include all file attributes (vs minimal)
            progress: Optional ProgressTracker
            args: Command-line args for determining which fields to include
        """
        self.client = client
        self.output_path = output_path
        self.output_format = output_format
        self.batch_size = batch_size
        self.show_owner = show_owner
        self.show_group = show_group
        self.all_attributes = all_attributes
        self.progress = progress
        self.args = args

        self.batch = []
        self.lock = asyncio.Lock()
        self.file_handle = None
        self.csv_writer = None
        self.header_written = False
        self.rows_written = 0

    def _get_fieldnames(self) -> list:
        """Determine CSV fieldnames based on configuration."""
        if self.all_attributes:
            # Use canonical field list plus any resolved name fields
            fieldnames = list(CANONICAL_FILE_FIELDS)
            if self.show_owner:
                fieldnames.insert(fieldnames.index("owner") + 1, "owner_name")
            if self.show_group:
                fieldnames.insert(fieldnames.index("group") + 1, "group_name")
            return fieldnames
        else:
            # Minimal fields based on what filters are active
            fieldnames = ["path"]

            # Add time field if time filter was used
            if self.args:
                if (self.args.older_than or self.args.newer_than or
                    self.args.accessed_older_than or self.args.accessed_newer_than or
                    self.args.modified_older_than or self.args.modified_newer_than or
                    self.args.created_older_than or self.args.created_newer_than or
                    self.args.changed_older_than or self.args.changed_newer_than):
                    fieldnames.append(self.args.time_field)

                # Add size if size filter was used
                if self.args.larger_than or self.args.smaller_than:
                    fieldnames.append("size")

            # Add owner/group if requested
            if self.show_owner:
                fieldnames.append("owner")
            if self.show_group:
                fieldnames.append("group")

            # Add symlink_target if resolve-links would be used
            if self.args and self.args.resolve_links:
                fieldnames.append("symlink_target")

            return fieldnames

    def _flatten_entry(self, entry: dict) -> dict:
        """Flatten nested dicts for CSV output."""
        flat = {}
        for key, value in entry.items():
            if isinstance(value, dict):
                # Convert nested dicts to JSON string for CSV
                flat[key] = json_parser.dumps(value)
            else:
                flat[key] = value
        return flat

    async def open(self):
        """Open the output file and write header if CSV."""
        import csv

        self.file_handle = open(self.output_path, "w", newline="")

        if self.output_format == "csv":
            fieldnames = self._get_fieldnames()
            self.csv_writer = csv.DictWriter(
                self.file_handle,
                fieldnames=fieldnames,
                extrasaction="ignore"
            )
            self.csv_writer.writeheader()
            self.header_written = True

    async def add_entry(self, entry: dict):
        """Add entry to batch and flush if batch is full."""
        async with self.lock:
            self.batch.append(entry)

            if len(self.batch) >= self.batch_size:
                await self._flush_batch()

    async def _flush_batch(self):
        """Resolve identities for current batch and write to file."""
        if not self.batch:
            return

        if not self.file_handle:
            await self.open()

        identity_cache = {}

        # Collect unique auth_ids for resolution
        if self.show_owner or self.show_group:
            unique_auth_ids = set()

            if self.show_owner:
                for entry in self.batch:
                    owner_details = entry.get("owner_details", {})
                    owner_auth_id = owner_details.get("auth_id") or entry.get("owner")
                    if owner_auth_id:
                        unique_auth_ids.add(str(owner_auth_id))

            if self.show_group:
                for entry in self.batch:
                    group_details = entry.get("group_details", {})
                    group_auth_id = group_details.get("auth_id") or entry.get("group")
                    if group_auth_id:
                        unique_auth_ids.add(str(group_auth_id))

            # Resolve identities in batch
            if unique_auth_ids:
                async with self.client.create_session() as session:
                    identity_cache = await self.client.resolve_multiple_identities(
                        session, list(unique_auth_ids)
                    )

        # Write entries to file
        for entry in self.batch:
            # Check output limit
            if self.progress and not self.progress.can_output():
                break

            # Add resolved owner name if requested
            if self.show_owner:
                owner_details = entry.get("owner_details", {})
                owner_auth_id = str(owner_details.get("auth_id") or entry.get("owner", ""))
                if owner_auth_id and owner_auth_id in identity_cache:
                    identity = identity_cache[owner_auth_id]
                    entry["owner_name"] = format_owner_name(identity)
                else:
                    entry["owner_name"] = "Unknown"

            # Add resolved group name if requested
            if self.show_group:
                group_details = entry.get("group_details", {})
                group_auth_id = str(group_details.get("auth_id") or entry.get("group", ""))
                if group_auth_id and group_auth_id in identity_cache:
                    identity = identity_cache[group_auth_id]
                    entry["group_name"] = format_owner_name(identity)
                else:
                    entry["group_name"] = "Unknown"

            if self.output_format == "csv":
                if self.all_attributes:
                    # Flatten nested dicts and write all fields
                    flat_entry = self._flatten_entry(entry)
                    self.csv_writer.writerow(flat_entry)
                else:
                    # Write minimal row
                    row = {"path": entry["path"]}
                    if self.args:
                        if (self.args.older_than or self.args.newer_than or
                            self.args.accessed_older_than or self.args.accessed_newer_than or
                            self.args.modified_older_than or self.args.modified_newer_than or
                            self.args.created_older_than or self.args.created_newer_than or
                            self.args.changed_older_than or self.args.changed_newer_than):
                            row[self.args.time_field] = entry.get(self.args.time_field)
                        if self.args.larger_than or self.args.smaller_than:
                            row["size"] = entry.get("size")
                        if self.args.resolve_links and "symlink_target" in entry:
                            row["symlink_target"] = entry.get("symlink_target")
                    if self.show_owner:
                        row["owner"] = entry.get("owner_name", "Unknown")
                    if self.show_group:
                        row["group"] = entry.get("group_name", "Unknown")
                    self.csv_writer.writerow(row)
            else:
                # JSON output (NDJSON)
                try:
                    self.file_handle.write(
                        json_parser.dumps(entry, escape_forward_slashes=False) + "\n"
                    )
                except TypeError:
                    self.file_handle.write(json_parser.dumps(entry) + "\n")

            self.rows_written += 1

            # Update progress
            if self.progress:
                await self.progress.increment_output()

        # Flush to disk periodically
        self.file_handle.flush()

        # Clear batch
        self.batch = []

    async def flush(self):
        """Flush any remaining entries."""
        async with self.lock:
            await self._flush_batch()

    async def close(self):
        """Close the output file."""
        await self.flush()
        if self.file_handle:
            self.file_handle.close()
            self.file_handle = None

    def get_rows_written(self) -> int:
        """Return the number of rows written."""
        return self.rows_written


class Profiler:
    """Track detailed performance metrics for profiling."""

    def __init__(self):
        self.timings = {}  # operation -> total time
        self.counts = {}  # operation -> call count
        self.lock = asyncio.Lock()

    async def record(self, operation: str, duration: float):
        """Record timing for an operation."""
        async with self.lock:
            if operation not in self.timings:
                self.timings[operation] = 0.0
                self.counts[operation] = 0
            self.timings[operation] += duration
            self.counts[operation] += 1

    def record_sync(self, operation: str, duration: float):
        """Record timing for an operation (synchronous version)."""
        if operation not in self.timings:
            self.timings[operation] = 0.0
            self.counts[operation] = 0
        self.timings[operation] += duration
        self.counts[operation] += 1

    def print_report(self, total_elapsed: float):
        """Print profiling report."""
        print("\n" + "=" * 80, file=sys.stderr)
        print("PROFILING REPORT", file=sys.stderr)
        print("=" * 80, file=sys.stderr)

        # Calculate total accounted time
        total_accounted = sum(self.timings.values())

        # Sort by total time descending
        sorted_ops = sorted(self.timings.items(), key=lambda x: x[1], reverse=True)

        print(
            f"\n{'Operation':<30} {'Total Time':>12} {'Calls':>10} {'Avg Time':>12} {'% Total':>8}",
            file=sys.stderr,
        )
        print("-" * 80, file=sys.stderr)

        for operation, total_time in sorted_ops:
            count = self.counts[operation]
            avg_time = total_time / count if count > 0 else 0
            pct_total = (total_time / total_elapsed * 100) if total_elapsed > 0 else 0

            print(
                f"{operation:<30} {total_time:>11.3f}s {count:>10,} {avg_time*1000:>11.2f}ms {pct_total:>7.1f}%",
                file=sys.stderr,
            )

        print("-" * 80, file=sys.stderr)
        print(f"{'Total Accounted':<30} {total_accounted:>11.3f}s", file=sys.stderr)
        print(f"{'Total Elapsed':<30} {total_elapsed:>11.3f}s", file=sys.stderr)

        unaccounted = total_elapsed - total_accounted
        if unaccounted > 0.01:
            pct_unaccounted = (
                (unaccounted / total_elapsed * 100) if total_elapsed > 0 else 0
            )
            print(
                f"{'Unaccounted (overhead)':<30} {unaccounted:>11.3f}s {pct_unaccounted:>7.1f}%",
                file=sys.stderr,
            )

        # Identify bottlenecks
        print(f"\nTop 3 Bottlenecks:", file=sys.stderr)
        for i, (operation, total_time) in enumerate(sorted_ops[:3]):
            pct = (total_time / total_elapsed * 100) if total_elapsed > 0 else 0
            print(f"  {i+1}. {operation}: {pct:.1f}% of total time", file=sys.stderr)

        print("=" * 80, file=sys.stderr)
