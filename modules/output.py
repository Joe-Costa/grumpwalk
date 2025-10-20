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
    ):
        self.client = client
        self.batch_size = batch_size
        self.show_owner = show_owner
        self.show_group = show_group
        self.output_format = output_format  # 'text' or 'json'
        self.batch = []
        self.lock = asyncio.Lock()
        self.progress = progress

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
                print(json_parser.dumps(entry))
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
