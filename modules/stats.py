"""
Statistics tracking classes for grumpwalk.

This module contains classes for tracking file ownership statistics
and generating reports.
"""

import asyncio
from typing import List, Dict


class OwnerStats:
    """Track file ownership statistics for --owner-report."""

    def __init__(self, use_capacity: bool = False):
        """
        Initialize owner statistics tracker.

        Args:
            use_capacity: If True, use actual disk usage (datablocks + metablocks).
                         If False, use logical file size. Set to True to handle sparse files correctly.
        """
        self.owner_data = {}  # auth_id -> {'bytes': int, 'files': int, 'dirs': int}
        self.lock = asyncio.Lock()
        self.use_capacity = use_capacity

    async def add_file(self, owner_auth_id: str, size: int, is_dir: bool = False):
        """Add a file to the owner statistics."""
        async with self.lock:
            if owner_auth_id not in self.owner_data:
                self.owner_data[owner_auth_id] = {"bytes": 0, "files": 0, "dirs": 0}

            self.owner_data[owner_auth_id]["bytes"] += size
            if is_dir:
                self.owner_data[owner_auth_id]["dirs"] += 1
            else:
                self.owner_data[owner_auth_id]["files"] += 1

    def get_all_owners(self) -> List[str]:
        """Get list of all unique owner auth_ids."""
        return list(self.owner_data.keys())

    def get_stats(self, owner_auth_id: str) -> Dict:
        """Get statistics for a specific owner."""
        return self.owner_data.get(owner_auth_id, {"bytes": 0, "files": 0, "dirs": 0})


BLOCK_SIZE = 4096


def entry_capacity(entry: dict) -> int:
    """
    On-disk used capacity of one entry, in bytes.

    Allocated blocks rather than logical size, so sparse files are reported as
    the space they actually occupy. Falls back to logical size when a response
    carries no block counts.

    Shared by every report that totals capacity, so they cannot drift apart.

    Args:
        entry: File/directory entry dict from the walk

    Returns:
        Capacity in bytes
    """
    datablocks = entry.get("datablocks")
    metablocks = entry.get("metablocks")
    if datablocks is not None or metablocks is not None:
        return (int(datablocks or 0) + int(metablocks or 0)) * BLOCK_SIZE
    return int(entry.get("size", 0) or 0)


class MatchTotals:
    """Count and total capacity of matching objects, for --size-totals-only.

    Fed one matched entry at a time from the tree walk and keeps two running
    numbers, so the totals cost the same memory whether the walk matches ten
    objects or a hundred million.
    """

    def __init__(self):
        self.total_files = 0
        self.total_capacity = 0

    def add(self, entry: dict) -> None:
        """Add one matched entry to the totals.

        Runs inside the async walk's single-threaded event loop with no awaits,
        so it is atomic with respect to other callbacks (no lock needed).
        """
        self.total_files += 1
        self.total_capacity += entry_capacity(entry)


class DirectoryMatchStats:
    """Aggregate filtered matches per directory for --per-directory-matches.

    Fed one matched entry at a time from the tree walk. Each match is credited
    to its ancestor directories (recursive, du-style rollup), so a directory's
    totals include all matches anywhere in its subtree. A grand total across
    the whole tree is tracked separately and is always complete.

    How many ancestors are credited depends on what will be reported. The
    default report lists only the immediate children of the root, so only those
    are tracked and one bucket is held per child. Under subdir_report every
    directory containing a match is reported, so one bucket is held per such
    directory -- unavoidable for that report, but it means memory grows with
    the size of the tree.

    Capacity is actual on-disk usage -- (datablocks + metablocks) * 4096 --
    which reflects what admins care about (allocated space, correct for sparse
    files), falling back to logical size when block counts are absent.
    """

    BLOCK_SIZE = 4096

    def __init__(self, root_path: str, subdir_report: bool = False):
        """
        Args:
            root_path: The --path search root that all matches live under.
            subdir_report: Whether every subdirectory will be reported. When
                False only the immediate children of the root are ever
                displayed, so only those are tracked and memory is bounded by
                the root's fan-out instead of the size of the tree. When True
                every directory containing a match is kept, because every one
                of them is reported.
        """
        self.root = self._normalize(root_path)
        self.subdir_report = subdir_report
        # dir_path -> {"files": int, "capacity": int, "depth": int}
        self.dirs: Dict[str, Dict] = {}
        self.total_files = 0
        self.total_capacity = 0

    @staticmethod
    def _normalize(p: str) -> str:
        p = (p or "/").rstrip("/")
        return p or "/"

    def _capacity(self, entry: dict) -> int:
        """On-disk used capacity of an entry, in bytes."""
        return entry_capacity(entry)

    def add(self, entry: dict) -> None:
        """Credit one matched entry to the grand total and its ancestor dirs.

        Runs inside the async walk's single-threaded event loop with no awaits,
        so it is atomic with respect to other callbacks (no lock needed).
        """
        path = entry.get("path")
        if not path:
            return

        cap = self._capacity(entry)
        self.total_files += 1
        self.total_capacity += cap

        p = path.rstrip("/")
        if self.root == "/":
            rel = p[1:] if p.startswith("/") else p
        else:
            prefix = self.root + "/"
            if not p.startswith(prefix):
                # Entry equals the root itself or lies outside it: counts toward
                # the grand total only, no intermediate directory bucket.
                return
            rel = p[len(prefix):]

        components = rel.split("/") if rel else []
        # Ancestor directories are the prefixes excluding the final component
        # (the matched object itself). depth == number of components below root.
        #
        # Only the depth-1 bucket is ever displayed unless every subdirectory
        # was asked for. Crediting deeper ancestors costs one bucket for every
        # directory in the tree that contains a match -- enough to exhaust
        # memory on a filesystem with millions of directories, to produce rows
        # that are then discarded. Stop at depth 1 unless they will be shown.
        deepest = len(components) if self.subdir_report else min(2, len(components))
        for depth in range(1, deepest):
            if self.root == "/":
                dir_path = "/" + "/".join(components[:depth])
            else:
                dir_path = self.root + "/" + "/".join(components[:depth])
            bucket = self.dirs.get(dir_path)
            if bucket is None:
                self.dirs[dir_path] = {"files": 1, "capacity": cap, "depth": depth}
            else:
                bucket["files"] += 1
                bucket["capacity"] += cap

    def rows(self) -> List[Dict]:
        """Return per-directory rows to display.

        In the default mode: only the immediate children of the root (depth 1),
        each a rollup of its whole subtree (du -d1 style). Under subdir_report:
        every directory that contains matches, at every depth reached by the
        walk (du style).

        The mode comes from the instance rather than the caller, because only
        what the instance was told to track was ever recorded -- asking here
        for a deeper report than was collected would silently print a partial
        one under a heading promising the full tree.
        """
        rows = []
        for dir_path, bucket in self.dirs.items():
            if not self.subdir_report and bucket["depth"] != 1:
                continue
            rows.append({
                "path": dir_path,
                "files": bucket["files"],
                "capacity": bucket["capacity"],
                "depth": bucket["depth"],
            })
        return rows
