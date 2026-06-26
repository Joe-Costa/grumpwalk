# Grumpwalk Users Guide

**Version 3.3.0** | [Changelog](CHANGELOG.md) | [README](README.md)

A practical guide with recipes for common storage administration tasks using grumpwalk.

---

## Table of Contents

1. [Getting Started](#getting-started)
2. [Finding Files](#finding-files)
3. [Directory Statistics](#directory-statistics)
4. [Storage Capacity Planning](#storage-capacity-planning)
5. [Data Lifecycle Management](#data-lifecycle-management)
6. [Object Tagging](#object-tagging)
7. [Moving, Copying, and Renaming Files](#moving-copying-and-renaming-files)
8. [Recovering Data from Snapshots](#recovering-data-from-snapshots)
9. [User and Access Management](#user-and-access-management)
10. [Domain Migration](#domain-migration)
11. [Compliance and Auditing](#compliance-and-auditing)
12. [Security and Incident Response](#security-and-incident-response)
13. [Duplicate and Similar File Detection](#duplicate-and-similar-file-detection)
14. [Media and Creative Workflows](#media-and-creative-workflows)
15. [Reporting and Analytics](#reporting-and-analytics)
16. [Performance Optimization](#performance-optimization)
17. [Scripting and Automation](#scripting-and-automation)
18. [Combining Filters with Actions](#combining-filters-with-actions)

---

## Getting Started

### Prerequisites

1. **Authentication**: grumpwalk needs Qumulo credentials. There are two ways to provide them.

   **Long-lived API access key (preferred)** - Create an access key (see
   [Qumulo: creating and using access tokens](https://docs.qumulo.com/administrator-guide/connecting-to-external-services/creating-using-access-tokens-to-authenticate-external-services-qumulo-core.html)),
   save it to a file, and point grumpwalk at that file with `--credentials-store`:
   ```bash
   ./grumpwalk.py --host cluster.example.com --credentials-store /path/to/keyfile ...
   ```

   **Temporary login with the `qq` CLI (expires after 10 hours)** - if you have the
   `qq` CLI installed:
   ```bash
   qq --host cluster.example.com login -u "DOMAIN\user"
   ```
   This writes a `.qfsd_cred` file to your home directory, which grumpwalk uses
   automatically (no `--credentials-store` needed). This method is often more
   convenient if you switch between clusters frequently or prefer tokens that
   expire on their own.

   Log in as a user with the RBAC rights for whatever grumpwalk will do, and treat
   these keys like any other credentials - secure them properly.

2. **Dependencies**: Install required packages:
   ```bash
   pip install aiohttp

   # Optional for better performance:
   pip install ujson xxhash
   ```

### Basic Usage Pattern

```bash
./grumpwalk.py --host CLUSTER --path /starting/path [FILTERS] [OPTIONS]
```

### Your First Crawl

```bash
# Basic crawl with progress
./grumpwalk.py --host cluster.example.com --path /data --progress > inventory.ndjson

# Quick file count
./grumpwalk.py --host cluster.example.com --path /data --progress 2>&1 | tail -1
```

---

## Finding Files

### How do I find files by name?

**Find all log files:**
```bash
./grumpwalk.py --host cluster --path /var --name '*.log' --type file
```

**Find files matching multiple patterns (OR logic):**
```bash
./grumpwalk.py --host cluster --path /data --name '*.tmp' --name '*.bak' --name '*.old'
```

**Find files matching ALL patterns (AND logic):**
```bash
./grumpwalk.py --host cluster --path /backups --name-and '*backup*' --name-and '*2024*'
```

**Case-sensitive search:**
```bash
./grumpwalk.py --host cluster --path /docs --name 'README*' --name-case-sensitive
```

> **Glob matching is whole-name (like the shell).** `--name 'file_*'` matches names
> that *begin* with `file_` (not `myfile_1`); `--name '*.log'` matches names ending in
> `.log`; and a wildcard-free `--name report` matches only the exact name `report` -
> use `--name '*report*'` for "contains". Always quote patterns so your shell does not
> expand `*` against your local directory before grumpwalk runs. (Regex patterns - those
> containing characters like `^`, `$`, `.`, `+` - are matched unanchored; anchor them
> with `^`/`$` yourself.)

**Find using regex:**
```bash
# Find files starting with numbers
./grumpwalk.py --host cluster --path /data --name '^[0-9].*'

# Find files with version numbers (v1, v2, etc.)
./grumpwalk.py --host cluster --path /releases --name '.*_v[0-9]+\.'
```

### How do I find files by size?

**Find large files (over 1GB):**
```bash
./grumpwalk.py --host cluster --path /data --larger-than 1GB --type file --progress
```

**Find small files (under 1KB)**
```bash
./grumpwalk.py --host cluster --path /data --smaller-than 1KB --type file
```

**Find files in a size range:**
```bash
./grumpwalk.py --host cluster --path /media \
  --larger-than 100MB --smaller-than 1GB --type file
```


### How do I find files by age?

**Find files older than 90 days (by creation time):**
```bash
./grumpwalk.py --host cluster --path /data --older-than 90 --type file
```

**Find files modified in the last 7 days:**
```bash
./grumpwalk.py --host cluster --path /projects --modified --newer-than 7
```

**Find files not accessed in over a year:**
```bash
./grumpwalk.py --host cluster --path /archive --accessed --older-than 365
```

**Find files created recently but not modified (potential placeholders):**
```bash
./grumpwalk.py --host cluster --path /data \
  --created --newer-than 30 \
  --modified-older-than 30
```

### How do I find files by owner?

**Find all files owned by a specific user:**
```bash
./grumpwalk.py --host cluster --path /home --owner jsmith --progress
```

**Find files owned by a UID:**
```bash
./grumpwalk.py --host cluster --path /nfs-data --owner 1001 --uid
```

**Find files owned by an AD user:**
```bash
./grumpwalk.py --host cluster --path /shared --owner "jsmith" --ad
```

****Find files owned by an AD user (Alternate method):**

```bash
./grumpwalk.py --host cluster --path /shared --owner "AD\jsmith"
```

**Find files owned by multiple users (OR logic):**
```bash
./grumpwalk.py --host cluster --path /projects \
  --owner alice --owner bob --owner charlie
```

### How do I find specific file types?

**Find only directories:**
```bash
./grumpwalk.py --host cluster --path /data --type directory
```

When `--type directory` is used alone (without other filters), grumpwalk uses recursive aggregates to skip enumeration of "leaf" directories that contain only files. On trees with many file-heavy leaf directories, this is a significant speedup.

**Find only symlinks:**
```bash
./grumpwalk.py --host cluster --path /opt --type symlink --resolve-links
```

**Find empty directories:**
```bash
./grumpwalk.py --host cluster --path /data --type directory \
  --json --all-attributes --progress | \
  jq 'select(.child_count == 0)'
```

### How do I search within specific directories?

**Limit search depth:**
```bash
./grumpwalk.py --host cluster --path /home --max-depth 2 --type file
```

**Skip certain directories:**
```bash
./grumpwalk.py --host cluster --path /data \
  --omit-subdirs '.snapshot' \
  --omit-subdirs 'node_modules' \
  --omit-subdirs '.git'
```

**Skip specific paths:**
```bash
./grumpwalk.py --host cluster --path / \
  --omit-path /var/log \
  --omit-path /tmp \
  --omit-path /proc
```

### How do I find and manage files by DOS extended attributes?

Qumulo tracks nine extended attributes on every file and directory: `read_only`, `hidden`, `system`, `archive`, `temporary`, `compressed`, `not_content_indexed`, `sparse_file`, and `offline`. Four of these (`read_only`, `hidden`, `system`, `archive`) are the classic DOS attributes and can be modified through grumpwalk.

> **Note:** DOS attributes are only honored and interpreted by SMB clients. They have no impact on access through NFS, REST, FTP, or S3 protocols. Setting `read_only` via grumpwalk, for example, will prevent writes from Windows/SMB clients but will not restrict NFS users.

**Find all files with the archive bit set:**
```bash
./grumpwalk.py --host cluster --path /data --find-attribute-true archive --type file --progress
```

**Find hidden files:**
```bash
./grumpwalk.py --host cluster --path /shares --find-attribute-true hidden --type file
```

**Find files that are NOT read-only:**
```bash
./grumpwalk.py --host cluster --path /finance --find-attribute-false read_only --type file
```

**Find sparse files (filter-only, not settable):**
```bash
./grumpwalk.py --host cluster --path /data --find-attribute-true sparse --type file
```

**Clear the archive bit on all files in a directory tree:**
```bash
./grumpwalk.py --host cluster --path /backups \
  --find-attribute-true archive --set-attribute-false archive \
  --propagate-changes --progress
```

**Set read-only on all PDF files:**
```bash
./grumpwalk.py --host cluster --path /legal \
  --name '*.pdf' --type file \
  --set-attribute-true read_only \
  --propagate-changes --progress
```

**Preview changes before applying (dry run):**
```bash
./grumpwalk.py --host cluster --path /projects \
  --find-attribute-true archive --set-attribute-false archive \
  --propagate-changes --dry-run
```

**Combine both pairs in one command** -- find archived files and clear the bit, while also finding non-hidden files and marking them hidden:
```bash
./grumpwalk.py --host cluster --path /staging \
  --find-attribute-true archive --set-attribute-false archive \
  --find-attribute-false hidden --set-attribute-true hidden \
  --propagate-changes --dry-run
```

A `--find-attribute` flag and its paired `--set-attribute` flag must use opposite booleans and appear next to each other on the command line. Inserting other flags between a find/set pair will produce an error.

**Combine attribute filters with other filters:**
```bash
# Find archived files larger than 1GB that haven't been accessed in 90 days
./grumpwalk.py --host cluster --path /data \
  --find-attribute-true archive \
  --larger-than 1GB --accessed --older-than 90 \
  --type file --progress
```

---

## Directory Statistics

The `--stats` flag retrieves directory aggregate counts directly from the cluster and exits -- no tree walk required. This is the fastest way to get file counts, directory counts, and total size for a path.

### How do I get a quick summary of a directory?

```bash
./grumpwalk.py --host cluster --path /data --stats
```

**Sample output:**
```
Path                          Files  Subdirectories  Total Size
----------------------------  -----  --------------  ----------
/data                     2,271,601              42     1.5 TiB
```

### How do I see a breakdown by subdirectory?

Use `--max-depth` to recurse into subdirectories:

```bash
# One level deep
./grumpwalk.py --host cluster --path /home --stats --max-depth 1

# Two levels deep, skipping snapshots
./grumpwalk.py --host cluster --path /home --stats --max-depth 2 --omit-subdirs '.snapshot'
```

### How do I skip specific directories?

```bash
# Skip by name pattern
./grumpwalk.py --host cluster --path /data --stats --max-depth 2 \
  --omit-subdirs '.snapshot' --omit-subdirs 'tmp'

# Skip by exact path
./grumpwalk.py --host cluster --path / --stats --max-depth 1 \
  --omit-path /var/log --omit-path /tmp
```

### How do I export directory statistics?

```bash
# JSON to stdout (pipeable to jq)
./grumpwalk.py --host cluster --path /data --stats --max-depth 1 --json

# JSON to file
./grumpwalk.py --host cluster --path /data --stats --max-depth 1 --json-out stats.json

# CSV for spreadsheets
./grumpwalk.py --host cluster --path /data --stats --max-depth 1 --csv-out stats.csv
```

The CSV and JSON output include raw byte values for `total_size`, suitable for further processing.

### How do I sort the results?

Use `--sort` to order the table by size, file count, or name:

```bash
# Largest directories first
./grumpwalk.py --host cluster --path /data --stats --max-depth 1 --sort size

# Most files first
./grumpwalk.py --host cluster --path /data --stats --max-depth 1 --sort count

# Alphabetical by path
./grumpwalk.py --host cluster --path /data --stats --max-depth 1 --sort name
```

---

## Storage Capacity Planning

### How do I generate a storage report by owner?

```bash
./grumpwalk.py --host cluster --path /home --owner-report --progress
```

**Sample output:**
```
================================================================================
OWNER REPORT
================================================================================
Owner                          Domain               Files       Dirs      Total Size
------------------------------------------------------------------------------------------
alice@corp.com                 AD_USER              125,432    2,341     1.23 TB
bob@corp.com                   AD_USER               98,234    1,892     987.45 GB
UID 1001                       POSIX_USER            45,123      234     456.78 GB
------------------------------------------------------------------------------------------
TOTAL                                               268,789    4,467     2.67 TB
```

### How do I find who is using the most storage?

```bash
# Top 10 storage consumers
./grumpwalk.py --host cluster --path /shared --owner-report --progress 2>&1 | \
  grep -A 20 "OWNER REPORT"
```

### How do I identify cold data for tiering?

**Find data not accessed in 90+ days:**
```bash
./grumpwalk.py --host cluster --path /data \
  --accessed --older-than 90 \
  --type file --progress \
  --json-out cold_data_90days.json
```

**Summarize cold data by directory:**
```bash
./grumpwalk.py --host cluster --path /projects \
  --accessed --older-than 180 \
  --json --all-attributes \
  --type file | \
  jq -r '.path | split("/")[1:4] | join("/")' | sort | uniq -c | sort -rn | head -20
```

**Find large cold files (candidates for archival):**
```bash
./grumpwalk.py --host cluster --path /data \
  --accessed --older-than 365 \
  --larger-than 100MB \
  --type file --progress
```

### How do I estimate storage growth?

**Compare file counts by creation date:**
```bash
# Files created in the last 30 days
./grumpwalk.py --host cluster --path /data --created --newer-than 30 --type file | wc -l

# Files created 30-60 days ago
./grumpwalk.py --host cluster --path /data \
  --created --newer-than 60 --created-older-than 30 --type file | wc -l
```

**Analyze recent growth by owner:**
```bash
./grumpwalk.py --host cluster --path /home \
  --created --newer-than 30 \
  --owner-report --progress
```

### How do I find directories consuming the most space?

```bash
./grumpwalk.py --host cluster --path /data \
  --show-dir-stats --max-depth 2 --progress
```

---

## Data Lifecycle Management

### Does crawling change access times (atime)?

No, not by default on modern clusters. Reading a directory's contents or a file's
data normally updates that object's access time (atime). For a metadata crawl this
is an unwanted side effect: an access-time-based workflow (cold-data tiering, "not
accessed in N days" retention, compliance auditing) would be corrupted by the very
crawl meant to measure it.

On **Qumulo Core 7.9.0 and later**, grumpwalk automatically suppresses these atime
updates. It detects the cluster version once at startup and adds the
`skip-atime-update=true` parameter to every read that would otherwise bump atime
(directory enumeration, symlink target reads, and file-content sampling). You do not
need to do anything; the access times you filter on are the access times you observe.

On clusters older than 7.9.0 the parameter is not available, so reads behave as the
cluster's own atime settings dictate (note that many clusters disable atime updates
globally, or coarsen them to a daily/weekly granularity).

**If you want reads to update atime as usual, pass `--update-atime`:**
```bash
./grumpwalk.py --host cluster --path /data --update-atime --progress
```
On a cluster that does not support the option, `--update-atime` prints a single
warning and reads simply fall back to the cluster's default atime behavior.

### How do I find stale data for cleanup?

**Find files untouched for 2+ years:**
```bash
./grumpwalk.py --host cluster --path /archive \
  --accessed --older-than 730 \
  --modified --older-than 730 \
  --type file --progress \
  --csv-out stale_files.csv
```

**Find old temporary files:**
```bash
./grumpwalk.py --host cluster --path /data \
  --name '*.tmp' --name '*.temp' --name '*.bak' --name '~*' \
  --older-than 30 \
  --type file
```

### How do I implement a retention policy?

**Find files exceeding 7-year retention:**
```bash
./grumpwalk.py --host cluster --path /legal/documents \
  --created --older-than 2555 \
  --type file --progress \
  --json-out retention_exceeded.json
```

**Generate deletion candidate list by category:**
```bash
# Log files older than 90 days
./grumpwalk.py --host cluster --path /var/log \
  --name '*.log' --name '*.log.*' \
  --older-than 90 --type file \
  --csv-out logs_to_delete.csv

# Core dumps older than 30 days
./grumpwalk.py --host cluster --path /var \
  --name 'core.*' --name '*.core' \
  --older-than 30 --type file \
  --csv-out cores_to_delete.csv
```

### How do I find files that should be compressed?

```bash
# Large text/log files that could benefit from compression
./grumpwalk.py --host cluster --path /logs \
  --name '*.log' --name '*.txt' --name '*.csv' --name '*.json' \
  --larger-than 100MB \
  --type file
```

---

## Object Tagging

Grumpwalk can attach custom key/value tags to files and directories. Tags are useful for classifying data however you like -- marking review status, recording a project or owner, or flagging assets for a workflow. Every tagging command uses the same filters as the rest of grumpwalk, so you can tag, find, or remove tags on exactly the objects you mean.

For more information refer to the [Managing User-Defined Metadata in Qumulo Core](https://docs.qumulo.com/administrator-guide/metadata/managing-user-defined-metadata.html) guide in the Qumulo Documentation Portal

There are three modes, all driven by `--path`:

- `--add-tag` adds or updates a tag (needs `--key` and `--value`)
- `--find-tag` lists objects that carry a tag
- `--remove-tag` deletes a tag (needs `--key`)

All three walk the tree, so they work with `--progress`, `--dry-run`, and `--limit`. As with the other action flags, `--dry-run` previews every object, and a real run lists each object only when you add `--verbose`.

### How do I tag matching files?

**Tag every JPEG modified in the last three days:**
```bash
./grumpwalk.py --host cluster --path /media \
  --name '*.jpg' --modified --newer-than 3 \
  --add-tag --key reviewed --value yes --progress
```

The tag lands on every object the filters match. Point `--path` at a single file to tag just that file, or use `--max-depth 0` to tag only the directory itself and not its contents.

### What happens if the tag already exists?

If the key is already set to the same value, grumpwalk leaves it alone. If the key exists with a *different* value, the object is skipped and reported -- grumpwalk will not overwrite it unless you ask:

```bash
# Skips files where 'reviewed' is already set to a different value
./grumpwalk.py --host cluster --path /media --name '*.jpg' \
  --add-tag --key reviewed --value yes

# Replace the existing value instead
./grumpwalk.py --host cluster --path /media --name '*.jpg' \
  --add-tag --key reviewed --value yes --overwrite
```

### How do I find tagged objects?

`--find-tag` streams one JSON line per match to stdout, ready to pipe into `jq` or save to a file.

```bash
# Everything with a 'reviewed' tag, any value
./grumpwalk.py --host cluster --path /media --find-tag --key reviewed

# Only where reviewed=yes
./grumpwalk.py --host cluster --path /media --find-tag --key reviewed --value yes

# Any object whose tag value is 'archive'
./grumpwalk.py --host cluster --path /media --find-tag --value archive

# Every tagged object under the path
./grumpwalk.py --host cluster --path /media --find-tag
```

Add the usual filters to narrow the search:
```bash
# Tagged PNGs only
./grumpwalk.py --host cluster --path /media \
  --find-tag --key reviewed --name '*.png' --type file
```

### How do I remove a tag?

`--remove-tag` deletes a key from matching objects. Add `--value` to remove it only when the current value matches -- a guard against deleting something unexpected.

```bash
# Preview first
./grumpwalk.py --host cluster --path /media \
  --name '*.jpg' --remove-tag --key reviewed --dry-run

# Remove it
./grumpwalk.py --host cluster --path /media \
  --name '*.jpg' --remove-tag --key reviewed

# Remove only where reviewed=yes; other values are left untouched
./grumpwalk.py --host cluster --path /media \
  --remove-tag --key reviewed --value yes
```

---

## Moving, Copying, and Renaming Files

`--move-to`, `--copy-to`, and `--rename-to` bring `mv`/`cp`-style moves, copies,
and bulk renaming to a filtered crawl. A move is a single RENAME metadata
operation; a copy is a server-side `copy-chunk` (data is copied on the cluster,
not streamed through grumpwalk). Always preview with `--dry-run` first; it prints
the complete `source -> target` plan and changes nothing.

### How do I move matching files into another directory?

`--move-to DEST` moves every match into the existing directory DEST, flattened
just like `mv a/x.log b/x.log /archive/`:
```bash
# Move all .log files older than 90 days into /archive (preview first)
./grumpwalk.py --host cluster --path /var/log \
  --name '*.log' --older-than 90 --type file \
  --move-to /archive --dry-run

# Run it for real (skip the prompt non-interactively)
./grumpwalk.py --host cluster --path /var/log \
  --name '*.log' --older-than 90 --type file \
  --move-to /archive --yes
```
On a name collision the object is skipped with a warning; add `--clobber` to
overwrite. If two different matches would land on the same name, both are
skipped **even with `--clobber`** (overwriting one move with another is never
intended) - the summary reports this as "Multiple sources to one target".

### How do I rename files in place?

Use `--rename-to` without `--move-to`. The `{old|new}` form replaces matched
text and leaves the rest of the name alone:
```bash
# Fix an extension: report.jpeg -> report.jpg
./grumpwalk.py --host cluster --path /photos \
  --name '*.jpeg' --rename-to '{.jpeg|.jpg}' --yes

# Re-brand a prefix: my_file_1.jpg -> our_file_1.jpg
./grumpwalk.py --host cluster --path /share \
  --name 'my_*' --rename-to '{my|our}' --yes
```
`{old|new}` accepts regex on the match side and `*`/`?` wildcards that capture:
`{IMG_*|photo_*}` turns `IMG_2024.jpg` into `photo_2024.jpg`; `{(\d+)|v\1}`
turns `scan12.tif` into `scanv12.tif`; `{_draft|}` deletes `_draft` from names.

A brace-less pattern is a whole-name template whose `*`/`?` come from the
matching `--name` glob:
```bash
# my_report.csv -> our_report.csv
./grumpwalk.py --host cluster --path /data \
  --name 'my_*' --rename-to 'our_*' --yes
```

### How do I move and rename in one pass?

Combine both flags:
```bash
# Move every *.log into /archive and give it a .txt extension
./grumpwalk.py --host cluster --path /var/log \
  --name '*.log' --move-to /archive --rename-to '{.log|.txt}' --yes
```

### How do I move whole directories?

By default only files and symlinks move; matched directories are skipped. Add
`--include-directories` to move directories with their entire subtree. Objects
that would travel inside a moved directory are pruned so nothing is moved twice,
and moving a directory into its own subtree is refused:
```bash
./grumpwalk.py --host cluster --path /projects \
  --name '*_archived' --type directory \
  --move-to /cold-storage --include-directories --yes
```

### How do I copy matching files (instead of moving them)?

`--copy-to DEST` is the copy counterpart of `--move-to`. The copy happens
server-side on the cluster (via the `copy-chunk` API - data is not streamed
through grumpwalk), the source is left untouched, and each file is copied via a
temp name then atomically renamed into place, so an interrupted run never leaves
a partial destination:
```bash
# Copy every PDF created in the last 7 days into /review (preview first)
./grumpwalk.py --host cluster --path /incoming \
  --name '*.pdf' --created --newer-than 7 \
  --copy-to /review --dry-run

./grumpwalk.py --host cluster --path /incoming \
  --name '*.pdf' --created --newer-than 7 \
  --copy-to /review --yes
```
`--copy-to` **flattens** its matches into DEST exactly like `--move-to` (and like
`cp a/x b/x DEST/`): each match lands at `DEST/<name>`, so the source's
subdirectory structure is dropped. It composes with `--rename-to` (copy and
rename in one pass), and `--copy-to` and `--move-to` cannot be used together.

Two collision rules apply (identical to `--move-to`):

- A match whose name already exists in DEST is **skipped**, unless `--clobber`
  overwrites it.
- If two matches would land on the **same** name in DEST - e.g. `a/dog` and
  `b/dog` both targeting `DEST/dog` - **both are skipped, even with `--clobber`**
  (silently letting one overwrite the other is never intended). The summary
  reports this as "Multiple sources to one target". To get them all copied,
  give them distinct names with `--rename-to`, narrow the match so only one
  wins, or copy the parent directory with `--include-directories` to keep the
  tree intact. (To put snapshot files back at their *original* paths rather than
  flatten them into one directory, use `--restore-in-place` instead.)

### Does a copy keep the original's owner and permissions?

No - by default a copy contains only the **data**. The new file is owned by you
(the API user) and its permissions are inherited from the destination directory,
exactly like plain `cp`. Two flags change that:

- `--preserve-permissions` copies each source's **owner, group, and ACL/mode**:
```bash
./grumpwalk.py --host cluster --path /home/alice \
  --name '*.key' --copy-to /backup/alice --preserve-permissions --yes
```
- `--preserve-all` copies **every settable attribute** - owner, group, ACL/mode,
  DOS extended attributes (`read_only`, `hidden`, etc.), GENERIC user-metadata
  tags, and timestamps (modification/access/creation):
```bash
./grumpwalk.py --host cluster --path /home/alice \
  --name '*' --copy-to /backup/alice --preserve-all --yes
```
Note: `change_time` (ctime) always reflects the moment of the copy and cannot be
preserved - copying a file is itself a metadata change. (This matches `cp -a` /
`rsync`, which also cannot restore ctime.)

### How do I copy whole directory trees?

Add `--include-directories`. Each matched directory is recreated under the
destination and its files, subdirectories, and symlinks are copied recursively
(an existing target directory is skipped - there is no merge):
```bash
./grumpwalk.py --host cluster --path /projects \
  --name 'release_*' --type directory \
  --copy-to /archive --include-directories --preserve-all --yes
```

### What if the copy (or move) destination does not exist yet?

By default a missing `--copy-to` (or `--move-to`) destination is an error. Add
`--create-destination-directory` to create it (and any missing parent
directories, like `mkdir -p`). It works the same way for both `--copy-to` and
`--move-to`. grumpwalk then asks how the new directory should
be permissioned - inherit the parent directory's permissions, or a specific
POSIX mode:
```bash
./grumpwalk.py --host cluster --path /incoming \
  --name '*.pdf' --copy-to /archive/2026/q2 --create-destination-directory
# prompt: [I]nherit from parent or specify a [P]OSIX mode? [I/p]:
```
For unattended runs, choose the permissions up front (no prompt). `--yes`
without a mode inherits from the parent:
```bash
# Inherit from parent, owned by a specific user
./grumpwalk.py --host cluster --path /incoming \
  --name '*.pdf' --copy-to /archive/2026/q2 \
  --create-destination-directory --destination-directory-owner 'DOMAIN\dataops' --yes

# Set an explicit mode on the new directories
./grumpwalk.py --host cluster --path /incoming \
  --name '*.pdf' --copy-to /archive/2026/q2 \
  --create-destination-directory --destination-directory-mode 0750 --yes
```
Use `--dry-run` to see exactly which directories would be created (and with what
permissions/owner) before anything is changed.

> **Note:** `--destination-directory-mode` and `--destination-directory-owner`
> apply only to directories grumpwalk *creates*. If the destination already
> exists, they are ignored (grumpwalk prints a warning) and the existing
> directory's owner and permissions are left unchanged - the copy/move still
> proceeds into it.

### How do I watch progress on a large copy or restore?

Add `--progress`. During `--copy-to` and snapshot restores it shows a live line
with files done, data copied, transfer rate, and ETA - and it advances *through*
a single large file, so a multi-gigabyte copy never looks stalled:
```bash
./grumpwalk.py --host cluster --path /projects --type file \
  --copy-to /archive --progress --yes
#   [COPY] 12/240 files | 18.4 GiB/212 GiB (8.7%) | 410 MiB/s | ETA 7m54s
```
The same line appears for `--restore-in-place`, labelled `[RESTORE]`.

### How do I re-run a copy - to resume it, or to keep a destination in sync?

These are two different needs, and they use different tools.

**Resuming an interrupted copy: just re-run it - no special flag.** Re-running a
`--copy-to` is cheap by default: grumpwalk checks each destination *before*
copying, so files already there are skipped without moving any data. Because the
copy is server-side, that saves real cluster I/O - re-running a half-finished
200 GB copy skips the done files in seconds and transfers only what is missing.
The same applies to restoring out of a snapshot (`--snapshot … --copy-to`) and to
`--restore-in-place`: run the command again and only the not-yet-restored files
are written. **A snapshot can never change, so there is nothing to "re-sync" - the
plain re-run is all an interrupted restore needs.**

**Keeping a destination in sync with a changing source: `--skip-unchanged`.** The
default skips by *existence* - a destination file that already exists is left
alone even if the *source* has since changed. That is exactly right for an
unchanging source (like a snapshot). But when the source is **live and evolving**
and you want the destination to track it, add `--skip-unchanged`:
```bash
# Re-runnable sync: copy only new/changed files from an evolving source
./grumpwalk.py --host cluster --path /home/joe/active --type file \
  --copy-to /home/joe/published --skip-unchanged --yes
```
It skips a file only when its size **and** modification time match the
destination, re-copies files that changed, and copies missing ones - an
incremental, rsync-style sync. It implies `--preserve-all` (the source's mtime
must be stamped on the destination for "unchanged" to be detectable next run), so
use it from the **first** copy; pointed at a destination made by an earlier
non-preserving copy, the first run re-copies everything once and later runs are
clean.

| Goal | Use |
|------|-----|
| Resume an interrupted copy or snapshot restore (source unchanged) | just re-run (no flag) |
| Keep a destination matching a changing live source | `--skip-unchanged` |
| Force every matched file to be overwritten | `--clobber` |

`--skip-unchanged` is a `--copy-to` option; an interrupted `--restore-in-place` is
resumed by simply re-running it. The check trusts size + mtime, not a content hash
(like rsync's default) - a file edited back to the exact same size *and* timestamp
would read as unchanged, which is rare in practice but worth knowing.

---

## Recovering Data from Snapshots

You can search a snapshot with your normal filters and copy matching files back out.
Snapshot reads see files as they were at snapshot time - **including files that
have since been deleted**.

### How do I see what snapshots exist?

```bash
./grumpwalk.py --host cluster --list-snapshots
#     ID  TIMESTAMP (UTC)        NAME             SOURCE
#      5  2026-06-22 21:16:00    Shared_Shared    /Shared
# Narrow by snapshot age:
./grumpwalk.py --host cluster --list-snapshots --snapshots-newer-than 7
```
On a large cluster the list can be long. Add `--path` to show only the snapshots
that cover a path - those whose source is that path or an ancestor, i.e. the
snapshots you can actually search or restore it from:
```bash
./grumpwalk.py --host cluster --list-snapshots --path /home/joe
# lists only snapshots sourced at /home/joe, /home, or / (not, say, /home/someone-else)
```
Qumulo's replication snapshots (`replication_from_*` / `replication_to_*`) and any
snapshots currently being deleted are hidden by default from both listing and
search, since they are not useful for restoring data. Add
`--include-replication-snapshots` if you need to see the replication ones
(snapshots being deleted are always hidden).

### How do I search inside a snapshot?

Add `--snapshot ID` to any normal crawl - every filter and output mode works:
```bash
# Large .docx files owned by alice, as they were in snapshot 5
./grumpwalk.py --host cluster --snapshot 5 --path /Shared \
  --name '*.docx' --owner alice --larger-than 1MB
```

### How do I find a file across all snapshots (I don't know which one has it)?

`--all-snapshots` searches every snapshot; each match is tagged with its snapshot.
Use `--path` to restrict to snapshots that cover that path, and the snapshot-age
flags to bound the set. Snapshot ages are in **UTC** and accept days or hours -
`5`/`5d` = 5 days, `12h` = 12 hours:
```bash
./grumpwalk.py --host cluster --all-snapshots --path /Shared \
  --name 'report.docx' --snapshots-newer-than 30d
#   [snap 9] /Shared/docs/report.docx
#   [snap 5] /Shared/docs/report.docx   <- the same file, duplicated per snapshot
```
When you give a snapshot-age limit on its own, `--all-snapshots` is implied - so
"search the snapshots from the last hour" is just:
```bash
./grumpwalk.py --host cluster --path /Shared --name 'report.docx' --snapshots-newer-than 1h
```

### How do I get just the latest version of each match (no duplicates)?

A file that hasn't changed appears in every snapshot, so `--all-snapshots` repeats
it. `--in-the-last-snapshots N` searches the **N most recent** snapshots and shows
only the **newest** result for each path:
```bash
# The latest recoverable version of each report, looking back over the 5 newest snapshots
./grumpwalk.py --host cluster --in-the-last-snapshots 5 --path /Shared --name 'report.docx'
#   [snap 9] /Shared/docs/report.docx        (one line per file, newest snapshot wins)
```
It composes with the snapshot-age limits, e.g. `--in-the-last-snapshots 10 --snapshots-newer-than 12h`.

### How do I see the size, age, and other attributes of matches (not just paths)?

By default a search prints one path per line. Add `--show-details` to get an
aligned table with the **size (human-readable)** and **change_time (ctime)** of
each match - this works for snapshot search and for the live walk:
```bash
./grumpwalk.py --host cluster --snapshot 5 --path /Shared --name '*.docx' --show-details
#   PATH                       SIZE     CHANGE_TIME
#   /Shared/docs/report.docx   1.4 MiB  2026-06-20T08:02:11Z
```
Choose your own columns with `--fields`, or get everything with `--fields all`
(which implies `--show-details`):
```bash
./grumpwalk.py --host cluster --snapshot 5 --path /Shared --name '*.docx' \
  --show-details --fields path,size,owner_name,modification_time
```
In a multi-snapshot search (`--all-snapshots` / `--in-the-last-snapshots`) the
table gains a leading `SNAPSHOT` column showing which snapshot each row came from.
It also writes to files - `--csv-out FILE` or `--json-out FILE` (and `--json` to
stdout); in those machine formats `size` stays raw bytes rather than human-readable.
Note: `--all-attributes` does nothing for snapshot search - use `--fields all`.

When you search for **directories** (`--type directory --show-details`), the size
column is replaced by the directory's recursive aggregate **`capacity`** - the
total bytes (data + metadata) of everything in its subtree, not the near-empty
inode size - so you can see how much each directory actually holds:
```bash
./grumpwalk.py --host cluster --path /Shared --max-depth 1 --type directory --show-details
#   PATH         CAPACITY   CHANGE_TIME
#   /Shared/6/   954.3 MiB  2026-06-25T16:41:31Z
#   /Shared/nfs/ 136 KiB    2026-06-19T15:16:09Z
```
The value comes from one directory-aggregates call per matched directory; it is
available as the `total_capacity` field (alias `capacity`) and is included by
`--fields all` for directory searches.

### How do I copy files out of a snapshot?

Combine `--snapshot` with `--copy-to`. It copies the snapshot version (including
deleted files) into a live staging directory and never touches the originals:
```bash
./grumpwalk.py --host cluster --snapshot 5 --path /Shared \
  --name '*.docx' --copy-to /Shared/restore-staging \
  --create-destination-directory --preserve-all --yes
```
Like any `--copy-to`, this **flattens**: every match lands at `DEST/<name>`, not
at its original sub-path. So two snapshot files with the same name (say
`a/b/c/d/dog` and `a/b/c/d/e/dog`) both target `DEST/dog`, collide, and are both
skipped ("Multiple sources to one target"). Even a single file copied this way
lands at the top of DEST, not back in its old subdirectory. When the goal is to
put files back where they *were* - at their original nested paths - use
`--restore-in-place` (next question), which never flattens and never collides on
same-named files.

**Copy and rename in one pass.** Add `--rename-to` to give the copies new names as
they land - handy for staging a snapshot version next to the live file, or tagging
a restore by snapshot/date. The snapshot version is what gets copied:
```bash
# Copy each *.docx out of snapshot 5, renaming report.docx -> report_snap5.docx
./grumpwalk.py --host cluster --snapshot 5 --path /Shared \
  --name '*.docx' --copy-to /Shared/restore-staging \
  --rename-to '{.docx|_snap5.docx}' --create-destination-directory --yes
```
The rename uses the full `--rename-to` syntax (`{old|new}`, `*`/`?` wildcards,
whole-name templates) and composes with `--preserve-all`, `--include-directories`,
and `--clobber`. The flatten/collision rule above still applies, though:
`--rename-to` only disambiguates same-named matches when the new names actually
differ, so it won't rescue two files both named `dog` - use `--restore-in-place`
for that.

### How do I restore files back to where they were (undelete / roll back)?

`--restore-in-place` writes each matched file back to its original path,
recreating files and parent directories deleted since the snapshot. This
overwrites live data, so it needs `--clobber` (to replace existing files) plus
confirmation - preview with `--dry-run` first:
```bash
# Preview
./grumpwalk.py --host cluster --snapshot 5 --path /Shared \
  --name '*.docx' --restore-in-place --clobber --dry-run

# Do it
./grumpwalk.py --host cluster --snapshot 5 --path /Shared \
  --name '*.docx' --restore-in-place --clobber --yes
```
Without `--clobber`, files that still exist live are skipped (only deleted ones
are recreated) - a safe way to undelete without rolling anything back.

To restore a single known file, point `--path` straight at it (no `--name`
needed) - `--path` accepts a file, not just a directory:
```bash
./grumpwalk.py --host cluster --snapshot 5 \
  --path /Shared/docs/report.docx --restore-in-place --yes
```
To restore several files at once, repeat `--name` - the patterns are OR'd, so this
restores everything named `cat`, `dog`, or `pig` anywhere under `--path`:
```bash
./grumpwalk.py --host cluster --snapshot 5 --path /Shared \
  --name cat --name dog --name pig --restore-in-place --yes
```
Any other filters narrow the set further (AND), e.g. add `--type file --older-than 30`
to restore only files, only those older than 30 days, among the names matched.

If a restore is interrupted, just run it again: already-restored files are skipped
(checked before any data moves) and only the rest are written. A snapshot never
changes, so there is nothing to re-sync - re-running is all you need, and
`--skip-unchanged` is neither required nor applicable here (see
[re-running a copy](#how-do-i-re-run-a-copy---to-resume-it-or-to-keep-a-destination-in-sync)).

### How do I restore an entire directory (not just its files)?

By default `--restore-in-place` restores files and recreates only the directories
that contain them, so empty subdirectories are left out. To bring back a whole
directory as it was - including non-matching files and empty subdirectories - add
`--include-directories`, or select directories with `--type directory`:
```bash
# Restore the whole project-x directory from the snapshot (subtree, empty dirs and all)
./grumpwalk.py --host cluster --snapshot 5 --path /Shared --max-depth 1 \
  --name 'project-x' --type directory --restore-in-place --yes

# Or: restore everything under a path, directories included
./grumpwalk.py --host cluster --snapshot 5 --path /Shared/project-x \
  --restore-in-place --include-directories --yes
```
If the directory still exists live, the restore **merges** into it: existing files
follow the conflict strategy (skip / `--clobber` / `--rename-on-conflict`), missing
files and subdirectories are recreated, and the live directory is left in place.

### What if a name already exists at the destination?

Three strategies, anywhere a copy/restore writes: the default **skips** the
conflict; `--clobber` **overwrites**; and `--rename-on-conflict` writes the item
under a `_restored_<date>_<time>` suffix (e.g. `report_restored_2026-06-25_14-30-05.docx`),
so you keep both. The stamp is the grumpwalk host's local time, stamped once per
run; customize it with `--conflict-suffix`.

---

## User and Access Management

### How do I audit permissions for a user?

**Generate ACL report showing user's access:**
```bash
./grumpwalk.py --host cluster --path /shared \
  --acl-report --acl-resolve-names --progress
```

**Find all files a user owns:**
```bash
./grumpwalk.py --host cluster --path / \
  --owner "DOMAIN\\jsmith" --ad \
  --expand-identity \
  --progress \
  --json-out jsmith_files.json
```

### How do I handle employee offboarding?

**Step 1: Find all files owned by departing employee:**
```bash
./grumpwalk.py --host cluster --path /home/jsmith \
  --owner "DOMAIN\\jsmith" --ad \
  --type file --progress \
  --json-out departing_user_files.json
```

**Step 2: Clone their permissions to manager:**
```bash
./grumpwalk.py --host cluster --path /home/jsmith \
  --clone-ace-source "DOMAIN\\jsmith" \
  --clone-ace-target "DOMAIN\\manager" \
  --propagate-changes --progress
```

**Step 3: Remove departing user's ACEs:**
```bash
./grumpwalk.py --host cluster --path /home/jsmith \
  --remove-ace "Allow:DOMAIN\\jsmith" \
  --propagate-changes --progress
```

**Step 4: Transfer file ownership to manager:**
```bash
# Preview ownership changes first
./grumpwalk.py --host cluster --path /home/jsmith \
  --change-owner "DOMAIN\\jsmith:DOMAIN\\manager" \
  --propagate-changes --dry-run

# Execute the ownership transfer
./grumpwalk.py --host cluster --path /home/jsmith \
  --change-owner "DOMAIN\\jsmith:DOMAIN\\manager" \
  --propagate-changes --progress
```

### How do I transfer file ownership between users?

**Transfer ownership of a single directory:**
```bash
./grumpwalk.py --host cluster --path /projects/projectA \
  --change-owner "olduser:newuser"
```

**Transfer ownership recursively (all children):**
```bash
./grumpwalk.py --host cluster --path /shared/team-data \
  --change-owner "olduser:newuser" \
  --propagate-changes --progress
```

**Transfer ownership using UIDs (NFS environments):**
```bash
./grumpwalk.py --host cluster --path /nfs-exports/home \
  --change-owner "uid:1001:uid:2001" \
  --propagate-changes --progress
```

**Transfer both owner and group simultaneously:**
```bash
./grumpwalk.py --host cluster --path /projects/legacy \
  --change-owner "departed_user:new_owner" \
  --change-group "old_team:new_team" \
  --propagate-changes --progress
```

### How do I change ownership based on filters?

**Change ownership only for files (not directories):**
```bash
./grumpwalk.py --host cluster --path /data \
  --change-owner "olduser:newuser" \
  --type file \
  --propagate-changes --progress
```

**Change ownership only for old files:**
```bash
./grumpwalk.py --host cluster --path /archive \
  --change-owner "departed_user:archive_admin" \
  --older-than 365 \
  --propagate-changes --progress
```

**Change ownership only for large files:**
```bash
./grumpwalk.py --host cluster --path /media \
  --change-owner "contractor:media_team" \
  --larger-than 1GB \
  --type file \
  --propagate-changes --progress
```

**Change ownership for specific file types:**
```bash
./grumpwalk.py --host cluster --path /projects \
  --change-owner "developer1:developer2" \
  --name "*.py" --name "*.js" \
  --type file \
  --propagate-changes --progress
```

### How do I perform bulk ownership changes?

**Create a CSV file with ownership mappings:**
```csv
source,target
olduser1,newuser1
olduser2,newuser2
uid:1001,newuser3
OLDDOMAIN\jsmith,NEWDOMAIN\jsmith
```

**Preview bulk ownership changes:**
```bash
./grumpwalk.py --host cluster --path /data \
  --change-owners-file ownership_migration.csv \
  --propagate-changes --dry-run
```

**Execute bulk ownership changes:**
```bash
./grumpwalk.py --host cluster --path /data \
  --change-owners-file ownership_migration.csv \
  --propagate-changes --progress
```

**Bulk group changes from CSV:**
```bash
./grumpwalk.py --host cluster --path /shared \
  --change-groups-file group_migration.csv \
  --propagate-changes --progress
```

### How do I change group ownership?

**Change group for a directory tree:**
```bash
./grumpwalk.py --host cluster --path /projects/teamA \
  --change-group "old_team:new_team" \
  --propagate-changes --progress
```

**Change group using GIDs:**
```bash
./grumpwalk.py --host cluster --path /nfs-data \
  --change-group "gid:100:gid:200" \
  --propagate-changes --progress
```

**Combine owner and group changes:**
```bash
./grumpwalk.py --host cluster --path /shared/department \
  --change-owner "manager1:manager2" \
  --change-group "dept_old:dept_new" \
  --propagate-changes --progress
```

### How do I add a new team member to existing shares?

**Clone permissions from existing team member:**
```bash
./grumpwalk.py --host cluster --path /projects/teamA \
  --clone-ace-source "existing_member" \
  --clone-ace-target "new_member" \
  --propagate-changes --progress
```

**Or add explicit permissions:**
```bash
./grumpwalk.py --host cluster --path /projects/teamA \
  --add-ace "Allow:fd:new_member:Modify" \
  --propagate-changes --progress
```

### How do I copy an ACL from one directory to another?

Use `--source-acl` and `--acl-target` to clone an entire ACL (all ACEs, owner, and group) from a source path to a target path.

**Hint:** You can create and save one or more source directories with the ideal ACL to use as templates in some other location of the Qumulo cluster.

**Copy ACL to a single directory:**
```bash
./grumpwalk.py --host cluster \
  --source-acl /template/dir \
  --acl-target /target/dir
```

**Copy ACL and apply to all children recursively:**
```bash
./grumpwalk.py --host cluster \
  --source-acl /template/dir \
  --acl-target /target/dir \
  --propagate-acls --progress
```

**Copy ACL along with owner and group:**
```bash
./grumpwalk.py --host cluster \
  --source-acl /template/dir \
  --acl-target /target/dir \
  --copy-owner --copy-group \
  --propagate-acls --progress
```

**Copy only owner and group (no ACL changes):**
```bash
./grumpwalk.py --host cluster \
  --source-acl /template/dir \
  --acl-target /target/dir \
  --copy-owner --copy-group --owner-group-only \
  --propagate-acls
```

**Apply ACL only to files matching a filter:**
```bash
# Only apply to files older than 30 days
./grumpwalk.py --host cluster \
  --source-acl /template/dir \
  --acl-target /target/dir \
  --propagate-acls \
  --older-than 30 --type file \
  --progress
```

### How do I set POSIX permissions (like chmod)?

Use `--set-mode` with a standard octal mode to replace the ACL with clean POSIX-style permissions using the `OWNER@`, `GROUP@`, and `EVERYONE@` placeholders. This is the equivalent of running `chmod` via an NFS client.

**Set mode on a single file or directory:**
```bash
./grumpwalk.py --host cluster --set-mode 755 --path /data/project
```

**Recursive chmod (apply to all children):**
```bash
./grumpwalk.py --host cluster \
  --set-mode 755 --path /data/project \
  --propagate --progress
```

**Set mode with setgid on a shared directory:**

Setgid (`2xxx`) ensures new files inherit the parent directory's group. When propagating, setgid is applied to directories only -- files receive the base permissions without the setgid bit.

```bash
./grumpwalk.py --host cluster \
  --set-mode 2775 --path /data/shared \
  --propagate --progress
```

**Set sticky bit (restricted delete) on a shared directory:**

The sticky bit (`1xxx`) prevents users from deleting files they don't own, even if they have write access to the directory. Common on shared temp or drop-box directories.

```bash
./grumpwalk.py --host cluster \
  --set-mode 1777 --path /data/dropbox
```

**Controlling scope with --type:**

Use `--type` to restrict which objects `--set-mode` applies to. When `--type file` is specified, the target directory itself is left unchanged and only files inside the tree are modified. Likewise, `--type directory` applies only to directories.

```bash
# Set 644 on files only -- the target directory and subdirectories are untouched
./grumpwalk.py --host cluster \
  --set-mode 644 --path /data/project \
  --propagate --type file --progress

# Set 755 on directories only -- files are untouched
./grumpwalk.py --host cluster \
  --set-mode 755 --path /data/project \
  --propagate --type directory --progress
```

This is useful when files and directories need different permissions. Run `--set-mode` twice with different `--type` filters to apply 755 to directories and 644 to files, for example.

**Set permissions and change ownership at the same time:**

Use `--new-owner` and `--new-group` to specify explicit identities. This replaces the `OWNER@`/`GROUP@` placeholders in the ACL with the resolved identity and changes the file's actual ownership -- combining `chmod` and `chown` in one pass.

```bash
./grumpwalk.py --host cluster \
  --set-mode 2775 --path /data/shared \
  --new-owner uid:1001 --new-group gid:5000 \
  --propagate --progress
```

`--new-owner` and `--new-group` accept the same identity formats as other grumpwalk flags: `uid:N`, `gid:N`, `username`, `DOMAIN\user`, or a SID.

**Preview changes with dry-run:**
```bash
./grumpwalk.py --host cluster \
  --set-mode 750 --path /data/sensitive \
  --propagate --dry-run
```

### How do I keep two users' permissions in sync?

Use `--sync-cloned-aces` to update existing ACEs to match the source user's rights.

**Default behavior (without --sync-cloned-aces):**
```bash
# If joe already has an Allow ACE, it's skipped (no change)
./grumpwalk.py --host cluster --path /shared \
  --clone-ace-source bob --clone-ace-target joe \
  --propagate-changes
```

**With --sync-cloned-aces (updates existing ACEs):**
```bash
# Joe's existing Allow ACE is updated to match Bob's rights
./grumpwalk.py --host cluster --path /shared \
  --clone-ace-source bob --clone-ace-target joe \
  --sync-cloned-aces \
  --propagate-changes --progress
```

**Team member replacement workflow:**
```bash
# Alice (leaving) has carefully tuned permissions
# Bob (replacement) should have identical access

# Step 1: Initial clone - creates ACEs where Bob has none
./grumpwalk.py --host cluster --path /projects \
  --clone-ace-source alice --clone-ace-target bob \
  --propagate-changes --progress

# Step 2: Later, if Alice's permissions changed, sync Bob to match
./grumpwalk.py --host cluster --path /projects \
  --clone-ace-source alice --clone-ace-target bob \
  --sync-cloned-aces \
  --propagate-changes --progress
```

**Behavior summary:**

| Scenario | Without --sync-cloned-aces | With --sync-cloned-aces |
|----------|---------------------------|------------------------|
| Target has no ACE | Create new ACE | Create new ACE |
| Target has existing ACE | Skip (no change) | Update rights to match source |

### How do I implement least privilege access?

Following [NTFS permissions best practices](https://activedirectorypro.com/ntfs-permissions-management-best-practices/):

**Remove overly broad permissions:**
```bash
# Remove Everyone access
./grumpwalk.py --host cluster --path /sensitive \
  --remove-ace "Allow:Everyone" \
  --propagate-changes --dry-run

# If satisfied, run without --dry-run
```

**Downgrade from FullControl to Modify:**
```bash
./grumpwalk.py --host cluster --path /shared \
  --replace-ace "Allow:Domain Users" \
  --new-ace "Allow:fd:Domain Users:Modify" \
  --propagate-changes --progress
```

### How do I grant read-only access?

```bash
./grumpwalk.py --host cluster --path /published \
  --add-ace "Allow:fd:Readers_Group:Read" \
  --propagate-changes --progress
```

### How do I revoke write access while keeping read?

```bash
./grumpwalk.py --host cluster --path /archive \
  --remove-rights "Allow:Domain Users:w" \
  --propagate-changes --progress
```

### How do I disable inheritance on a directory tree?

Equivalent to Windows "Disable Inheritance" or `icacls /inheritance`:

**Convert inherited ACEs to explicit** (preserve all permissions, just break the link to parent):
```bash
./grumpwalk.py --host cluster --path /data/project \
  --disable-inheritance --propagate --progress
```

**Remove all inherited ACEs** (strip inherited entries, keep only explicitly-set ones):
```bash
./grumpwalk.py --host cluster --path /data/project \
  --disable-inheritance --remove-inherited --propagate --progress
```

**Preview first with dry-run:**
```bash
./grumpwalk.py --host cluster --path /data/project \
  --disable-inheritance --remove-inherited --propagate --dry-run --verbose
```

> **Tip:** If you want to strip inherited entries and set a clean POSIX ACL in one step, `--set-mode` replaces the entire ACL:
> ```bash
> ./grumpwalk.py --host cluster --set-mode 755 --path /data/project --propagate --progress
> ```

---

## Domain Migration

### How do I migrate permissions during an AD domain migration?

**Step 1: Create migration CSV file:**
```csv
source,target
OLDDOMAIN\user1,NEWDOMAIN\user1
OLDDOMAIN\user2,NEWDOMAIN\user2
OLDDOMAIN\GroupA,NEWDOMAIN\GroupA
OLDDOMAIN\Domain Users,NEWDOMAIN\Domain Users
OLDDOMAIN\Domain Admins,NEWDOMAIN\Domain Admins
```

**Step 2: Dry-run the migration:**
```bash
./grumpwalk.py --host cluster --path /data \
  --migrate-trustees domain_migration.csv \
  --dry-run
```

**Step 3: Execute the migration:**
```bash
./grumpwalk.py --host cluster --path /data \
  --migrate-trustees domain_migration.csv \
  --propagate-changes \
  --ace-backup pre_migration_acls.json \
  --progress
```

### How do I migrate from NFS UIDs to AD accounts?

**Create UID to AD mapping:**
```csv
source,target
uid:1001,NEWDOMAIN\alice
uid:1002,NEWDOMAIN\bob
uid:1003,NEWDOMAIN\charlie
gid:100,NEWDOMAIN\Engineering
gid:200,NEWDOMAIN\Sales
```

**Execute migration:**
```bash
./grumpwalk.py --host cluster --path /nfs-data \
  --migrate-trustees uid_to_ad.csv \
  --propagate-changes --progress
```

### How do I clone permissions for a new parallel structure?

```bash
# Create mapping for team restructuring
cat > team_restructure.csv << EOF
source,target
TeamA_Leads,NewTeam_Leads
TeamA_Members,NewTeam_Members
TeamB_Leads,NewTeam_Leads
TeamB_Members,NewTeam_Members
EOF

./grumpwalk.py --host cluster --path /projects \
  --clone-ace-map team_restructure.csv \
  --propagate-changes --progress
```

### How do I migrate file ownership during domain migration?

File ownership migration is separate from ACL/ACE migration. Use `--change-owner` and `--change-group` for ownership:

**Step 1: Create ownership migration CSV:**
```csv
source,target
OLDDOMAIN\user1,NEWDOMAIN\user1
OLDDOMAIN\user2,NEWDOMAIN\user2
OLDDOMAIN\service_account,NEWDOMAIN\service_account
```

**Step 2: Preview ownership changes:**
```bash
./grumpwalk.py --host cluster --path /data \
  --change-owners-file owner_migration.csv \
  --propagate-changes --dry-run
```

**Step 3: Execute ownership migration:**
```bash
./grumpwalk.py --host cluster --path /data \
  --change-owners-file owner_migration.csv \
  --propagate-changes --progress
```

### How do I migrate both ACLs and ownership together?

For a complete domain migration, you typically need to migrate both ACEs and file ownership:

**Complete domain migration script:**
```bash
#!/bin/bash
CLUSTER="cluster.example.com"
PATH="/data"
ACE_CSV="ace_migration.csv"
OWNER_CSV="owner_migration.csv"
GROUP_CSV="group_migration.csv"

# Step 1: Backup current ACLs
./grumpwalk.py --host $CLUSTER --path $PATH \
  --acl-report --acl-resolve-names \
  --json-out pre_migration_acls.json

# Step 2: Migrate ACE trustees (permissions)
./grumpwalk.py --host $CLUSTER --path $PATH \
  --migrate-trustees $ACE_CSV \
  --propagate-changes --progress

# Step 3: Migrate file owners
./grumpwalk.py --host $CLUSTER --path $PATH \
  --change-owners-file $OWNER_CSV \
  --propagate-changes --progress

# Step 4: Migrate file groups
./grumpwalk.py --host $CLUSTER --path $PATH \
  --change-groups-file $GROUP_CSV \
  --propagate-changes --progress
```

### How do I migrate NFS UID/GID ownership to AD accounts?

**Create ownership mapping CSV:**
```csv
source,target
uid:1001,NEWDOMAIN\alice
uid:1002,NEWDOMAIN\bob
uid:1003,NEWDOMAIN\charlie
```

**Create group ownership mapping CSV:**
```csv
source,target
gid:100,NEWDOMAIN\Engineering
gid:200,NEWDOMAIN\Sales
gid:300,NEWDOMAIN\Marketing
```

**Execute NFS to AD ownership migration:**
```bash
# Migrate owners
./grumpwalk.py --host cluster --path /nfs-data \
  --change-owners-file uid_to_ad_owners.csv \
  --propagate-changes --progress

# Migrate groups
./grumpwalk.py --host cluster --path /nfs-data \
  --change-groups-file gid_to_ad_groups.csv \
  --propagate-changes --progress
```

### How do I consolidate ownership after an acquisition?

When merging companies, you may need to consolidate file ownership:

**Create consolidation mapping:**
```csv
source,target
ACQUIRED_DOMAIN\user1,PARENT_DOMAIN\user1
ACQUIRED_DOMAIN\user2,PARENT_DOMAIN\user2
ACQUIRED_DOMAIN\admin,PARENT_DOMAIN\admin
```

**Migrate in phases by department:**
```bash
# Phase 1: Engineering
./grumpwalk.py --host cluster --path /acquired/engineering \
  --change-owners-file consolidation.csv \
  --propagate-changes --progress

# Phase 2: Sales
./grumpwalk.py --host cluster --path /acquired/sales \
  --change-owners-file consolidation.csv \
  --propagate-changes --progress

# Phase 3: Remaining
./grumpwalk.py --host cluster --path /acquired \
  --change-owners-file consolidation.csv \
  --propagate-changes --progress
```

### How do I handle mixed identity environments?

When migrating environments with both AD and NFS identities:

**Create comprehensive mapping:**
```csv
source,target
# AD users
OLDDOMAIN\alice,NEWDOMAIN\alice
OLDDOMAIN\bob,NEWDOMAIN\bob
# NFS UIDs that map to AD
uid:1001,NEWDOMAIN\alice
uid:1002,NEWDOMAIN\bob
# Service accounts
OLDDOMAIN\svc_backup,NEWDOMAIN\svc_backup
```

**Execute with combined CSV:**
```bash
./grumpwalk.py --host cluster --path /mixed-data \
  --change-owners-file comprehensive_migration.csv \
  --propagate-changes --progress
```

---

## Compliance and Auditing

### How do I generate a permissions audit report?

```bash
./grumpwalk.py --host cluster --path /sensitive \
  --acl-report \
  --acl-resolve-names \
  --acl-csv permissions_audit.csv \
  --progress
```

**Audit directory ACLs only (much faster):**
```bash
./grumpwalk.py --host cluster --path /sensitive \
  --acl-report \
  --acl-resolve-names \
  --acl-csv permissions_audit.csv \
  --type directory \
  --progress
```

If you only need ACLs for directories (a common audit pattern), adding `--type directory` is significantly faster: grumpwalk skips enumeration of leaf directories that contain only files.

### How do I find files with specific permissions?

**Find files accessible by Everyone:**
```bash
./grumpwalk.py --host cluster --path /data \
  --acl-report --progress | \
  grep -i "everyone"
```

### How do I identify GDPR data retention violations?

**Find personal data older than retention period:**
```bash
./grumpwalk.py --host cluster --path /customer-data \
  --older-than 1095 \
  --type file \
  --csv-out gdpr_retention_review.csv
```

**Find files in regulated directories not accessed in required period:**
```bash
./grumpwalk.py --host cluster --path /financial-records \
  --accessed --older-than 2555 \
  --type file --progress
```

### How do I audit who has access to sensitive directories?

```bash
./grumpwalk.py --host cluster --path /hr/confidential \
  --acl-report --acl-resolve-names --max-depth 1
```


---

## Security and Incident Response

### How do I identify files modified during a suspected breach?

**Find files modified in the last 24 hours:**
```bash
./grumpwalk.py --host cluster --path /data \
  --modified --newer-than 1 \
  --type file --progress \
  --json-out modified_24h.json
```

**Find files modified during specific attack window (combined with timestamps):**
```bash
./grumpwalk.py --host cluster --path /data \
  --modified --newer-than 3 \
  --json --all-attributes \
  --type file | \
  jq 'select(.modification_time > "2024-01-15T00:00:00" and .modification_time < "2024-01-15T12:00:00")'
```

### How do I find potentially encrypted files (ransomware)?

**Find files with suspicious extensions:**
```bash
./grumpwalk.py --host cluster --path /data \
  --name '*.encrypted' --name '*.locked' --name '*.crypto' \
  --name '*.crypt' --name '*.enc' --name '*.crypted' \
  --type file --progress
```

**Find ransom note files:**
```bash
./grumpwalk.py --host cluster --path /data \
  --name '*README*' --name '*DECRYPT*' --name '*RECOVER*' \
  --name '*INSTRUCTION*' --name '*HOW_TO*' \
  --modified --newer-than 7 \
  --type file
```

### How do I identify unusual file permission changes?

**Find files where Everyone has write access:**
```bash
./grumpwalk.py --host cluster --path /data \
  --acl-report --json | \
  jq 'select(.trustees[] | contains("EVERYONE@") and contains("w"))'
```

### How do I find recently created executable content?

```bash
./grumpwalk.py --host cluster --path /data \
  --name '*.exe' --name '*.dll' --name '*.bat' --name '*.ps1' \
  --name '*.sh' --name '*.py' --name '*.js' \
  --created --newer-than 7 \
  --type file
```

### How do I audit access after a security incident?

```bash
# Generate comprehensive ACL report
./grumpwalk.py --host cluster --path /compromised-share \
  --acl-report \
  --acl-resolve-names \
  --show-owner \
  --show-group \
  --acl-csv incident_acl_audit.csv \
  --progress
```

### How do I lock down a directory during investigation?

**Backup current ACLs and add deny:**
```bash
./grumpwalk.py --host cluster --path /investigation \
  --add-ace "Deny::Everyone:w" \
  --ace-backup investigation_original_acls.json \
  --propagate-changes --progress
```

### How do I restore ACLs after investigation is complete?

**Preview the restore (dry run):**
```bash
./grumpwalk.py --host cluster \
  --ace-restore investigation_original_acls.json --dry-run
```

**Restore ACLs to the original path:**
```bash
./grumpwalk.py --host cluster \
  --ace-restore investigation_original_acls.json
```

**Restore and propagate to all children:**
```bash
./grumpwalk.py --host cluster \
  --ace-restore investigation_original_acls.json \
  --propagate-changes --progress
```

**If the file/directory was renamed, use --force-restore:**
```bash
# The backup contains the original file_id for safety verification
# If the current path has a different file_id (e.g., path was reused),
# grumpwalk will refuse to restore unless --force-restore is used
./grumpwalk.py --host cluster \
  --ace-restore investigation_original_acls.json \
  --force-restore
```

**Restore to a different path:**
```bash
# Use --path to override the original path stored in the backup
./grumpwalk.py --host cluster --path /new/location \
  --ace-restore investigation_original_acls.json \
  --force-restore --propagate-changes
```

---

## Duplicate and Similar File Detection

### How do I find duplicate files?

**Find similar files using content sampling:**
```bash
./grumpwalk.py --host cluster --path /backups \
  --find-similar \
  --progress \
  --csv-out potential_duplicates.csv
```

**Estimate data transfer before scanning:**
```bash
./grumpwalk.py --host cluster --path /data \
  --find-similar --estimate-size
```

### How do I find duplicates quickly (less accurate)?

```bash
./grumpwalk.py --host cluster --path /data \
  --find-similar --by-size \
  --progress
```

### How do I tune similarity detection for accuracy?

**Higher accuracy (more data transfer):**
```bash
./grumpwalk.py --host cluster --path /important \
  --find-similar \
  --sample-size 256KB \
  --sample-points 11 \
  --progress
```

**Lower accuracy, faster (less data transfer):**
```bash
./grumpwalk.py --host cluster --path /archives \
  --find-similar \
  --sample-size 32KB \
  --sample-points 5 \
  --progress
```

### How do I find duplicate large files specifically?

```bash
./grumpwalk.py --host cluster --path /data \
  --larger-than 100MB \
  --type file \
  --find-similar \
  --progress \
  --csv-out large_duplicates.csv
```

---

## Media and Creative Workflows

### How do I find large media files?

```bash
./grumpwalk.py --host cluster --path /media \
  --name '*.mov' --name '*.mp4' --name '*.mxf' --name '*.r3d' \
  --name '*.ari' --name '*.braw' --name '*.prores' \
  --larger-than 1GB \
  --type file --progress
```

### How do I find old project files for archival?

```bash
./grumpwalk.py --host cluster --path /projects \
  --accessed --older-than 180 \
  --modified --older-than 180 \
  --larger-than 100MB \
  --type file \
  --csv-out archive_candidates.csv
```

### How do I identify render cache files for cleanup?

```bash
./grumpwalk.py --host cluster --path /renders \
  --name '*.tmp' --name '*cache*' --name '*preview*' \
  --name '*.peak' --name '*.pek' --name '*.pkf' \
  --older-than 30 \
  --type file
```

### How do I find proxy files vs original media?

```bash
# Find proxy files
./grumpwalk.py --host cluster --path /media \
  --name '*proxy*' --name '*_lowres*' --name '*_small*' \
  --type file \
  --json-out proxies.json

# Find original high-res
./grumpwalk.py --host cluster --path /media \
  --name '*.r3d' --name '*.braw' --name '*.ari' \
  --larger-than 1GB \
  --type file \
  --json-out originals.json
```

### How do I audit project folder structures?

```bash
./grumpwalk.py --host cluster --path /projects \
  --show-dir-stats --max-depth 3 --progress
```

---

## Reporting and Analytics

### How do I generate a full inventory?

```bash
./grumpwalk.py --host cluster --path / \
  --all-attributes \
  --progress \
  > full_inventory.ndjson
```

### How do I export to CSV for Excel analysis?

```bash
./grumpwalk.py --host cluster --path /data \
  --older-than 365 \
  --type file \
  --csv-out old_files.csv
```

### How do I analyze results with jq?

**Note:** These examples assume `inventory.ndjson` was created with `--json --all-attributes`:
```bash
./grumpwalk.py --host cluster --path /data --json --all-attributes > inventory.ndjson
```

**Count files by extension:**
```bash
cat inventory.ndjson | \
  jq -r '.name | split(".") | .[-1] | ascii_downcase' | \
  sort | uniq -c | sort -rn | head -20
```

**Sum total size:**
```bash
cat inventory.ndjson | jq -s 'map(.size | tonumber) | add'
```

**Group by owner:**
```bash
cat inventory.ndjson | \
  jq -r '.owner' | sort | uniq -c | sort -rn
```

**Find paths with most files:**
```bash
cat inventory.ndjson | \
  jq -r '.path | split("/")[1:3] | join("/")' | \
  sort | uniq -c | sort -rn | head -20
```

### How do I get raw UID/GID/SID values without name resolution?

Use `--dont-resolve-ids` with `--show-owner` or `--show-group` to skip identity API calls and output raw identifiers. This is faster and useful when you need the actual UID/GID/SID values rather than human-readable names.

**Plain text output:**
```bash
./grumpwalk.py --host cluster --path /data \
  --show-owner --show-group --dont-resolve-ids
```

Output:
```
/data/file1.txt	UID:1001	GID:100
/data/file2.txt	SID:S-1-5-21-3192274952-881459882-370606532-1352	SID:S-1-5-21-3192274952-881459882-370606532-513
```

**CSV export with raw IDs:**
```bash
./grumpwalk.py --host cluster --path /home \
  --show-owner --show-group --dont-resolve-ids \
  --csv-out ownership_raw.csv
```

**JSON output with raw IDs:**
```bash
./grumpwalk.py --host cluster --path /data \
  --show-owner --dont-resolve-ids --json
```

Output format reference:

| ID Type | Output Format | Example |
|---------|---------------|---------|
| NFS UID | `UID:<value>` | `UID:1001` |
| NFS GID | `GID:<value>` | `GID:100` |
| SMB SID | `SID:<value>` | `SID:S-1-5-21-...` |
| Local account | `auth_id:<value>` | `auth_id:admin` |

### How do I select specific output fields?

Use `--fields` to choose exactly which columns appear in output. This reduces file size and avoids post-processing to strip unwanted columns.

**Output only path, size, and owner SID:**
```bash
./grumpwalk.py --host cluster --path /data --json \
  --fields path,size,owner_id --type file --limit 10
```

Output:
```json
{"path": "/data/report.pdf", "size": "1048576", "owner_id": "S-1-5-21-123456-1109"}
```

**CSV with selected fields:**
```bash
./grumpwalk.py --host cluster --path /data \
  --fields path,size,modification_time,owner_id \
  --csv-out inventory.csv --progress
```

**Include resolved owner names** (identity resolution runs automatically):
```bash
./grumpwalk.py --host cluster --path /home --json \
  --fields path,size,owner_name,group_name
```

**Extract individual extended attributes:**
```bash
./grumpwalk.py --host cluster --path /data --json \
  --fields path,attr.archive,attr.read_only --type file
```

**Plain text with multiple fields** (tab-separated):
```bash
./grumpwalk.py --host cluster --path /data \
  --fields path,size,modification_time --type file
```
Bare `--fields` (above) streams a tab-separated projection with raw byte sizes.
For a readable **aligned table with human-readable sizes**, add `--show-details`
(or use it alone for the default `path,size,change_time` columns). `--show-details`
is also what enables attribute output for **snapshot search**, where bare `--fields`
implies it:
```bash
./grumpwalk.py --host cluster --path /data --show-details --fields path,size,owner_name
```
Get every attribute with `--fields all` (implies `--show-details`):
```bash
./grumpwalk.py --host cluster --snapshot 5 --path /Shared --name '*.docx' \
  --fields all --csv-out report.csv
```

Full dot notation also works for any nested field:
```bash
./grumpwalk.py --host cluster --path /data --json \
  --fields path,owner_details.id_type,owner_details.id_value
```

Use `--fields-list` to see all available field names and descriptions:
```bash
./grumpwalk.py --fields-list
```

**Available aliases:**

| Alias | Resolves to | Description |
|-------|-------------|-------------|
| `owner_id` | `owner_details.id_value` | Owner SID or UID |
| `owner_type` | `owner_details.id_type` | NFS_UID, SMB_SID, etc. |
| `group_id` | `group_details.id_value` | Group SID or GID |
| `group_type` | `group_details.id_type` | NFS_GID, SMB_SID, etc. |
| `attr.<name>` | `extended_attributes.<name>` | Individual attribute flag |

### How do I output timestamps as unix epoch seconds?

Use `--unix-time` to convert all timestamp fields to integer epoch seconds. This is useful when feeding output into databases or tools that expect numeric timestamps.

```bash
./grumpwalk.py --host cluster --path /data --json \
  --fields path,modification_time --unix-time --type file --limit 3
```

Output:
```json
{"path": "/data/file.txt", "modification_time": 1730927563}
```

Works with any output mode and combines with `--fields`:
```bash
# CSV with epoch timestamps
./grumpwalk.py --host cluster --path /data \
  --fields path,size,creation_time,modification_time \
  --unix-time --csv-out data.csv

# Full inventory with epoch timestamps
./grumpwalk.py --host cluster --path / --json --all-attributes --unix-time > inventory.ndjson
```

Stderr and logging timestamps are not affected by this flag.

### How do I analyze with DuckDB?

```sql
-- Create table from NDJSON
CREATE TABLE files AS SELECT * FROM read_ndjson_auto('inventory.ndjson');

-- Storage by owner (top 20)
SELECT owner,
       COUNT(*) as file_count,
       SUM(size) / (1024*1024*1024) as total_gb
FROM files
GROUP BY owner
ORDER BY total_gb DESC
LIMIT 20;

-- Files by age bucket
SELECT
  CASE
    WHEN creation_time > CURRENT_DATE - INTERVAL 30 DAY THEN '0-30 days'
    WHEN creation_time > CURRENT_DATE - INTERVAL 90 DAY THEN '30-90 days'
    WHEN creation_time > CURRENT_DATE - INTERVAL 365 DAY THEN '90-365 days'
    ELSE '1+ years'
  END as age_bucket,
  COUNT(*) as file_count,
  SUM(size) / (1024*1024*1024) as total_gb
FROM files
GROUP BY age_bucket;
```

### How do I analyze with Python?

```python
import json

total_size = 0
file_count = 0
owners = {}

with open('inventory.ndjson') as f:
    for line in f:
        file = json.loads(line)
        total_size += file.get('size', 0)
        file_count += 1

        owner = file.get('owner', 'unknown')
        if owner not in owners:
            owners[owner] = {'count': 0, 'size': 0}
        owners[owner]['count'] += 1
        owners[owner]['size'] += file.get('size', 0)

print(f"Total files: {file_count:,}")
print(f"Total size: {total_size / (1024**4):.2f} TB")

# Top 10 owners by size
for owner, stats in sorted(owners.items(), key=lambda x: x[1]['size'], reverse=True)[:10]:
    print(f"{owner}: {stats['count']:,} files, {stats['size'] / (1024**3):.2f} GB")
```

---

## Performance Optimization

### How do I use auto-tuning?

Grumpwalk automatically detects your system resources and generates optimal performance settings on first run. A tuning profile is saved to `tuning-profile` in the grumpwalk directory.

**View current tuning profile:**
```bash
./grumpwalk.py --show-tuning
```

**Regenerate tuning profile:**
```bash
./grumpwalk.py --retune
```

**Select a tuning profile:**
```bash
# Conservative (lower concurrency, safer for constrained systems)
./grumpwalk.py --host cluster --path /data --tuning-profile conservative

# Balanced (default, good for most systems)
./grumpwalk.py --host cluster --path /data --tuning-profile balanced

# Aggressive (higher concurrency, for well-resourced systems)
./grumpwalk.py --host cluster --path /data --tuning-profile aggressive
```

### How do I benchmark my cluster?

The `--benchmark` flag tests multiple concurrency levels against your cluster and suggests optimal settings based on actual throughput measurements.

**Run a benchmark:**
```bash
./grumpwalk.py --host cluster --path /data --benchmark
```

This will:
1. Test concurrency levels: 100, 150, 200, 250, 300, 400
2. Measure throughput (objects/second) at each level
3. Identify the optimal setting for your cluster
4. Offer to save the results to your tuning profile

**Example output:**
```
======================================================================
Benchmark Results:
  Concurrent | Rate (obj/sec) | Time
  -----------|----------------|------
         100 |         17,066 | 6.8s
         150 |         17,628 | 6.6s
         200 |         17,803 | 6.5s
         250 |         16,288 | 7.1s
         300 |         18,061 | 6.4s *
         400 |         13,456 | 8.6s

Suggested settings:
  max-concurrent:  300
  connector-limit: 300
  acl-concurrency: 240
======================================================================
```

The `*` marks the optimal concurrency level. Note that higher concurrency does not always mean better throughput - cluster and network capacity are often the bottleneck, not local resources.

### How do I maximize crawl speed?

**For large clusters (>10M files): REVIEW RAM USE GUIDELINES FIRST!**
```bash
./grumpwalk.py --host cluster --path /data \
  --max-concurrent 500 \
  --connector-limit 500 \
  --progress
```

**Use type filters when possible:**

When you only need files, use `--type file`. When you only need directories, use `--type directory`. Grumpwalk uses recursive aggregates to skip entire subtrees that cannot contain matches -- e.g. with `--type directory`, leaf directories containing only files are never enumerated.

**Skip identity resolution when you only need raw IDs:**
```bash
./grumpwalk.py --host cluster --path /data \
  --show-owner --dont-resolve-ids \
  --progress
```

This avoids API calls to `/v1/identity/expand` for every unique owner/group, which can be a significant bottleneck on large result sets.

### How do I profile performance bottlenecks?

```bash
./grumpwalk.py --host cluster --path /data \
  --profile --progress \
  --limit 10000
```

### How do I reduce memory usage?

Memory usage scales primarily with the number of subdirectories being traversed, not the number of files. The main memory consumers are:

| Component | Impact | Tunable |
|-----------|--------|---------|
| Subdirectory queue | O(num_dirs) - paths held for processing | Partial |
| Concurrency buffers | O(max_concurrent) - async task overhead | Yes |
| Identity cache | O(unique_owners) - auth_id mappings | No |
| Connection pool | O(connector_limit) - HTTP connections | Yes |

**Reduce concurrency for memory-constrained systems:**
```bash
# For systems with <8GB RAM
./grumpwalk.py --host cluster --path /data \
  --max-concurrent 25 \
  --connector-limit 25 \
  --progress
```

**Process output in streaming fashion:**
```bash
# Stream directly to compressed file (minimal memory)
./grumpwalk.py --host cluster --path /data --progress | \
  gzip > inventory.ndjson.gz

# Stream to CSV file (writes rows incrementally)
./grumpwalk.py --host cluster --path /data \
  --csv-out inventory.csv \
  --progress
```

**Limit traversal depth:**
```bash
# Process shallower trees to limit queued directories
./grumpwalk.py --host cluster --path /data \
  --max-depth 5 \
  --progress
```

**Process large trees in segments:**
```bash
# Instead of crawling /data with 500k subdirectories at once,
# process top-level directories separately
for dir in project1 project2 project3; do
  ./grumpwalk.py --host cluster --path /data/$dir \
    --csv-out ${dir}_inventory.csv \
    --progress
done
```

**Limit results for quick checks:**
```bash
./grumpwalk.py --host cluster --path /data \
  --older-than 365 \
  --limit 1000
```

### Memory Planning Guide

Use this formula to estimate RAM requirements:

```
RAM (GB) ~ (subdirectories / 50000) + (max_concurrent * 0.05) + 0.5
```

**Example calculations:**
- 50k subdirs, default concurrency: `50000/50000 + 100*0.05 + 0.5 = 6.5 GB`
- 500k subdirs, default concurrency: `500000/50000 + 100*0.05 + 0.5 = 15.5 GB`
- 500k subdirs, reduced concurrency: `500000/50000 + 25*0.05 + 0.5 = 11.75 GB`

**Recommended configurations by available RAM:**

| Available RAM | --max-concurrent | --connector-limit | Notes |
|---------------|------------------|-------------------|-------|
| 4 GB | 25 | 25 | Use --max-depth or segment paths |
| 8 GB | 50 | 50 | OK for <100k directories |
| 16 GB | 100 | 100 | Default, handles most cases |
| 32+ GB | 200-500 | 200 | High performance mode |

**Low-memory configuration example:**
```bash
# For 4GB RAM systems with large directory trees
./grumpwalk.py --host cluster --path /data \
  --max-concurrent 25 \
  --connector-limit 25 \
  --max-depth 3 \
  --csv-out inventory.csv \
  --progress
```

### How do I handle very large directories?

**Skip directories with too many entries:**
```bash
./grumpwalk.py --host cluster --path /data \
  --max-entries-per-dir 100000 \
  --progress
```

**Skip known large or irrelevant directories:**
```bash
./grumpwalk.py --host cluster --path /data \
  --omit-subdirs '.snapshot' \
  --omit-subdirs 'tmp' \
  --omit-subdirs 'cache' \
  --progress
```

**Skip specific paths entirely:**
```bash
./grumpwalk.py --host cluster --path / \
  --omit-path /var/log \
  --omit-path /tmp \
  --omit-path /scratch \
  --progress
```

---

## Scripting and Automation

### How do I run grumpwalk in a scheduled job?

```bash
#!/bin/bash
# daily_inventory.sh

DATE=$(date +%Y%m%d)
CLUSTER="cluster.example.com"
OUTPUT_DIR="/reports"

# Generate daily inventory
./grumpwalk.py --host $CLUSTER --path /data \
  --progress \
  > "${OUTPUT_DIR}/inventory_${DATE}.ndjson" 2> "${OUTPUT_DIR}/inventory_${DATE}.log"

# Compress older inventories
find ${OUTPUT_DIR} -name "inventory_*.ndjson" -mtime +7 -exec gzip {} \;

# Clean up inventories older than 30 days
find ${OUTPUT_DIR} -name "inventory_*.ndjson.gz" -mtime +30 -delete
```

### How do I create an alerting script for stale data?

```bash
#!/bin/bash
# stale_data_alert.sh

THRESHOLD_GB=1000
CLUSTER="cluster.example.com"

# Find stale data (not accessed in 365 days)
STALE_SIZE=$(./grumpwalk.py --host $CLUSTER --path /data \
  --accessed --older-than 365 \
  --json --all-attributes \
  --type file 2>/dev/null | \
  jq -s 'map(.size | tonumber) | add // 0' | \
  awk '{print int($1/1024/1024/1024)}')

if [ "$STALE_SIZE" -gt "$THRESHOLD_GB" ]; then
  echo "ALERT: ${STALE_SIZE}GB of stale data found (threshold: ${THRESHOLD_GB}GB)"
  # Send email/Slack notification here
fi
```

### How do I automate permission reports?

```bash
#!/bin/bash
# weekly_permission_audit.sh

DATE=$(date +%Y%m%d)
CLUSTER="cluster.example.com"
SENSITIVE_PATHS="/hr/confidential /finance/restricted /legal/privileged"

for PATH in $SENSITIVE_PATHS; do
  SAFE_NAME=$(echo $PATH | tr '/' '_')
  ./grumpwalk.py --host $CLUSTER --path $PATH \
    --acl-report \
    --acl-resolve-names \
    --acl-csv "acl_audit${SAFE_NAME}_${DATE}.csv" \
    --progress 2>&1 | tee "acl_audit${SAFE_NAME}_${DATE}.log"
done
```

### How do I pipe grumpwalk output to other tools?

**To jq for filtering:**
```bash
./grumpwalk.py --host cluster --path /data \
  --json --all-attributes | \
  jq 'select((.size | tonumber) > 1073741824)' > large_files.json
```

**To gzip for compression:**
```bash
./grumpwalk.py --host cluster --path / --progress | \
  gzip > full_inventory.ndjson.gz
```

**To xargs for further processing:**
```bash
# Default output is one path per line, perfect for xargs
./grumpwalk.py --host cluster --path /tmp \
  --name '*.tmp' --older-than 7 --type file | \
  xargs -I {} echo "Would delete: {}"
```

---

## Quick Reference Card

### Most Common Commands

| Task | Command |
|------|---------|
| Directory stats | `--path /data --stats` |
| Subdirectory breakdown | `--path /data --stats --max-depth 1` |
| Stats sorted by size | `--path /data --stats --max-depth 1 --sort size` |
| Full inventory | `--path / --progress > inventory.ndjson` |
| Find large files | `--larger-than 1GB --type file` |
| Find old files | `--older-than 365 --type file` |
| Find by name | `--name '*.log'` |
| Owner report | `--owner-report --progress` |
| Show raw IDs | `--show-owner --dont-resolve-ids` |
| ACL audit | `--acl-report --acl-resolve-names` |
| Add permission | `--add-ace 'Allow:fd:Group:Modify' --propagate-changes` |
| Remove permission | `--remove-ace 'Allow:Everyone' --propagate-changes` |
| Disable inheritance (convert) | `--disable-inheritance --path /data --propagate` |
| Disable inheritance (remove) | `--disable-inheritance --remove-inherited --path /data --propagate` |
| Set POSIX mode | `--set-mode 755 --path /data` |
| Recursive chmod | `--set-mode 755 --path /data --propagate` |
| chmod + chown | `--set-mode 755 --path /data --new-owner uid:1001 --new-group gid:5000 --propagate` |
| Change owner | `--change-owner 'old:new' --propagate-changes` |
| Change group | `--change-group 'old:new' --propagate-changes` |
| Bulk owner migration | `--change-owners-file migration.csv --propagate-changes` |
| Backup ACL | `--ace-backup backup.json` (with any ACE operation) |
| Restore ACL | `--ace-restore backup.json` |
| Find duplicates | `--find-similar --progress` |
| Dry run | `--dry-run` (add to any modification command) |

### Size Suffixes

| Suffix | Meaning |
|--------|---------|
| `KB` | Kilobytes (1000) |
| `KiB` | Kibibytes (1024) |
| `MB` | Megabytes |
| `MiB` | Mebibytes |
| `GB` | Gigabytes |
| `GiB` | Gibibytes |
| `TB` | Terabytes |
| `TiB` | Tebibytes |

### Time Field Shortcuts

| Flag | Time Field |
|------|------------|
| `--created` | creation_time |
| `--modified` | modification_time |
| `--accessed` | access_time |
| `--changed` | change_time |

### ACE Pattern Quick Reference

| Pattern | Meaning |
|---------|---------|
| `Allow:fd:User:Modify` | Allow, file+dir inherit, Modify rights |
| `Deny::Everyone:w` | Deny, no inheritance, write only |
| `Allow:fd:Group:Read` | Allow, file+dir inherit, Read rights |
| `Allow:fd:User:FullControl` | Allow, file+dir inherit, all rights |

### ACE Operation Behavior

| Operation | When trustee exists | When trustee doesn't exist |
|-----------|--------------------|-----------------------------|
| `--add-ace` | Merges rights with existing ACE | Creates new ACE |
| `--replace-ace` (alone) | Replaces flags and rights in-place | No change |
| `--replace-ace` + `--new-ace` | Replaces first match, removes duplicates | No change |

**Important:** When using `--replace-ace` with `--new-ace`:
- The `--replace-ace` pattern is a **search pattern** using `Type:Trustee` format only
- If multiple ACEs match the same trustee, all are consolidated into one
- The first match is replaced; additional matches are deleted

**Example:** If an ACL has three ACEs for "Domain Users" (Read, Write, Execute), running:
```bash
--replace-ace "Allow:Domain Users" --new-ace "Allow:fd:Domain Users:Modify"
```
Results in a single ACE with Modify rights; the other two are removed.

### Inheritance Handling

When modifying an inherited ACE, grumpwalk automatically:
1. Breaks inheritance at the target path (sets PROTECTED control flag)
2. Converts inherited ACEs to explicit (removes INHERITED flag)
3. Applies your modifications

This establishes the target as a new inheritance root. Use `--propagate-changes` to push the modified ACL to children.

### Disabling Inheritance

Use `--disable-inheritance` for standalone inheritance control, equivalent to Windows "Disable Inheritance" or `icacls /inheritance`:

**Convert inherited ACEs to explicit** (keeps all entries, removes INHERITED flag):
```bash
./grumpwalk.py --host cluster --path /data/project \
  --disable-inheritance --propagate --progress
```

**Remove all inherited ACEs** (deletes inherited entries, keeps only explicit):
```bash
./grumpwalk.py --host cluster --path /data/project \
  --disable-inheritance --remove-inherited --propagate --progress
```

| Mode | Equivalent | Explicit ACEs | Inherited ACEs |
|------|-----------|---------------|----------------|
| `--disable-inheritance` | `icacls /inheritance:d` | Kept | Converted to explicit |
| `--disable-inheritance --remove-inherited` | `icacls /inheritance:r` | Kept | Deleted |

> **Note:** If all ACEs on an object are inherited, `--remove-inherited` will leave it with no ACEs. Use `--dry-run` to preview before applying. Both modes set the PROTECTED control flag to block future inheritance from parent directories.

**Restarting inheritance** from a parent after disabling it:
```bash
./grumpwalk.py --host cluster.example.com \
  --source-acl /parent/path --acl-target /child/path \
  --propagate-acls --progress
```

### Owner/Group Change Pattern Quick Reference

| Pattern | Meaning |
|---------|---------|
| `olduser:newuser` | Simple username change |
| `uid:1001:uid:2001` | UID to UID (NFS) |
| `gid:100:gid:200` | GID to GID (NFS) |
| `DOMAIN\old:DOMAIN\new` | AD user/group change |
| `uid:1001:DOMAIN\user` | UID to AD user |
| `OLDDOMAIN\user:NEWDOMAIN\user` | Cross-domain migration |

### Propagation Flag

The `--propagate-changes` flag applies modifications recursively to all children (note: `--propagate-acls` is also accepted):

| Without flag | Only the target path is modified |
|--------------|----------------------------------|
| With flag | Target path and all descendants are modified |

Works with:
- ACE operations (`--add-ace`, `--remove-ace`, `--replace-ace`, etc.)
- Inheritance control (`--disable-inheritance`, `--disable-inheritance --remove-inherited`)
- Owner/group changes (`--change-owner`, `--change-group`)
- Trustee migration (`--migrate-trustees`)
- ACE cloning (`--clone-ace-source/--clone-ace-target`)
- ACL restore (`--ace-restore`)

### ACL Backup and Restore

| Operation | Command |
|-----------|---------|
| Backup ACL | `--ace-backup backup.json` (with any ACE operation) |
| Restore ACL | `--ace-restore backup.json` |
| Preview restore | `--ace-restore backup.json --dry-run` |
| Force restore | `--ace-restore backup.json --force-restore` |

The backup file includes:
- Original path
- File ID (for safety verification)
- Complete ACL with all ACEs
- Timestamp

---

## Combining Filters with Actions

One of grumpwalk's most powerful capabilities is combining multiple filters with modification actions. This allows surgical precision when making changes across large file systems.

### Complex Ownership Migration with Exclusions

**Scenario:** Change owners from multiple sources, but only for large cold files, excluding archive directories:

```bash
./grumpwalk.py --host cluster --path /data \
  --change-owner "DOMAIN\\joe:DOMAIN\\bob" \
  --change-owner "uid:1000:uid:3000" \
  --larger-than 100GB \
  --accessed --older-than 30 \
  --omit-path /data/deep_archive \
  --type file \
  --propagate-changes --progress
```

This command:
- Changes owner from `DOMAIN\joe` to `DOMAIN\bob`
- Also changes owner from `uid:1000` to `uid:3000`
- Only affects files larger than 100GB
- Only affects files not accessed in 30+ days
- Excludes everything under `/data/deep_archive`
- Only processes files (not directories)

### Targeted Permission Cleanup by File Age and Type

**Scenario:** Remove "Everyone" access from old documents, but keep it on recent files and exclude temp directories:

```bash
./grumpwalk.py --host cluster --path /shared \
  --remove-ace "Allow:Everyone" \
  --name "*.docx" --name "*.xlsx" --name "*.pdf" \
  --modified --older-than 90 \
  --omit-subdirs "temp" --omit-subdirs ".tmp" \
  --type file \
  --propagate-changes --dry-run
```

### Contractor Offboarding with Scope Limits

**Scenario:** Remove contractor access and transfer ownership, but only in project directories and only 3 levels deep:

```bash
./grumpwalk.py --host cluster --path /projects \
  --remove-ace "Allow:DOMAIN\\contractor_group" \
  --change-owner "DOMAIN\\contractor1:DOMAIN\\project_lead" \
  --max-depth 3 \
  --omit-subdirs ".git" --omit-subdirs "node_modules" \
  --propagate-changes --progress
```

### Size-Based Permission Tiering

**Scenario:** Large media files should only be accessible by the media team, not general users:

```bash
./grumpwalk.py --host cluster --path /media \
  --remove-ace "Allow:Domain Users" \
  --add-ace "Allow:fd:Media_Team:Modify" \
  --larger-than 1GB \
  --name "*.mov" --name "*.mp4" --name "*.mxf" --name "*.r3d" \
  --type file \
  --propagate-changes --progress
```

### Stale Data Ownership Consolidation

**Scenario:** Transfer ownership of all files not accessed in 2 years to an archive administrator, but only in specific departments:

```bash
./grumpwalk.py --host cluster --path /home \
  --change-owner "DOMAIN\\departed_user1:DOMAIN\\archive_admin" \
  --change-owner "DOMAIN\\departed_user2:DOMAIN\\archive_admin" \
  --change-owner "DOMAIN\\departed_user3:DOMAIN\\archive_admin" \
  --accessed --older-than 730 \
  --omit-path /home/executives \
  --omit-path /home/legal \
  --type file \
  --propagate-changes --progress
```

### Compliance-Driven Permission Lockdown

**Scenario:** Make financial documents read-only for everyone except finance team after fiscal year close:

```bash
./grumpwalk.py --host cluster --path /finance/FY2024 \
  --remove-rights "Allow:Domain Users:w" \
  --add-ace "Allow:fd:Finance_Team:Modify" \
  --name "*.xlsx" --name "*.pdf" --name "*.csv" \
  --created --older-than 365 \
  --type file \
  --propagate-changes --ace-backup fy2024_acl_backup.json \
  --progress
```

### Multi-Domain Migration with File Type Filtering

**Scenario:** Migrate ACEs and ownership from old domain to new, but only for source code files:

```bash
./grumpwalk.py --host cluster --path /development \
  --migrate-trustees domain_migration.csv \
  --change-owners-file owner_migration.csv \
  --name "*.py" --name "*.js" --name "*.java" --name "*.go" --name "*.rs" \
  --omit-subdirs "vendor" --omit-subdirs "node_modules" --omit-subdirs ".venv" \
  --type file \
  --propagate-changes --progress
```

### Ransomware Recovery Permission Reset

**Scenario:** After a security incident, reset permissions on recently modified files while excluding known-good directories:

```bash
./grumpwalk.py --host cluster --path /data \
  --remove-ace "Allow:Everyone" \
  --remove-ace "Allow:Authenticated Users" \
  --add-ace "Allow:fd:IT_Admins:FullControl" \
  --modified --newer-than 7 \
  --omit-path /data/system \
  --omit-path /data/backups \
  --type file \
  --propagate-changes --ace-backup incident_recovery_backup.json \
  --progress
```

### Selective Group Migration for NFS to AD Transition

**Scenario:** Migrate group ownership from NFS GIDs to AD groups, but only for files owned by specific UIDs:

```bash
./grumpwalk.py --host cluster --path /nfs-share \
  --change-group "gid:100:DOMAIN\\Engineering" \
  --change-group "gid:200:DOMAIN\\Sales" \
  --owner 1001 --owner 1002 --owner 1003 --uid \
  --type file \
  --propagate-changes --progress
```

### Project Handoff with Comprehensive Filters

**Scenario:** Transfer a project from one team to another - change owners, groups, and permissions, but only for active project files:

```bash
./grumpwalk.py --host cluster --path /projects/legacy_app \
  --change-owner "DOMAIN\\old_lead:DOMAIN\\new_lead" \
  --change-group "Old_Team:New_Team" \
  --clone-ace-source "Old_Team" \
  --clone-ace-target "New_Team" \
  --remove-ace "Allow:Old_Team" \
  --modified --newer-than 365 \
  --omit-subdirs ".git" --omit-subdirs "archive" \
  --max-depth 5 \
  --propagate-changes --dry-run
```

### Quota Enforcement Preparation

**Scenario:** Before implementing quotas, transfer ownership of oversized user directories to a shared service account:

```bash
./grumpwalk.py --host cluster --path /home \
  --change-owner "uid:1001:DOMAIN\\storage_service" \
  --change-owner "uid:1002:DOMAIN\\storage_service" \
  --larger-than 500GB \
  --type file \
  --propagate-changes --progress
```

### Combining CSV Mappings with Runtime Filters

**Scenario:** Use CSV files for bulk mappings while applying runtime filters:

```bash
# Create mapping files
cat > owners.csv << EOF
source,target
OLDDOMAIN\user1,NEWDOMAIN\user1
OLDDOMAIN\user2,NEWDOMAIN\user2
OLDDOMAIN\service,NEWDOMAIN\service
EOF

cat > groups.csv << EOF
source,target
OLDDOMAIN\Team_A,NEWDOMAIN\Team_A
OLDDOMAIN\Team_B,NEWDOMAIN\Team_B
EOF

# Apply with filters
./grumpwalk.py --host cluster --path /shared \
  --change-owners-file owners.csv \
  --change-groups-file groups.csv \
  --accessed --newer-than 365 \
  --omit-subdirs ".snapshot" \
  --type file \
  --propagate-changes --progress
```

### Filter Combination Quick Reference

| Filter Type | Flag | Combines With |
|-------------|------|---------------|
| Size | `--larger-than`, `--smaller-than` | All actions |
| Time | `--older-than`, `--newer-than` with `--accessed`, `--modified`, `--created` | All actions |
| Name | `--name` (OR), `--name-and` (AND) | All actions |
| Type | `--type file/directory/symlink` | All actions |
| Owner | `--owner` with `--ad`, `--uid`, `--local` | All actions |
| Exclusion | `--omit-subdirs`, `--omit-path` | All actions |
| Depth | `--max-depth` | All propagating actions |

### Best Practices for Complex Operations

1. **Always use `--dry-run` first** - Preview what will change before executing
2. **Use `--ace-backup`** - Save original ACLs before permission changes
3. **Start narrow, expand** - Test on a subdirectory before running on entire tree
4. **Combine `--progress` with `--verbose`** - Monitor what's happening in real-time
5. **Use `--max-depth` for testing** - Limit scope during validation
6. **Chain operations carefully** - Some filters may interact unexpectedly; verify with dry-run

### What does --verbose show?

The `--verbose` flag enables detailed diagnostic output beyond what `--progress` provides.
Use it when you need to understand what grumpwalk is doing internally -- particularly
when debugging ACE operations, verifying identity resolution, or diagnosing filter behavior.

`--progress` and `--verbose` control what is shown in the **terminal** (stderr).
They are independent of `--log-file`, which writes to a file with its own `--log-level`.

`--progress` shows **how fast** the operation is running (objects/sec, match counts).
`--verbose` shows **what decisions** grumpwalk is making along the way.

| Category | What it shows |
|---|---|
| Identity resolution | Trustee name-to-auth_id lookups, cached identity loads, cache save confirmations |
| ACE manipulation | Which ACEs matched removal/replacement patterns, duplicate cleanup, clone and migration details |
| Owner/group changes | Per-file ownership change reporting, source/target resolution details |
| Filter resolution | Resolved owner auth_ids, directory aggregate fetch warnings |
| Trustee mappings | Loading of CSV mapping files for clone, migrate, and owner change operations |
| Auto-tuning | Profile load/generation details |
| Adaptive concurrency | When batch sizes are reduced for large or small directories |

Example output with `--verbose`:

```
[2026-03-26 14:30:05] [INFO] Loaded 42 cached identities from file_filter_resolved_identities
[2026-03-26 14:30:05] [INFO] Adaptive concurrency: Processing 3 subdirs with batch size 10 (reduced from 200)
[2026-03-26 14:30:06] [DEBUG] ACE type='Allowed' auth_id='501' vs pattern type='Allowed' auth_id='501'
[2026-03-26 14:30:06] [DEBUG]   -> MATCH - will remove
[2026-03-26 14:30:07] [INFO] Saved 42 identities to cache file
```

### Capturing log output to a file

#### Using --log-file (recommended)

The `--log-file` flag writes log output to a file with timezone-aware timestamps.
Use `--log-level` to control verbosity. Stderr output is unaffected -- you still see
progress and messages in the terminal.

```bash
# Log everything to a file (default level: INFO)
./grumpwalk.py --host cluster --path /data --progress \
  --log-file run.log

# Log only errors and warnings
./grumpwalk.py --host cluster --path /data --progress \
  --log-file run.log --log-level ERROR

# Log all diagnostic output (including ACE matching, identity resolution)
./grumpwalk.py --host cluster --path /data --verbose \
  --log-file debug.log --log-level DEBUG
```

The log file includes a header recording the timezone:

```
# grumpwalk log started 2026-03-26 11:09:38 PDT (UTC-0700)
# All timestamps are local time (PDT)
# Log level: INFO
```

Log levels are cumulative:

| Level | What it captures |
|---|---|
| ERROR | Errors, warnings, and hints |
| INFO | Everything in ERROR, plus operational messages (default) |
| DEBUG | Everything, including ACE matching internals and per-entry diagnostics |

#### Using shell redirection

You can also capture stderr directly using shell redirection. This captures
everything printed to stderr, including progress lines.

```bash
# Save data and logs to separate files
./grumpwalk.py --host cluster --path /data --progress \
  > output.ndjson 2> run.log

# View logs in the terminal and save to a file (bash)
./grumpwalk.py --host cluster --path /data --progress \
  > output.ndjson 2> >(tee run.log >&2)

# Suppress all log output
./grumpwalk.py --host cluster --path /data 2>/dev/null > output.ndjson
```

The `2> >(tee ...)` syntax is bash-specific (process substitution). In other shells,
redirect to a file and tail it separately.


