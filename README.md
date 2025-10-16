# grump_walk.py

High-performance async file search tool for Qumulo storage systems.

## Features

- **Fast async operations** - Direct REST API calls with concurrent requests
- **Name pattern matching** - Glob wildcards and regex support
- **Time-based filtering** - Search by creation, modification, access, or change time
- **Size-based filtering** - Find files by size with smart directory skipping
- **Owner filtering** - Filter by user/group with identity expansion
- **Type filtering** - Search files, directories, or symlinks
- **Symlink resolution** - Display symlink targets as absolute paths
- **Progress tracking** - Real-time statistics with smart skip counters
- **Multiple output formats** - Plain text, JSON, or CSV
- **Directory scope preview** - Shows total subdirs/files before search
- **Owner reports** - Generate storage capacity breakdowns by owner

## Requirements

- Python 3.8+
- `aiohttp` - Install with: `pip install aiohttp`
- `qumulo_api` - Install with: `pip install qumulo_api`
- `ujson` (optional) - For faster JSON parsing: `pip install ujson`
- Qumulo cluster credentials (use `qq login`)

## Installation

```bash
git clone https://github.com/Joe-Costa/grump-walk.git
cd grump-walk
chmod +x grump_walk.py
pip install aiohttp qumulo_api ujson
```

## Quick Examples

```bash
# List all files in a directory
./grump_walk.py --host cluster.example.com --path /home

# Find files older than 30 days
./grump_walk.py --host cluster.example.com --path /home --older-than 30

# Find large log files with progress
./grump_walk.py --host cluster.example.com --path /var --name '*.log' --larger-than 100MB --progress

# Search for Python test files
./grump_walk.py --host cluster.example.com --path /code --name 'test_*.py' --type file

# Find symlinks and show their targets
./grump_walk.py --host cluster.example.com --path /home --type symlink --resolve-links

# Generate owner capacity report
./grump_walk.py --host cluster.example.com --path /data --owner-report --csv-out report.csv
```

## Command Reference

### Required
- `--host` - Qumulo cluster hostname or IP
- `--path` - Path to search

### Name/Type Filters
- `--name PATTERN` - Match by name (glob/regex, OR logic, repeatable)
- `--name-and PATTERN` - Match by name (AND logic, repeatable)
- `--name-case-sensitive` - Case-sensitive name matching
- `--type {file,directory,symlink}` - Filter by object type
- `--file-only` - Search files only (deprecated, use `--type file`)

### Time Filters
- `--older-than N` - Files older than N days
- `--newer-than N` - Files newer than N days
- `--time-field {creation_time,modification_time,access_time,change_time}` - Time field to use (default: modification_time)

**Field-specific time filters (AND logic):**
- `--accessed-older-than N` / `--accessed-newer-than N`
- `--modified-older-than N` / `--modified-newer-than N`
- `--created-older-than N` / `--created-newer-than N`
- `--changed-older-than N` / `--changed-newer-than N`

### Size Filters
- `--larger-than SIZE` - Larger than size (e.g., `100MB`, `1.5GiB`)
- `--smaller-than SIZE` - Smaller than size
- `--include-metadata` - Include metadata blocks in size calculations

**Supported units:** B, KB, MB, GB, TB, PB, KiB, MiB, GiB, TiB, PiB

### Owner Filters
- `--owner NAME` - Filter by owner (OR logic, repeatable)
- `--ad` - Owner is Active Directory user
- `--local` - Owner is local user
- `--uid` - Owner is UID number
- `--expand-identity` - Match equivalent identities (AD user + NFS UID)
- `--show-owner` - Display owner information in output
- `--owner-report` - Generate capacity report by owner

### Directory Options
- `--max-depth N` - Maximum directory depth
- `--omit-subdirs PATTERN` - Skip directories (supports glob and paths, repeatable)
- `--max-entries-per-dir N` - Skip directories exceeding N entries

### Symlink Options
- `--resolve-links` - Show symlink targets as absolute paths

### Output Options
- `--json` - JSON output to stdout
- `--json-out FILE` - JSON output to file
- `--csv-out FILE` - CSV output to file
- `--all-attributes` - Include all file attributes in output
- `--limit N` - Stop after N matches
- `--progress` - Show real-time progress
- `--verbose` - Detailed logging

### Performance Options
- `--max-concurrent N` - Concurrent operations (default: 100)
- `--connector-limit N` - HTTP connection pool size (default: 100)
- `--profile` - Performance profiling

### Connection Options
- `--port PORT` - API port (default: 8000)
- `--credentials-store PATH` - Credentials file path

## Pattern Matching

### Glob Patterns (shell-style)
```bash
--name '*.log'           # All log files
--name 'test_*'          # Files starting with test_
--name 'file?.txt'       # file1.txt, fileA.txt, etc.
```

### Regex Patterns
```bash
--name '^test_.*\.py$'   # Python test files (anchored)
--name '.*\.(jpg|png)$'  # Image files
```

**Auto-detection:** Patterns with `/`, `^`, `$`, or regex chars are treated as regex. Others as glob.

### Combining Patterns (--name vs --name-and)
```bash
# OR logic: Match files containing 'backup' OR '2024'
--name '*backup*' --name '*2024*'

# AND logic: Match files containing 'backup' AND '2024'
--name-and '*backup*' --name-and '*2024*'

# Mixed logic: (report OR summary) AND 2024 AND .pdf
--name '*report*' --name '*summary*' --name-and '*2024*' --name-and '*.pdf'
```

### Path Matching (--omit-subdirs)
```bash
--omit-subdirs temp             # Skip any directory named "temp"
--omit-subdirs /home/bob        # Skip specific path
--omit-subdirs '/home/*/backup' # Skip backup dirs in all home directories
```

## Advanced Examples

### Complex time range query
```bash
./grump_walk.py --host cluster.example.com --path /data \
  --accessed-newer-than 30 --accessed-older-than 90 \
  --modified-older-than 180 \
  --larger-than 1GB --progress
```

### Find stale backups, exclude users
```bash
./grump_walk.py --host cluster.example.com --path /backups \
  --name '*backup*' --name-and '*2024*' \
  --older-than 365 --larger-than 100MB \
  --omit-subdirs /backups/alice --omit-subdirs /backups/bob \
  --csv-out stale-backups.csv
```

### Capacity report for specific owners
```bash
./grump_walk.py --host cluster.example.com --path /projects \
  --owner joe --owner jane --expand-identity \
  --owner-report --csv-out capacity.csv
```

### Find all symlinks and their targets
```bash
./grump_walk.py --host cluster.example.com --path /home \
  --type symlink --resolve-links --max-depth 2 \
  --csv-out symlinks.csv
```

## Performance Tips

1. **Use --max-depth** to limit search scope
2. **Enable --progress** to monitor large searches
3. **Use --omit-subdirs** to skip known large directories
4. **Combine filters** - More filters = fewer results to process
5. **Use --limit** for testing before full runs
6. **Smart skipping** automatically avoids directories that can't match your filters

## Output Formats

### Plain Text (default)
```
/home/joe/file1.txt
/home/jane/file2.log
```

### With --show-owner
```
/home/joe/file1.txt    joe (UID 1000)
/home/jane/file2.log   AD\jane
```

### With --resolve-links
```
/home/joe/link_to_docs → /shared/documentation
```

### CSV
```csv
path,modification_time,size
/home/joe/file1.txt,2024-01-15T10:30:00Z,1024
```

### JSON
```json
{"path":"/home/joe/file1.txt","modification_time":"2024-01-15T10:30:00Z"}
```

## Architecture

- **Async I/O** - aiohttp for concurrent HTTP requests
- **Connection pooling** - Reuses connections for efficiency
- **Smart directory skipping** - Uses aggregates API to skip entire directory trees
- **Streaming output** - Results output as found (non-blocking)
- **Adaptive concurrency** - Automatically adjusts based on directory size
- **Identity caching** - Caches owner name resolutions

## License

MIT License

## Author

Joe Costa

## Contributing

Pull requests welcome at https://github.com/Joe-Costa/grump-walk
