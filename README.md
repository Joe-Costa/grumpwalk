# Qumulo File Filter

A memory-efficient streaming utility for filtering files on Qumulo storage systems by timestamps, size and ownership. This tool uses `jq` streaming to process large directory trees efficiently, even via remote `qq` CLI

**Two versions available:**
- `qumulo_file_filter.sh` - For Linux/GNU systems (uses GNU date)
- `qumulo_file_filter_mac.sh` - For macOS/BSD systems (uses BSD date)

## Features

- **Memory-safe streaming**: Processes files one at a time using jq streaming, avoiding OOM issues on large directory trees
- **File listing**: List all files in a directory tree with optional filtering
- **Time-based filtering**: Optionally filter by creation, access, modification, or change time
- **Size-based filtering**: Filter by file size with support for decimal (KB, MB, GB, TB, PB) and binary (KiB, MiB, GiB, TiB, PiB) units
- **Owner filtering**: Filter by file owner with support for AD users, local users, and UIDs (supports multiple owners with OR logic)
- **Identity expansion**: Automatically match equivalent identities (e.g., AD user + corresponding NFS UID)
- **Selective directory omission**: Skip directories using wildcard patterns
- **Flexible output**: Plain text or JSON output, with optional file output for verbose mode
- **All attributes output**: Include all file metadata in JSON output when needed
- **Real-time results**: Streaming architecture outputs results as they're found

## Requirements

- Linux, Mac or Windows with Linux Subsystem
- `qq` CLI (`pip install qumulo_api`)
- `jq` (JSON processor)
- Python 3
- Bash (I've not tested it in other shells...)
- **Note**: Use `qumulo_file_filter_mac.sh` on macOS/BSD systems (Also one `bash`, I have not tested it with `zsh`)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/Joe-Costa/qumulo-file-filter.git
cd qumulo-file-filter
```

2. Make the script executable:
```bash
# For Linux/GNU systems:
chmod +x qumulo_file_filter.sh

# For macOS/BSD systems:
chmod +x qumulo_file_filter_mac.sh
```

## Usage

### Basic Syntax

```bash
# Linux/GNU:
./qumulo_file_filter.sh --path <path> [--older-than <days>] [--newer-than <days>] [OPTIONS]

# macOS/BSD:
./qumulo_file_filter_mac.sh --path <path> [--older-than <days>] [--newer-than <days>] [OPTIONS]
```

**Connect to specific Qumulo cluster: (For remote qq CLI use)**
```bash
./qumulo_file_filter.sh --path /home --older-than 30 \
  --host 10.1.1.100 --credentials-store ~/.qumulo_creds
```

*You may alternatively run `qq --host YOUR_QUMULO login -u YOUR_USER` in advance instead of using a `.qumulo_creds` file*

### Common Examples

**List all files in a directory:**
```bash
./qumulo_file_filter.sh --path /home
```

**List all files owned by a specific user:**
```bash
./qumulo_file_filter.sh --path /home --owner jdoe --ad
```

**Find files created more than 30 days ago:**
```bash
./qumulo_file_filter.sh --path /home --older-than 30
```

**Find files accessed in the last 7 days:**
```bash
./qumulo_file_filter.sh --path /home --newer-than 7 --accessed
```

**Find old files, exclude temp directories, save to JSON with logging:**
```bash
./qumulo_file_filter.sh --path /home --older-than 90 \
  --omit-subdirs "temp cache 100k*" \
  --json-out old-files.json --verbose
```

**Find files owned by a specific user (with identity expansion - Match Names to UID Numbers or vice versa):**
```bash
./qumulo_file_filter.sh --path /home --older-than 30 \
  --owner jdoe --expand-identity
```

**Find files owned by multiple users (OR logic):**
```bash
./qumulo_file_filter.sh --path /home --older-than 30 \
  --owner jdoe --owner jane --owner bob --ad
```

**Find recently modified files with depth limit:**
```bash
./qumulo_file_filter.sh --path /data --newer-than 1 \
  --modified --max-depth 3
```

**Output all file attributes in JSON:**
```bash
./qumulo_file_filter.sh --path /home --older-than 30 \
  --json-out results.json --all-attributes
```

**Find files larger than 100MB:**
```bash
./qumulo_file_filter.sh --path /home --larger-than 100MB
```

**Find files smaller than 1GiB and older than 30 days:**
```bash
./qumulo_file_filter.sh --path /home --smaller-than 1GiB --older-than 30
```

**Find files in a size range (between 100MB and 1GB):**
```bash
./qumulo_file_filter.sh --path /home --larger-than 100MB --smaller-than 1GB
```

**Find files in a time range (between 7 and 30 days old):**
```bash
./qumulo_file_filter.sh --path /home --newer-than 7 --older-than 30
```

**Find files in both time and size ranges:**
```bash
./qumulo_file_filter.sh --path /home --newer-than 30 --older-than 90 \
  --larger-than 1GB --smaller-than 10GB
```

**Complex multi-field query (accessed 10-30 days ago AND modified 20-22 days ago AND created >100 days ago):**
```bash
./qumulo_file_filter.sh --path /home \
  --accessed-newer-than 10 --accessed-older-than 30 \
  --modified-newer-than 20 --modified-older-than 22 \
  --created-older-than 100 \
  --owner joe
```

## Options

### Required Arguments
- `--path <path>` - Path to search

### Time Filter Options (optional)
- `--older-than <days>` - Find files older than N days
- `--newer-than <days>` - Find files newer than N days

**Time range filtering:** Both `--older-than` and `--newer-than` can be used together to find files within a specific age range (e.g., files between 7 and 30 days old).

**Note:** If neither time filter is specified, all files will be returned (filtered only by owner/size if specified).

### Time Field Options (for use with --older-than/--newer-than)
- `--created` - Filter by creation time (default)
- `--accessed` - Filter by last access time
- `--modified` - Filter by last modification time
- `--changed` - Filter by last metadata change time

### Field-Specific Time Filters (for complex multi-field queries)
- `--accessed-older-than <days>` - Files accessed older than N days
- `--accessed-newer-than <days>` - Files accessed newer than N days
- `--modified-older-than <days>` - Files modified older than N days
- `--modified-newer-than <days>` - Files modified newer than N days
- `--created-older-than <days>` - Files created older than N days
- `--created-newer-than <days>` - Files created newer than N days
- `--changed-older-than <days>` - Files with metadata changed older than N days
- `--changed-newer-than <days>` - Files with metadata changed newer than N days

**Note:** All field-specific filters use AND logic. This allows complex queries like "files accessed 10-30 days ago AND modified 20-22 days ago AND created >100 days ago".

### Size Filter Options (optional)
- `--larger-than <size>` - Find files larger than specified size
- `--smaller-than <size>` - Find files smaller than specified size

**Supported size units:**
- Decimal: B, KB, MB, GB, TB, PB
- Binary: KiB, MiB, GiB, TiB, PiB

**Examples:** `100MB`, `1.5GiB`, `500` (bytes), `10KB`

**Range filtering:** Both `--larger-than` and `--smaller-than` can be used together to find files within a size range.

### Owner Filter Options
- `--owner <name>` - Filter by file owner (can be specified multiple times for OR logic)
- `--ad` - Owner(s) are Active Directory users
- `--local` - Owner(s) are local users
- `--uid` - Owner(s) are specified as UID numbers
- `--expand-identity` - Match all equivalent identities (e.g., AD user + NFS UID)

**Note:** You cannot mix `--uid` with `--ad` or `--local` for simplicity. All owners must be of the same type.

### Search Options
- `--max-depth <N>` - Maximum directory depth to search (default: unlimited)
- `--file-only` - Search files only (default)
- `--all` - Search both files and directories
- `--omit-subdirs "patterns"` - Space-separated patterns to omit (supports wildcards)

### Output Options
- `--json` - Output results as JSON to stdout
- `--json-out <file>` - Write JSON results to file (allows --verbose)
- `--verbose` - Show detailed logging to stderr
- `--all-attributes` - Include all file attributes in JSON output (default: path + time field only)

### Qumulo Connection Options
- `--host <host>` - Qumulo cluster hostname or IP
- `--credentials-store <path>` - Path to credentials file (default: ~/.qfsd_cred)

## Identity Expansion

The `--expand-identity` flag leverages Qumulo's `qq auth_expand_identity` to find all equivalent representations of a user across different protocols:

```bash
./file_filter.sh --path /home --older-than 30 \
  --owner joe --expand-identity --verbose
```

**Verbose output example:**
```
[INFO] Resolving owner identity: joe (type: auto)
[INFO] Resolved owner auth_id: 25769805128
[INFO] Expanding identity to find equivalent auth_ids...
[INFO] Found equivalent auth_ids: 25769805128 12884903999 85899348031
```

This will match files owned by:
- joe's AD identity (SID-based)
- joe's NFS UID (e.g., 3030)
- Any other equivalent identity

## Multiple Owner Filtering

You can specify multiple `--owner` flags to filter files owned by any of the specified users (OR logic):

```bash
./file_filter.sh --path /home --older-than 30 \
  --owner joe --owner jane --owner bob --ad --verbose
```

**Verbose output example:**
```
[INFO] Resolving 3 owner(s)...
[INFO] Resolving owner identity: joe (type: ad)
[INFO] Resolved owner auth_id: 25769805128
[INFO] Resolving owner identity: jane (type: ad)
[INFO] Resolved owner auth_id: 25769805129
[INFO] Resolving owner identity: bob (type: ad)
[INFO] Resolved owner auth_id: 25769805130
[INFO] Final auth_id list (OR filter): 25769805128 25769805129 25769805130
```

When combined with `--expand-identity`, each owner's equivalent identities are also included:

```bash
./file_filter.sh --path /home --older-than 30 \
  --owner joe --owner jane --expand-identity --verbose
```

This will match files owned by joe OR jane, including all their equivalent identities (AD, NFS UID, etc.).

## All Attributes Output

By default, JSON output includes only the file path and the selected time field. Use `--all-attributes` to include all available file attributes:

```bash
./file_filter.sh --path /home --older-than 30 \
  --json --all-attributes
```

**Default output (path + selected time field only):**
```json
{"path": "/home/joe/file1.txt", "creation_time": "2024-01-15T10:30:00.000000000Z"}
{"path": "/home/jane/file2.txt", "creation_time": "2024-01-10T14:20:00.000000000Z"}
```

**With --all-attributes:**
```json
{"path": "/home/joe/file1.txt", "name": "file1.txt", "type": "FS_FILE_TYPE_FILE", "owner": "25769805128", "group": "25769805200", "size": "1024", "creation_time": "2024-01-15T10:30:00.000000000Z", "access_time": "2024-03-01T09:15:00.000000000Z", "modification_time": "2024-02-20T16:45:00.000000000Z", "change_time": "2024-02-20T16:45:00.000000000Z", "num_links": "1", "mode": "0644"}
```

**Note:** `--all-attributes` only affects JSON output. Plain text output always shows the time field and path.

## How It Works

1. **Streaming Architecture**: Uses `qq fs_walk_tree` piped to `jq --stream` to process JSON incrementally
2. **Python Processing**: Reads streamed JSON line-by-line, maintaining only one file object in memory at a time
3. **Immediate Output**: Results are output as soon as they match, allowing real-time monitoring
4. **Subdirectory Filtering**: When using `--omit-subdirs`, discovers subdirectories first, then processes only non-omitted ones

## Performance

- **Memory Usage**: O(1) - Constant memory regardless of tree size
- **Streaming**: Outputs results immediately as files are processed
- **Selective Processing**: `--omit-subdirs` avoids scanning entire directory trees

## License

MIT License - See LICENSE file for details

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Support

For issues or questions:
- Open an issue on GitHub
- Consult Qumulo documentation for `qq` CLI usage

## Author

Joe Costa

## Acknowledgments

Built for Qumulo storage systems using the `qq` CLI toolset.
