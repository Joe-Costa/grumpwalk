# Qumulo File Filter

A memory-efficient streaming utility for filtering files on Qumulo storage systems by age and ownership. This tool uses `jq` streaming to process large directory trees without running out of memory.

## Features

- **Memory-safe streaming**: Processes files one at a time using jq streaming, avoiding OOM issues on large directory trees
- **Time-based filtering**: Filter by creation, access, modification, or change time
- **Owner filtering**: Filter by file owner with support for AD users, local users, and UIDs
- **Identity expansion**: Automatically match equivalent identities (e.g., AD user + corresponding NFS UID)
- **Selective directory omission**: Skip directories using wildcard patterns
- **Flexible output**: Plain text or JSON output, with optional file output for verbose mode
- **Real-time results**: Streaming architecture outputs results as they're found

## Requirements

- Qumulo cluster with `qq` CLI installed
- `jq` (JSON processor)
- Python 3
- Bash

## Installation

1. Clone the repository:
```bash
git clone https://github.com/Joe-Costa/qumulo-file-filter.git
cd qumulo-file-filter
```

2. Make the script executable:
```bash
chmod +x file_filter.sh
```

## Usage

### Basic Syntax

```bash
./file_filter.sh --path <path> (--older-than <days> | --newer-than <days>) [OPTIONS]
```

### Common Examples

**Find files created more than 30 days ago:**
```bash
./file_filter.sh --path /home --older-than 30
```

**Find files accessed in the last 7 days:**
```bash
./file_filter.sh --path /home --newer-than 7 --accessed
```

**Find old files, exclude temp directories, save to JSON with logging:**
```bash
./file_filter.sh --path /home --older-than 90 \
  --omit-subdirs "temp cache 100k*" \
  --json-out old-files.json --verbose
```

**Find files owned by a specific user (with identity expansion):**
```bash
./file_filter.sh --path /home --older-than 30 \
  --owner jdoe --expand-identity
```

**Find recently modified files with depth limit:**
```bash
./file_filter.sh --path /data --newer-than 1 \
  --modified --max-depth 3
```

## Options

### Required Arguments
- `--path <path>` - Path to search
- `--older-than <days>` - Find files older than N days
- `--newer-than <days>` - Find files newer than N days

### Time Field Options (default: --created)
- `--created` - Filter by creation time (default)
- `--accessed` - Filter by last access time
- `--modified` - Filter by last modification time
- `--changed` - Filter by last metadata change time

### Owner Filter Options
- `--owner <name>` - Filter by file owner (auto-detects if no type specified)
- `--ad` - Owner is Active Directory user
- `--local` - Owner is local user
- `--uid` - Owner is specified as UID number
- `--expand-identity` - Match all equivalent identities (e.g., AD user + NFS UID)

### Search Options
- `--max-depth <N>` - Maximum directory depth to search
- `--file-only` - Search files only (default)
- `--all` - Search both files and directories
- `--omit-subdirs "patterns"` - Space-separated patterns to omit (supports wildcards)

### Output Options
- `--json` - Output results as JSON to stdout
- `--json-out <file>` - Write JSON results to file (allows --verbose)
- `--verbose` - Show detailed logging to stderr

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
