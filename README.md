# grumpwalk.py

High-performance, multi-purpose file crawling tool for Qumulo storage systems.

- **Find files by name, owner, size or timestamps**
- **Easily replace permissions on thousands of files**
- **Find similar files**
- **Find and resolve symlinks**
- **And more!**

I've observed performance as high as 12k objects per second processed against an old QC24 Qumulo cluster.<br>The lower the latency you have between where this code is running and the Qumulo cluster the better your performance
will be.<br>Keep in mind that some operations will read contents of files, which might be slower over low bandwidth public internet & VPN connections.

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
- **Permissions reports** - Retrieve permissions ACLs of objects in tree
- **ACL and owner/group management** - Copy ACLs, owner, and group between objects
- **Similarity detection** - Find similar files using adaptive sampling

## Requirements

- Python 3.8+
- `aiohttp` - Install with: `pip install aiohttp`
- `qumulo_api` - Install with: `pip install qumulo_api`
- `ujson` (optional) - For faster JSON parsing: `pip install ujson`
- `argcomplete` - For bash completion support: `pip install argcomplete`
- Qumulo cluster credentials (use `qq login`)

## Installation

```bash
git clone https://github.com/Joe-Costa/grumpwalk.git
cd grumpwalk
chmod +x grumpwalk.py
pip install -r requirements.txt
```

### Bash Completion Setup (Optional)

To enable tab completion for command-line arguments, use the provided setup script:

```bash
# Automated setup (installs argcomplete and configures your shell)
./setup_completion.sh

# Then reload your shell config
source ~/.bashrc  # or source ~/.zshrc for zsh
```

**Manual setup** (if you prefer):

```bash
# Install argcomplete for current user
python3 -m pip install --user argcomplete

# For current session only
eval "$(register-python-argcomplete grumpwalk.py)"

# For permanent setup, add to your ~/.bashrc or ~/.bash_profile
echo 'eval "$(register-python-argcomplete grumpwalk.py)"' >> ~/.bashrc

# Or for zsh users, add to ~/.zshrc
echo 'eval "$(register-python-argcomplete grumpwalk.py)"' >> ~/.zshrc
```

After enabling, you can use Tab to autocomplete options:
```bash
./grumpwalk.py --ho<TAB>     # completes to --host
./grumpwalk.py --type <TAB>  # shows: file directory symlink
```

**Troubleshooting tab completion:**

If tab completion isn't working after setup:

1. **Reload your shell configuration:**
   ```bash
   source ~/.bashrc  # or source ~/.zshrc for zsh
   ```

2. **Check if register-python-argcomplete is in PATH:**
   ```bash
   which register-python-argcomplete
   # Should show: ~/.local/bin/register-python-argcomplete
   ```

3. **If not found, add ~/.local/bin to PATH manually:**
   ```bash
   echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
   source ~/.bashrc
   ```

4. **Re-run the setup script:**
   ```bash
   ./setup_completion.sh
   source ~/.bashrc
   ```

5. **Test in a new shell session** - Sometimes completion only works in fresh shells

## Logging into a cluster

Since we've installed the `qq` CLI you can login with:

**Login with a user that has the correct RBAC rights for any operations you want `grumpwalk.py` to perform!**

`qq --host cluster.example.com login -u "DOMAIN\user"`

This will save a `.qfsd_cred` file in your current user's home directory. 

## Helpful Qumulo Care Articles:

[How to get an Access Token](https://docs.qumulo.com/administrator-guide/connecting-to-external-services/creating-using-access-tokens-to-authenticate-external-services-qumulo-core.html) 

[Qumulo Role Based Access Control](https://care.qumulo.com/hc/en-us/articles/360036591633-Role-Based-Access-Control-RBAC-with-Qumulo-Core#managing-roles-by-using-the-web-ui-0-7)

## Quick Examples

```bash
# List all files in a directory
./grumpwalk.py --host cluster.example.com --path /home

# Find files older than 30 days
./grumpwalk.py --host cluster.example.com --path /home --older-than 30

# Find large log files with progress
./grumpwalk.py --host cluster.example.com --path /var --name '*.log' --larger-than 100MB --progress

# Search for Python test files
./grumpwalk.py --host cluster.example.com --path /code --name 'test_*.py' --type file

# Find symlinks and show their targets
./grumpwalk.py --host cluster.example.com --path /home --type symlink --resolve-links

# Generate owner capacity report
./grumpwalk.py --host cluster.example.com --path /data --owner-report --csv-out report.csv

# Copy ACL from source to target
./grumpwalk.py --host cluster.example.com --source-acl /source/dir --acl-target /target/dir --propagate-acls

# Apply ACL from local JSON file
./grumpwalk.py --host cluster.example.com --source-acl-file acl.json --acl-target /target/dir --propagate-acls

# Copy owner and group only (no ACL changes)
./grumpwalk.py --host cluster.example.com --source-acl /source/dir --acl-target /target/dir --copy-owner --copy-group --owner-group-only --propagate-acls

# Find similar files
./grumpwalk.py --host cluster.example.com --path /backups --find-similar --progress
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
- `--omit-path PATH` - Skip specific absolute path (must start with `/`, repeatable)
- `--max-entries-per-dir N` - Skip directories exceeding N entries

### Symlink Options
- `--resolve-links` - Show symlink targets as absolute paths

### ACL Options
- `--acl-report` - Generate ACL inventory report
- `--acl-csv FILE` - Export per-file ACL data to CSV (requires `--acl-report`)
- `--acl-resolve-names` - Resolve IDs to names in ACL output
- `--show-owner` - Include owner column in ACL reports (requires `--acl-report`)
- `--show-group` - Include group column in ACL reports (requires `--acl-report`)
- ACLs are returned in NFSv4 shorthand for brevity and compactness (`rwaxdDtTnNcCoy`).
- These rights map directly to the 14 NTFS rights in an ACE
- Refer to [The nfs4_acl man page](https://www.man7.org/linux//man-pages/man5/nfs4_acl.5.html) for details

### ACL Management Options
- `--source-acl PATH` - Source ACL from cluster path
- `--source-acl-file FILE` - Source ACL from local JSON file
- `--acl-target PATH` - Target object/directory path
- `--propagate-acls` - Apply to all child objects recursively
- `--continue-on-error` - Continue on errors without prompting
- `--copy-owner` - Copy owner from source
- `--copy-group` - Copy group from source
- `--owner-group-only` - Copy only owner/group, skip ACL
- `--acl-concurrency N` - Concurrent ACL operations (default: 100, try 500 for faster throughput)

### Similarity Detection Options
- `--find-similar` - Find similar files using metadata + sample hashing
- `--by-size` - Match by size+metadata only (fast, may have false positives)
- `--sample-size SIZE` - Sample chunk size (e.g., `64KB`, `256KB`, `1MB`, default: `64KB`)
- `--sample-points N` - Number of sample points (3-11, default: adaptive based on file size)
- `--estimate-size` - Show data transfer estimate and exit (no actual hashing)

**Note:** Results are advisory. Always verify before deleting files.

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

### Path Filtering

**--omit-subdirs** - Pattern-based filtering (supports wildcards):
```bash
--omit-subdirs temp             # Skip any directory named "temp"
--omit-subdirs /home/bob        # Skip directories matching this pattern at a point
# past the value provided via --path.  See --omit-path for absolute path matching
--omit-subdirs '/home/*/backup' # Skip backup dirs in all home directories
```

**--omit-path** - Exact absolute path filtering (no wildcards):
```bash
--omit-path /home/joe/100k      # Skip this exact path only
--omit-path /data/archive       # Must start with / for filter to work
--omit-path /tmp/cache          # Can specify multiple paths
```

**Key differences:**
- `--omit-subdirs` uses pattern matching (wildcards like `*` and `?`)
- `--omit-path` requires exact absolute paths starting with `/`
- Both flags can be used multiple times
- Both increment the Smart Skip counter for progress tracking

## Advanced Examples

### Complex time range query
```bash
./grumpwalk.py --host cluster.example.com --path /data \
  --accessed-newer-than 30 --accessed-older-than 90 \
  --modified-older-than 180 \
  --larger-than 1GB --progress
```

### Find stale backups, exclude specific paths
```bash
./grumpwalk.py --host cluster.example.com --path /backups \
  --name '*backup*' --name-and '*2024*' \
  --older-than 365 --larger-than 100MB \
  --omit-path /backups/alice --omit-path /backups/bob \
  --csv-out stale-backups.csv
```

### Capacity report for specific owners
```bash
./grumpwalk.py --host cluster.example.com --path /projects \
  --owner joe --owner jane --expand-identity \
  --owner-report --csv-out capacity.csv
```

### Find all symlinks and their targets
```bash
./grumpwalk.py --host cluster.example.com --path /home \
  --type symlink --resolve-links --max-depth 2 \
  --csv-out symlinks.csv
```

### Generate ACL report with name resolution
```bash
./grumpwalk.py --host cluster.example.com --path /shared \
  --acl-report --acl-csv permissions.csv \
  --acl-resolve-names --show-owner --show-group --progress
```

### Copy ACL to directory and all children
```bash
./grumpwalk.py --host cluster.example.com \
  --source-acl /source/dir --acl-target /target/dir \
  --propagate-acls --progress
```

### Copy ACL with owner and group
```bash
./grumpwalk.py --host cluster.example.com \
  --source-acl /source/dir --acl-target /target/dir \
  --copy-owner --copy-group --propagate-acls --progress
```

### Copy only owner and group (no ACL)
```bash
./grumpwalk.py --host cluster.example.com \
  --source-acl /source/dir --acl-target /target/dir \
  --copy-owner --copy-group --owner-group-only \
  --propagate-acls --progress
```

### Copy ACL to filtered files only
```bash
./grumpwalk.py --host cluster.example.com \
  --source-acl /source/dir --acl-target /target/dir \
  --propagate-acls --older-than 30 --type file --progress
```

### Find similar files with custom sampling

**IMPORTANT NOTE!  `--find-similar` provides a list of files that might be similar, but is not built to perfom this operation**
**with 100% accuracy! You should perform your own checksumming of any returned files before deleting anything!**

**USE THIS FEATURE AT YOUR OWN RISK!**

```bash
# Estimate data transfer before running
./grumpwalk.py --host cluster.example.com --path /backups \
  --find-similar --estimate-size --sample-size 256KB --sample-points 11

# Find similar files with higher accuracy (more data transfer)
./grumpwalk.py --host cluster.example.com --path /backups \
  --find-similar --sample-size 256KB --sample-points 11 \
  --csv-out similar.csv --progress
```

## Performance Tips

1. **Use --max-depth** to limit search scope
2. **Enable --progress** to monitor large searches
3. **Use --omit-subdirs** to skip directories by pattern, or **--omit-path** for exact paths
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

### ACL Reports
ACL reports export per-file permissions in CSV or JSON format:

**CSV format** (one row per file):
```csv
path,owner,group,ace_count,inherited_count,explicit_count,trustee_1,trustee_2
/shared/file.txt,AD\joe,AD\Domain Users,2,0,2,Allow::admin:rwx,Allow:g:users:rx
```

**JSON format** (one object per file):
```json
{"path":"/shared/file.txt","owner":"AD\\joe","group":"AD\\Domain Users","ace_count":2,"inherited_count":0,"explicit_count":2,"trustees":["Allow::admin:rwx","Allow:g:users:rx"]}
```

Use `--acl-resolve-names` to convert auth IDs to readable names (e.g., `joe` instead of `auth_id:1234`).
Use `--show-owner` and `--show-group` to include owner and group columns in the output.

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

Pull requests welcome at https://github.com/Joe-Costa/grumpwalk
