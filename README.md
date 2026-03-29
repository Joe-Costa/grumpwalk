# grumpwalk.py

**Version 2.5.0** | [Changelog](CHANGELOG.md) | [User Guide](grumpwalk_users_guide.md)

<img height="300" alt="grumprun" src="https://github.com/user-attachments/assets/37ec015f-7ff1-40e5-ba7f-02440079974b" />

High-performance, multi-purpose file crawling tool for Qumulo storage systems.

- **Find files by name, owner, size or timestamps**
- **Easily replace permissions on thousands of files**
- **Find similar files**
- **Find and resolve symlinks**
- **And more!**

I've observed performance as high as 12k objects per second processed against an old QC24 Qumulo cluster.<br>The lower the latency you have between where this code is running and the Qumulo cluster the better your performance
will be.<br>Keep in mind that some operations will read contents of files, which might be slower over low bandwidth public internet & VPN connections.

Don't forget to check out the [Grumpwalk User's Guide](grumpwalk_users_guide.md) for many real world usage examples.

## Table of Contents

1. [Features](#features)
2. [Requirements](#requirements)
3. [Installation](#installation)
4. [Logging into a cluster](#logging-into-a-cluster)
5. [An important note about access_time](#an-important-note-about-access_time)
6. [Helpful Qumulo Care Articles](#helpful-qumulo-care-articles)
7. [Quick Examples](#quick-examples)
8. [Output Formats](#output-formats)
9. [Command Reference](#command-reference)
10. [Pattern Matching](#pattern-matching)
11. [Auto-Tuning](#auto-tuning)
12. [Performance Tips](#performance-tips)
13. [Architecture](#architecture)

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
- **ACE manipulation** - Surgically add, remove, or modify individual ACEs within ACLs
- **Extended attribute management** - Find and set DOS attributes (read_only, hidden, system, archive)
- **Similarity detection** - Find similar files using adaptive sampling
- **Auto-tuning** - Automatic performance tuning based on system resources

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

## An important note about access_time

If your cluster does not have `atime` updating enabled then be aware that the `access_time` attribute will remain the same as the file creation time.
<br><br>
Updating the `atime` attribute on file read and write ops is disabled by default on Qumulo clusters, you can learn more about this feature here:
<br><br>
[Enabling Access Time Updates for File and Directory Reads in Qumulo Core](https://care.qumulo.com/s/article/Enabling-Access-Time-Updates-for-File-and-Directory-Reads-in-Qumulo-Core?)



## Helpful Qumulo Care Articles

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

### With --show-owner --dont-resolve-ids
```
/home/joe/file1.txt    UID:1000
/home/jane/file2.log   SID:S-1-5-21-3192274952-881459882-370606532-1352
```

### With --fields (tab-separated)
```
/home/joe/file1.txt	1048576	2024-01-15T10:30:00Z
/home/jane/file2.log	2048	2024-02-20T14:15:00Z
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

### JSON with --fields
```json
{"path":"/home/joe/file1.txt","size":"1024","owner_id":"S-1-5-21-123456-1109"}
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

## Command Reference

### General
- `--help` - Show help message and exit
- `--version` - Display version and exit
- `--dry-run` - Preview changes without applying them (works with ACL, ACE, owner, and attribute operations)

### Connection
- `--host HOST` - Qumulo cluster hostname or IP (required)
- `--path PATH` - Path to search (required for walk mode)
- `--port PORT` - API port (default: 8000)
- `--credentials-store PATH` - Credentials file path

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
- `--created` / `--modified` / `--accessed` / `--changed` - Shortcuts for `--time-field`

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
- `--show-group` - Display group information in output
- `--dont-resolve-ids` - Skip identity resolution; output raw UID/GID/SID values
- `--owner-report` - Generate capacity report by owner
- `--use-capacity` - Use capacity-based calculation (datablocks + metablocks) for owner report
- `--report-logical-size` - Report logical file size instead of disk capacity

### Directory Options
- `--max-depth N` - Maximum directory depth
- `--omit-subdirs PATTERN` - Skip directories (supports glob and paths, repeatable)
- `--omit-path PATH` - Skip specific absolute path (must start with `/`, repeatable)
- `--max-entries-per-dir N` - Skip directories exceeding N entries
- `--show-dir-stats` - Show directory statistics (file/dir counts, sizes)

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

### Owner/Group Change Options

Selective ownership changes - find files by current owner/group and change to a new owner/group.

- `--change-owner 'SOURCE:TARGET'` - Change owner from SOURCE to TARGET (e.g., `'olduser:newuser'`, `'uid:1001:uid:2001'`)
- `--change-group 'SOURCE:TARGET'` - Change group from SOURCE to TARGET (e.g., `'oldgroup:newgroup'`, `'gid:100:gid:200'`)
- `--change-owners-file FILE.csv` - Load owner mappings from CSV file
- `--change-groups-file FILE.csv` - Load group mappings from CSV file
- `--propagate-changes` - Apply changes to all children recursively (without this, only the target path is changed)

**CSV Format** (same as `--migrate-trustees`):
```csv
source,target
olduser1,newuser1
uid:1001,uid:2001
OLDDOMAIN\user,NEWDOMAIN\user
```

**Important:** Always use `--dry-run` first to preview changes before applying.

### Extended Attribute Options

Find files by DOS extended attributes and optionally modify them. DOS attributes (`read_only`, `hidden`, `system`, `archive`) are only honored by SMB clients -- they have no impact on NFS, REST, FTP, or S3 access.

- `--find-attribute-true ATTR[,ATTR,...]` - Find files where listed attributes are true
- `--find-attribute-false ATTR[,ATTR,...]` - Find files where listed attributes are false
- `--set-attribute-true ATTR[,ATTR,...]` - Set listed DOS attributes to true
- `--set-attribute-false ATTR[,ATTR,...]` - Set listed DOS attributes to false

**Findable attributes:** `read_only`, `hidden`, `system`, `archive`, `temporary`, `compressed`, `not_content_indexed`, `sparse_file`, `offline`

**Settable attributes (DOS only):** `read_only`, `hidden`, `system`, `archive`

**Aliases:** `sparse` = `sparse_file`, `readonly` = `read_only`, `nci` / `not_indexed` = `not_content_indexed`

**Pairing rules:** A `--find-attribute-*` and `--set-attribute-*` pair must use opposite booleans and appear adjacent on the command line. Both pairs may appear in one command. Use `--propagate-changes` for recursive application.

```bash
# Find all files with the archive bit set
./grumpwalk.py --host cluster --path /data --find-attribute-true archive --type file

# Clear archive on matching files, preview first
./grumpwalk.py --host cluster --path /backups \
  --find-attribute-true archive --set-attribute-false archive \
  --propagate-changes --dry-run

# Set read-only on all PDFs
./grumpwalk.py --host cluster --path /legal \
  --name '*.pdf' --type file --set-attribute-true read_only \
  --propagate-changes
```

### ACE Manipulation Options

Surgically modify Access Control Entries (ACEs) within ACLs without replacing the entire ACL.

**Core Operations:**
- `--remove-ace 'Type:Trustee'` - Remove ACE(s) matching pattern (e.g., `'Allow:Everyone'`)
- `--add-ace 'Type:Flags:Trustee:Rights'` - Add new ACE or merge rights if exists (e.g., `'Allow:fd:jsmith:Modify'`)
- `--replace-ace 'Type:Flags:Trustee:Rights'` - Replace existing ACE (in-place, same type)
- `--replace-ace 'Type:Trustee' --new-ace 'Type:Flags:Trustee:Rights'` - Replace with different ACE (can change type)
- `--add-rights 'Type:Trustee:Rights'` - Add rights to existing ACE (e.g., `'Allow:Everyone:rx'`)
- `--remove-rights 'Type:Trustee:Rights'` - Remove specific rights from existing ACE (keeps other rights)
- `--clone-ace-source 'Trustee' --clone-ace-target 'Trustee'` - Clone all ACEs from source to target trustee

**Bulk Operations (CSV source files):**
- `--migrate-trustees FILE.csv` - In-place trustee replacement from CSV (source ACE becomes target)
- `--clone-ace-map FILE.csv` - Bulk clone ACEs from CSV mappings (works with `--sync-cloned-aces`)

**CSV File Format (for --migrate-trustees and --clone-ace-map):**

Simple two-column format with optional header row:
```csv
source,target
OLDDOMAIN\user1,NEWDOMAIN\user1
OLDDOMAIN\user2,NEWDOMAIN\user2
uid:1001,uid:2001
S-1-5-21-123456,S-1-5-21-789012
gid:100,NEWDOMAIN\Domain Users
```

Supported trustee formats in CSV (same as command-line):
- `DOMAIN\username` - NetBIOS format
- `user@domain.com` - UPN format
- `uid:1001` - NFS UID
- `gid:100` - NFS GID
- `S-1-5-21-...` - Direct SID
- `username` - Plain name (resolved via identity API but might cause issues if duplicate names are found)

**Quick Reference:**

| Operation | Example | Use Case |
|-----------|---------|----------|
| `--remove-ace` | `'Allow:Everyone'` | Revoke all access for a trustee |
| `--remove-rights` | `'Allow:Everyone:w'` | Remove write but keep read/execute |
| `--add-rights` | `'Allow:Everyone:x'` | Add execute to existing ACE |
| `--add-ace` | `'Allow:fd:Everyone:rx'` | Create new ACE (or merge if exists) |
| `--replace-ace` | `'Allow:fd:Everyone:rx'` | Replace ACE's flags and rights entirely |
| `--replace-ace` + `--new-ace` | `'Allow:User' 'Deny:fd:User:w'` | Change ACE type (Allow to Deny) |
| `--clone-ace-source` + `--clone-ace-target` | `'bob' 'joe'` | Copy all of bob's ACEs to joe in a new entry |
| `--sync-cloned-aces` | (with clone flags) | Update existing target ACEs to match source |
| `--migrate-trustees` | `migration.csv` | Domain migration (source trustees become target) |
| `--clone-ace-map` | `mappings.csv` | Bulk clone ACEs from CSV file |

**Supporting Flags:**
- `--propagate-changes` - Apply changes to all children recursively (`--propagate-acls` also accepted)
- `--sync-cloned-aces` - When cloning, update existing target ACEs to match source rights
- `--dry-run` - Preview changes without applying them
- `--ace-backup FILE` - Save original ACLs to JSON before modification (includes file_id for safety)
- `--ace-restore FILE` - Restore ACLs from a backup file (verifies file_id matches)
- `--force-restore` - Force restore even if file_id doesn't match (use with caution)

**Pattern Syntax:**

Trustee formats (same as `--owner`):
- `Everyone` - Well-known Everyone group
- `uid:1001` - NFS UID
- `gid:100` - NFS GID
- `DOMAIN\\user` - AD user (NetBIOS)
- `user@domain.com` - AD user (UPN)
- `S-1-5-21-...` - SID directly
- `jsmith` - Plain name (resolved via identity API)

Rights can be specified as:
- **Windows presets**: `Read`, `Write`, `Modify`, `FullControl`
- **NFSv4 shorthand**: `r` (read), `w` (write), `a` (append), `x` (execute), `d` (delete), etc.
- **Combined**: `rwx`, `rx`, `Read+w`

Flags (inheritance):
- `f` = OBJECT_INHERIT (files inherit)
- `d` = CONTAINER_INHERIT (directories inherit)
- `fd` = Both (typical for new permissions)

**Behavior Notes:**

- **--add-ace vs --replace-ace**: `--add-ace` merges rights if an ACE with the same type and trustee already exists. `--replace-ace` completely replaces the existing ACE's flags and rights with the new values.
- **--replace-ace with --new-ace**: When paired with `--new-ace`, you can change the ACE type (Allow to Deny or vice versa). The `--replace-ace` pattern specifies which ACE to find, and `--new-ace` specifies the full replacement. These must be positionally adjacent and paired 1:1.
- **--clone-ace-source/--clone-ace-target**: Clones ALL ACEs (both Allow and Deny) from source trustee to target trustee, preserving flags and rights. By default, skips if target already has an ACE of the same type. Use `--sync-cloned-aces` to update existing target ACEs to match source rights. Supports uid:N, gid:N, DOMAIN\\user, and plain name formats.
- **--migrate-trustees**: In-place trustee replacement. The source ACE's trustee is changed to the target trustee (preserving type, flags, and rights). Use for domain migrations where you want to replace OLD_DOMAIN\\user with NEW_DOMAIN\\user.
- **--clone-ace-map**: Bulk version of `--clone-ace-source/--clone-ace-target`. Reads mappings from CSV file. Each row creates cloned ACEs. Works with `--sync-cloned-aces`.
- **Canonical ordering**: ACEs are automatically sorted into Windows canonical order (Deny before Allow, Explicit before Inherited).
- **Empty ACE removal**: If `--remove-rights` removes all rights from an ACE, the ACE is deleted entirely.

**Inheritance Handling:**

When modifying an inherited ACE (one that has the INHERITED flag), grumpwalk automatically:
1. **Breaks inheritance** at the target path by adding PROTECTED to control flags
2. **Converts inherited ACEs to explicit** by removing the INHERITED flag from all ACEs
3. **Applies your modifications** to the now-explicit ACE

This establishes the target path as a new inheritance root. When used with `--propagate-changes`, the modified ACL propagates to all children with proper inheritance flags.

**Restarting Inheritance:**

To restart inheritance from a parent after breaking it, use the standard ACL cloning approach:
```bash
./grumpwalk.py --host cluster.example.com \
  --source-acl /parent/path --acl-target /child/path \
  --propagate-acls --progress
```

This copies the parent's ACL (with inherited flags set appropriately) to the child and its descendants.


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
- `--fields FIELD[,FIELD,...]` - Select specific output fields (aliases: `owner_id`, `group_id`, `attr.*`; dot notation supported). Use `--fields-list` to see all available fields
- `--fields-list` - List all available field names and exit
- `--unix-time` - Output timestamps as unix epoch seconds instead of ISO 8601
- `--limit N` - Stop after N matches
- `--progress` - Show real-time progress to the terminal (stderr)
- `--verbose` - Detailed diagnostic output to the terminal (stderr)
- `--log-file FILE` - Write log output to file with timezone-aware timestamps (independent of --verbose/--progress)
- `--log-level LEVEL` - Minimum level for --log-file: DEBUG, INFO (default), or ERROR
- **Log capture** - All status/error output goes to stderr. Capture with `2> logfile.txt`

### Performance Options
- `--max-concurrent N` - Concurrent operations (default: auto-tuned)
- `--connector-limit N` - HTTP connection pool size (default: auto-tuned)
- `--profile` - Performance profiling for user lookup operations
- `--retune` - Regenerate auto-tuning profile
- `--show-tuning` - Display current tuning profile
- `--tuning-profile {conservative,balanced,aggressive}` - Select tuning profile
- `--benchmark` - Test optimal concurrency for your cluster

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
--omit-path /data/archive       # Must start with / for filter to work (From Qumulo root, not Share root)
--omit-path /tmp/cache          # Can specify multiple paths
```

**Key differences:**
- `--omit-subdirs` uses pattern matching (wildcards like `*` and `?`)
- `--omit-path` requires exact absolute paths starting with `/`
- Both flags can be used multiple times
- Both increment the Smart Skip counter for progress tracking

## Auto-Tuning

Grumpwalk automatically detects your system resources and generates optimal performance settings on first run.

### First Run

On first run, grumpwalk detects your platform (macOS, Linux, Windows, WSL), available RAM, and file descriptor limits to generate a tuning profile saved to `tuning-profile` in the grumpwalk directory.

### Tuning Commands

```bash
# Show current tuning profile
./grumpwalk.py --show-tuning

# Regenerate tuning profile
./grumpwalk.py --retune

# Use a specific profile (conservative, balanced, aggressive)
./grumpwalk.py --host cluster --path /data --tuning-profile aggressive

# Run benchmark to find optimal settings for your cluster
./grumpwalk.py --host cluster --path /data --benchmark
```

### Benchmark Mode

The `--benchmark` flag tests multiple concurrency levels against your cluster and suggests optimal settings:

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

## Performance Tips

1. **Use --max-depth** to limit search scope
2. **Enable --progress** to monitor large searches
3. **Use --omit-subdirs** to skip directories by pattern, or **--omit-path** for exact paths
4. **Combine filters** - More filters = fewer results to process
5. **Use --limit** for testing before full runs
6. **Smart skipping** automatically avoids directories that can't match your filters

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

Joe Costa `joe at qumulo.com`

## Contributing

Pull requests welcome at https://github.com/Joe-Costa/grumpwalk
