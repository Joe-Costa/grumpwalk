# grumpwalk.py

**Version 3.7.0** | [Changelog](CHANGELOG.md) | [User Guide](grumpwalk_users_guide.md)

<img height="300" alt="grumprun" src="https://github.com/user-attachments/assets/37ec015f-7ff1-40e5-ba7f-02440079974b" />

High-performance, multi-purpose file crawling tool for Qumulo storage systems.

- **Find files by name, owner, size or timestamps**
- **Easily replace permissions on thousands of files**
- **Search and restore Snapshots**
- **Find similar files**
- **Find and resolve symlinks**
- **And more!**

I've observed performance as high as 12k objects per second processed against an old QC24 Qumulo cluster.<br>The lower the latency you have between where this code is running and the Qumulo cluster the better your performance
will be.<br>Keep in mind that some operations will read contents of files, which might be slower over low bandwidth public internet & VPN connections.

Please note that this tool should not be installed directly in a Qumulo node, due to RAM use conflicts. 

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
- **Directory statistics** - Quick aggregate counts without a tree walk (`--stats`)
- **Per-directory match report** - Count and capacity of files matching your filters, broken down by directory (`--per-directory-matches`)
- **Directory scope preview** - Shows total subdirs/files before every operation
- **Owner reports** - Generate storage capacity breakdowns by owner
- **Permissions reports** - Retrieve permissions ACLs of objects in tree
- **ACL and owner/group management** - Copy ACLs, owner, and group between objects
- **ACE manipulation** - Surgically add, remove, or modify individual ACEs within ACLs
- **Move, copy, and rename** - Server-side move (`--move-to`), copy (`--copy-to`), and bulk rename (`--rename-to`) of matched objects, with optional attribute preservation and incremental sync
- **Snapshot search and restore** - Search across snapshots, copy or restore snapshot versions (Qumulo has no native restore), `--restore-in-place` undelete, whole-directory `--revert`, byte-range `--delta` restore for large files, and `--incremental` diff-driven multi-snapshot search
- **Object tagging** - Add, find, and remove custom key/value tags on matching objects
- **Extended attribute management** - Find and set DOS attributes (read_only, hidden, system, archive)
- **Similarity detection** - Find similar files using adaptive sampling
- **Auto-tuning** - Automatic performance tuning based on system resources

## Requirements

- Python 3.8+
- `aiohttp` - Install with: `pip install aiohttp`
- `ujson` (optional) - For faster JSON parsing: `pip install ujson`
- `argcomplete` - For bash completion support: `pip install argcomplete`

## Optional Requirements

- `qumulo_api` - Install with: `pip install qumulo_api`
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


## Logging in wih a long lived API access key (Preferred method)

You can read about how to create API keys [in this help article](https://docs.qumulo.com/administrator-guide/connecting-to-external-services/creating-using-access-tokens-to-authenticate-external-services-qumulo-core.html) 

Save your access key to a file and use the `--credentials-store` option:

`grumpwalk.py --host cluster.example.com --credentials-store /path/to/keyfile`

**Treat these API keys as any other user credentials and secure them properly!**

## Logging into a cluster with a temporary key using the `qq` CLI (Key expires after 10 hours)

If you have installed the `qq` CLI you can login with:

`qq --host cluster.example.com login -u "DOMAIN\user"`

**Login with a user that has the correct RBAC rights for any operations you want `grumpwalk.py` to perform!**

This will save a `.qfsd_cred` file in your current user's home directory. Note that these keys auto expire after 10 hours.

**Treat these API keys as any other user credentials and secure them properly!**

## Helpful Qumulo Care Articles

[How to get an Access Token](https://docs.qumulo.com/administrator-guide/connecting-to-external-services/creating-using-access-tokens-to-authenticate-external-services-qumulo-core.html) 

[Qumulo Role Based Access Control](https://care.qumulo.com/hc/en-us/articles/360036591633-Role-Based-Access-Control-RBAC-with-Qumulo-Core#managing-roles-by-using-the-web-ui-0-7)

## An important note about access_time

If your cluster does not have `atime` updating enabled then be aware that the `access_time` attribute will remain the same as the file creation time.
<br><br>
Updating the `atime` attribute on file read and write ops is disabled by default on Qumulo clusters, you can learn more about this feature here:
<br><br>
[Enabling Access Time Updates for File and Directory Reads in Qumulo Core](https://care.qumulo.com/s/article/Enabling-Access-Time-Updates-for-File-and-Directory-Reads-in-Qumulo-Core?)


## Quick Examples

```bash
# List all files in a directory
./grumpwalk.py --host cluster.example.com --path /home

# Find files older than 30 days
./grumpwalk.py --host cluster.example.com --path /home --older-than 30

# Find large log files with progress
./grumpwalk.py --host cluster.example.com --path /var --name '*.log' --larger-than 100MB --progress

# Search for Python test files
./grumpwalk.py --host cluster.example.com --path /code --glob --name 'test_*.py' --type file

# Find files older than 90 days, skipping hidden files
./grumpwalk.py --host cluster.example.com --path /data --older-than 90 --glob --not-name '.*'

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

# Set POSIX mode (like chmod)
./grumpwalk.py --host cluster.example.com --set-mode 755 --path /data/project

# Recursive chmod with ownership change
./grumpwalk.py --host cluster.example.com --set-mode 2775 --path /data/shared --new-owner uid:1001 --new-group gid:5000 --propagate --progress

# Disable inheritance - convert inherited ACEs to explicit (icacls /inheritance:d)
./grumpwalk.py --host cluster.example.com --path /data/project --disable-inheritance --propagate --progress

# Disable inheritance - remove all inherited ACEs (icacls /inheritance:r)
./grumpwalk.py --host cluster.example.com --path /data/project --disable-inheritance --remove-inherited --propagate --progress

# Tag matching objects with a custom key/value (composes with all filters)
./grumpwalk.py --host cluster.example.com --path /data --name '*.jpg' --modified-newer-than 3 --add-tag --key reviewed --value yes

# Preview a tagging run without writing anything
./grumpwalk.py --host cluster.example.com --path /data --add-tag --key project --value alpha --dry-run

# Find objects carrying a tag (streams matches as NDJSON to stdout)
./grumpwalk.py --host cluster.example.com --path /data --find-tag --key reviewed --value yes > reviewed.ndjson

# Remove a tag from matching objects (only when the value matches, for safety)
./grumpwalk.py --host cluster.example.com --path /data --remove-tag --key reviewed --value yes --dry-run

# Find similar files
./grumpwalk.py --host cluster.example.com --path /backups --find-similar --progress

# Quick directory statistics (no tree walk)
./grumpwalk.py --host cluster.example.com --path /data --stats

# Directory statistics with one level of subdirectory breakdown
./grumpwalk.py --host cluster.example.com --path /data --stats --max-depth 1

# How much data was modified in the last 30 days, per directory (largest first)
./grumpwalk.py --host cluster.example.com --path /data --modified --newer-than 30 --type file --per-directory-matches --sort size

# Same, but list stale data: files not modified in 180+ days, per directory
./grumpwalk.py --host cluster.example.com --path /archive --modified --older-than 180 --type file --per-directory-matches --sort size
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
- `--path PATH` - Path to act on: a directory (walked recursively) or a single file/symlink (acted on directly). Required for walk mode
- `--port PORT` - API port (default: 8000)
- `--credentials-store PATH` - Credentials file path
- `--update-atime` - Allow access times (atime) to be updated by grumpwalk's reads. By default, on clusters that support it (Qumulo Core 7.9.0+), grumpwalk suppresses atime updates so a crawl does not disturb access-time metadata. This flag restores normal atime behavior.

### Name/Type Filters
- `--name PATTERN` - Match by name (glob/regex, OR logic, repeatable)
- `--name-and PATTERN` - Match by name (AND logic, repeatable)
- `--not-name PATTERN` - Exclude by name (repeatable; excluded if it matches any pattern). Tests each object's own name, not its path, and applies to directories as well as files: `--not-name '.*'` drops the `.git` directory itself, but the ordinary-named files inside it are still reported - add `--omit-subdirs` to skip its contents too. Skip hidden files with `--glob --not-name '.*'`
- `--name-case-sensitive` - Case-sensitive name matching
- `--glob` - Read every name pattern as a shell glob (`.` and `+` are literal, the match covers the whole name)
- `--regex` - Read every name pattern as a regular expression (unanchored - anchor with `^`/`$` yourself)
- `--type {file,directory,symlink}` - Filter by object type
- `--file-only` - Search files only (deprecated, use `--type file`)

Name patterns accept globs or regular expressions and grumpwalk works out which
you meant. A few are valid as both and mean different things - `.*` is a regular
expression matching everything, but a glob meaning "starts with a period" - so
grumpwalk warns when it has to choose. Use `--glob` or `--regex` to decide
yourself. Both also apply to `--omit-subdirs`, which stays a glob unless you pass
`--regex`.

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
- `--stats` - Show directory aggregate statistics (files, subdirectories, total size) and exit. Reports the whole subtree and ignores per-file filters (time, size, name, type, owner); use `--per-directory-matches` when you need a filtered breakdown. Supports `--max-depth`, `--omit-subdirs`, `--omit-path`, and all output options (`--json`, `--json-out`, `--csv-out`)
- `--sort {size,count,name}` - Sort `--stats` or `--per-directory-matches` table output by total size, file count, or path name
- `--show-dir-stats` - Show directory statistics (file/dir counts, sizes)
- `--per-directory-matches` - Report, per directory, the number of matching files and how much disk capacity they use. Applies all your filters (time, size, name, type, owner) and `--max-depth`. By default it lists the immediate subdirectories of `--path`, each total covering everything beneath it, plus a grand total. Works with `--sort` and with `--csv-out` / `--json-out` / `--json`
- `--subdir-report` - With `--per-directory-matches`, break the report down to every subdirectory that contains matches, not just the top level. Respects `--max-depth`

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

### POSIX Mode Options
- `--set-mode MODE` - Set POSIX permissions using chmod-style octal (e.g., `755`, `2770`, `0644`). Replaces the ACL with `OWNER@`/`GROUP@`/`EVERYONE@` entries. Use `--propagate` for recursive application. Setgid (`2xxx`) is applied to directories only.
- `--new-owner IDENTITY` - Set file owner (use with `--set-mode`). Accepts `uid:N`, username, `DOMAIN\user`, or SID. Uses the specified identity as the owner ACL trustee and changes file ownership.
- `--new-group IDENTITY` - Set file group (use with `--set-mode`). Accepts `gid:N`, groupname, `DOMAIN\group`, or SID. Uses the specified identity as the group ACL trustee and changes file group ownership.

### ACL Management Options
- `--source-acl PATH` - Source ACL from cluster path
- `--source-acl-file FILE` - Source ACL from local JSON file
- `--acl-target PATH` - Target object/directory path
- `--propagate-acls`, `--propagate` - Apply to all child objects recursively
- `--continue-on-error` - Continue on errors without prompting
- `--copy-owner` - Copy owner from source
- `--copy-group` - Copy group from source
- `--owner-group-only` - Copy only owner/group, skip ACL
- `--acl-concurrency N` - Concurrent ACL operations (default: 100, try 500 for faster throughput)
- `--disable-inheritance` - Disable ACL inheritance at `--path`. Converts inherited ACEs to explicit (like `icacls /inheritance:d`). Use with `--remove-inherited` to delete inherited ACEs instead (like `icacls /inheritance:r`). Supports `--propagate` for recursive application.
- `--remove-inherited` - When used with `--disable-inheritance`, removes all inherited ACEs entirely instead of converting them to explicit. Warning: leaves objects with no ACEs if all entries were inherited.

### Object Tagging Options

Add, find, and remove custom key/value tags (Qumulo user metadata) on objects that match the active filters. The three modes are mutually exclusive and all work with the universal filters plus `--progress`, `--dry-run`, and `--limit`.

- `--add-tag` - Add or update a tag on matching objects. Requires `--key` and `--value`.
- `--find-tag` - List objects whose tags match `--key` and/or `--value` (or any tagged object if neither is given). Streams one JSON line per match to stdout.
- `--remove-tag` - Remove tag `--key` from matching objects. With `--value`, removes only when the current value matches.
- `--key KEY` - Tag key. Required for `--add-tag` and `--remove-tag`; optional filter for `--find-tag`.
- `--value VALUE` - Tag value. Required for `--add-tag`; optional filter or guard otherwise.
- `--overwrite` - (`--add-tag`) Replace an existing value. Without it, objects whose key already holds a different value are skipped with a warning; a key already set to the same value is left unchanged.
- `--tag-concurrency N` - Concurrent tag operations during a walk (default: auto-tuned).

A tag is applied to every matching object under `--path`; use `--max-depth 0` to act only on `--path` itself. Per-object lines are shown with `--dry-run` or `--verbose`, and `--progress` shows a running counter.

### Move, Copy, and Rename Options

Move, server-side copy, and/or rename objects matching the filters, modeled on POSIX `mv`/`cp`. A move is a single RENAME metadata operation; a copy uses the Qumulo `copy-chunk` API so data is copied on the cluster (not streamed through grumpwalk). Composes with all universal filters plus `--progress`, `--dry-run`, and `--limit`.

- `--move-to DEST` - Move matching objects into the existing directory DEST. Matches are flattened into DEST (like `mv a/x b/x DEST/`).
- `--copy-to DEST` - Server-side **copy** matching objects into the existing directory DEST (flattened, like `cp`). Mutually exclusive with `--move-to`. Each file is copied via a temp name and atomically renamed into place, so an interrupted copy never leaves a partial destination.
- `--preserve-permissions` - With `--copy-to`, also copy each source's owner, group, and ACL/mode. Without it, only data is copied (owner becomes you, permissions inherited from DEST - like plain `cp`).
- `--preserve-all` - With `--copy-to`, preserve every settable attribute: owner, group, ACL/mode, DOS extended attributes, GENERIC user-metadata tags, and timestamps (modification/access/creation). `change_time` (ctime) reflects the copy and cannot be preserved.
- `--create-destination-directory` - With `--copy-to` or `--move-to`, create DEST (and any missing parents, like `mkdir -p`) if it does not exist. You are prompted to inherit permissions from the parent or set a POSIX mode. Without this flag a missing DEST is an error.
  - `--destination-directory-mode MODE` - Set this octal mode (e.g. `0755`) on the new directories instead of prompting (omit to inherit from the parent; non-interactive runs without it inherit).
  - `--destination-directory-owner OWNER` - Set the owner of the new directories (name, `uid:N`, SID, or `DOMAIN\user`).
  - Note: the mode/owner flags apply only to directories grumpwalk creates. If DEST already exists they are ignored with a warning, and the copy/move proceeds into the existing directory unchanged.
- `--rename-to PATTERN` - Rename matching objects. Two styles:
  - **Substitution** `{old|new}` replaces matched text and leaves the rest of the name unchanged. Regex and `*`/`?` wildcards are supported: `{my|our}`, `{IMG_*|photo_*}`, `{(\d+)|v\1}`, `{.jpeg|.jpg}`, `{_old|}` (empty replacement deletes text).
  - **Template** (no braces) is the whole new name; `*`/`?` are filled from the matching `--name` glob: `--name 'my_*' --rename-to 'our_*'`.

  Use `--rename-to` alone to rename in place, or with `--move-to`/`--copy-to` to transfer and rename in one pass.
- `--clobber` - Overwrite an existing destination entry (default: skip with a warning). Two matched sources mapping to the same target are always skipped, even with `--clobber`. For `--copy-to`, an existing target *directory* is skipped (no merge).
- `--skip-unchanged` - With `--copy-to`, incremental sync: skip destination files that already match the source's size and modification time, and copy only new or changed files. Re-runnable for keeping a destination in step with a changing source. Implies `--preserve-all`. (To simply *resume* an interrupted copy, no flag is needed - re-run the command and only the missing files are copied.)
- `--include-directories` - Also move/copy matched directories (the whole subtree). For `--copy-to`, the directory is recreated under DEST and its files, subdirectories, and symlinks are copied recursively. Descendants that travel with a transferred directory are pruned (not transferred twice), and transferring a directory into its own subtree is refused. Default: only files and symlinks are moved/copied.
- `--move-concurrency N` / `--copy-concurrency N` - Concurrent move / copy operations (default: auto-tuned).
- `--yes` - Skip the confirmation prompt. Required for non-interactive runs (grumpwalk refuses without confirmation otherwise).

**Important:** Always use `--dry-run` first to preview the full `source -> target` plan before applying.

### Snapshot Options

Search, copy, and restore data from Qumulo snapshots (Qumulo has no native restore call). Snapshot reads find files as they were at snapshot time, **including files deleted since**.

- `--list-snapshots` - List snapshots (id, timestamp, name, source path) and exit. Add `--path` to list only snapshots whose source covers that path (the path itself or an ancestor) - the ones you can search or restore it from. Replication snapshots and snapshots being deleted are hidden by default.
- `--include-replication-snapshots` - Include Qumulo replication-system snapshots (`replication_from_*`/`replication_to_*`) in listing and search. Excluded by default, since they are not useful for restoring data. (Snapshots being deleted are always hidden.)
- `--snapshot ID` - Run the crawl/search in snapshot ID's context; composes with every filter and output mode.
- `--all-snapshots` - Search across all snapshots (used instead of `--path`); with `--path`, only snapshots whose source covers it. Each match is annotated with its snapshot. Search-only.
- `--snapshots-newer-than DURATION` / `--snapshots-older-than DURATION` - Limit the snapshot set by snapshot age (UTC). Accepts days or hours: `5`/`5d` = 5 days, `12h` = 12 hours. On their own they imply `--all-snapshots` (search across the snapshots in that window); also work with `--list-snapshots`/`--in-the-last-snapshots`. Distinct from `--older-than`/`--newer-than`, which filter files.
- `--in-the-last-snapshots N` - Search the N most recent snapshots and show only the newest result per path (dedupes the same file across snapshots). Composes with the filters and snapshot-age limits. Search-only.
- `--incremental` - Speed up a multi-snapshot search: crawl only the oldest covered snapshot in full, then use the snapshot tree diff between consecutive snapshots to update the match set for each later one (re-checking only the files that changed). Identical results to crawling each snapshot, far fewer API calls when snapshots are mostly alike. Requires `--path`; not supported with `--max-depth` or access-time filters.
- `--snapshot ID --copy-to DEST` - Copy the snapshot version of matched files (incl. deleted) to a live DEST. Reuses the full copy feature (`--rename-to`, `--preserve-*`, `--include-directories`, `--create-destination-directory`).
- `--snapshot ID --restore-in-place` - Restore matched files to their original live paths (undelete / roll back): recreate files/dirs deleted since the snapshot, and with `--clobber` overwrite the current live version. Destructive - needs `--yes`/confirmation; preview with `--dry-run`. With `--include-directories` (or `--type directory`) a matched directory is restored as a full subtree - the directory and every descendant, including empty subdirectories; restoring into a directory that still exists live merges, with per-file conflict handling. Without those flags, directories are skipped and only files are restored.
- `--snapshot ID --revert` - Restore the whole directory at `--path` to its state in the snapshot, using the tree diff to act only on what changed: recreate files/dirs deleted since and restore modified files. Files created since the snapshot are **kept by default**; add `--delete-new` to also remove them for an exact byte-identical rollback. Whole-directory operation (ignores name/type/owner filters); overwrites modified files - needs `--yes`, preview with `--dry-run`.
- `--delta` - With `--restore-in-place` or `--revert`, patch modified files in place by copying only the byte ranges that differ from the snapshot, instead of rewriting the whole file - far faster for large files with localized edits, and it preserves file mode (no temp-file + rename). `--delta-threshold SIZE` (default 1 MiB) copies files below SIZE whole in place and byte-range-diffs only larger ones (keeps `--delta` optimal on mixed trees); `0` byte-range-diffs every file.
- `--rename-on-conflict` - On a name conflict (during copy/restore), write the item under a `_restored_<date>_<time>` suffix instead of skipping (default) or overwriting (`--clobber`). Mutually exclusive with `--clobber`; customize with `--conflict-suffix`.

```bash
# Find report.docx in any snapshot from the last week (fast diff-driven scan)
./grumpwalk.py --host HOST --all-snapshots --snapshots-newer-than 7 --glob --name 'report.docx' --incremental

# Restore everything matching, from a chosen snapshot, back to where it was
./grumpwalk.py --host HOST --snapshot 5 --path /Shared --name '*.docx' --restore-in-place --clobber --yes

# Revert a whole directory to a snapshot, patching only changed bytes of large files
./grumpwalk.py --host HOST --snapshot 5 --path /Shared/project --revert --delta --yes

# Restore an entire deleted directory (subtree, including empty subdirs)
./grumpwalk.py --host HOST --snapshot 5 --path /Shared --max-depth 1 --name 'project-x' \
    --type directory --restore-in-place --yes
```

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
- `--propagate-changes` - Apply the change to every object in the tree, checking each object's own ACL individually so only the matching ACE is touched and every other permission is left intact. It does not copy the parent's ACL onto its children, and it does not stop at a folder that lacks the ACE - the whole tree is searched. Without this flag, only the `--path` object is changed. (`--propagate-acls` also accepted.)
- `--sync-cloned-aces` - When cloning, update existing target ACEs to match source rights
- `--dry-run` - Preview what would change without applying anything. With `--propagate-changes`, it searches the whole tree and reports how many objects would change versus stay untouched, and lists the objects that would be modified - so you can confirm the exact scope before running for real.
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

**Disabling Inheritance Directly:**

Use `--disable-inheritance` for standalone inheritance control without other ACE modifications:

```bash
# Convert inherited ACEs to explicit, preserving all entries (icacls /inheritance:d)
./grumpwalk.py --host cluster --path /data/project \
  --disable-inheritance --propagate --progress

# Remove all inherited ACEs entirely (icacls /inheritance:r)
./grumpwalk.py --host cluster --path /data/project \
  --disable-inheritance --remove-inherited --propagate --progress

# Preview changes first
./grumpwalk.py --host cluster --path /data/project \
  --disable-inheritance --remove-inherited --propagate --dry-run
```

| Mode | Flag | Behavior | icacls equivalent |
|------|------|----------|-------------------|
| Convert | `--disable-inheritance` | Inherited ACEs become explicit | `/inheritance:d` |
| Remove | `--disable-inheritance --remove-inherited` | Inherited ACEs are deleted | `/inheritance:r` |

Both modes set the PROTECTED control flag to block future inheritance from parent directories. Supports all standard filters (`--type`, `--name`, `--max-depth`, etc.) and `--continue-on-error`.

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
- `--show-details` - Show attributes of matched results instead of just paths (snapshot search and the live walk). Defaults to `path`, human-readable `size`, and `change_time` (ctime); renders an aligned table, or honors `--csv-out`/`--json-out`/`--json` (size stays raw bytes there). Multi-snapshot search adds a `SNAPSHOT` column. With `--type directory` the size column becomes the recursive aggregate `capacity` (whole-subtree, from directory aggregates). `--limit` caps the rows shown
- `--fields FIELD[,FIELD,...]` - Select specific output fields (aliases: `owner_id`, `group_id`, `attr.*`; dot notation supported). `--fields all` selects every attribute (implies `--show-details`). Use `--fields-list` to see all available fields
- `--fields-list` - List all available field names and exit
- `--unix-time` - Output timestamps as unix epoch seconds instead of ISO 8601
- `--limit N` - Stop after N matches
- `--progress` - Show real-time progress to the terminal (stderr). During `--copy-to` and snapshot restores it reports files done, data copied, transfer rate, and ETA
- `--verbose` - Detailed diagnostic output to the terminal (stderr)
- `--log-file FILE` - Write log output to file with timezone-aware timestamps (independent of --verbose/--progress)
- `--log-level LEVEL` - Minimum level for --log-file: DEBUG, INFO (default), or ERROR
- **Log capture** - All status/error output goes to stderr. Capture with `2> logfile.txt`

### Performance Options
- `--max-concurrent N` - Concurrent operations (default: auto-tuned)
- `--connector-limit N` - HTTP connection pool size (default: auto-tuned)
- `--max-retries N` - Retries for a transient read failure before a directory is reported as failed (default: 5, `0` disables)
- `--profile` - Performance profiling for user lookup operations
- `--retune` - Regenerate auto-tuning profile
- `--show-tuning` - Display current tuning profile
- `--tuning-profile {conservative,balanced,aggressive}` - Select tuning profile
- `--benchmark` - Test optimal concurrency for your cluster

### Rate Limiting and Transient Errors

Clusters, proxies, and busy networks can occasionally refuse a request - a rate
limit (HTTP 429), a brief server error, or a dropped connection. grumpwalk
retries these automatically with increasing wait times (honoring the server's
`Retry-After` when given), so a momentary refusal does not cost you any
results. `--max-retries` controls how persistent it is.

If a directory still cannot be read after all retries, grumpwalk does not
pretend the run succeeded: it prints an `INCOMPLETE CRAWL` warning listing the
affected directories and **exits with code 2**, so scheduled jobs and scripts
can detect a partial result. This applies to every operation that walks the
tree - exports, reports, ACL/ACE changes, tagging, move/copy, and snapshot
search. If you see repeated rate limiting, lower `--max-concurrent` and re-run.

## Pattern Matching

### Glob Patterns (shell-style)
```bash
--name '*.log'                  # Names ending in .log
--name 'test_*'                 # Names starting with test_ (NOT "mytest_1")
--glob --name 'file?.txt'       # file1.txt, fileA.txt, etc.
--glob --name 'test_*.py'       # test_foo.py, test_bar.py
--name 'report'                 # Exactly "report" (no wildcards = exact name)
--name '*report*'               # Any name containing "report"
```

Globs match the **whole name** (like the shell), so `test_*` matches names that
*begin* with `test_`, not names that merely contain it; a pattern with no
wildcards matches the exact name. Always **quote** patterns (`--name 'file_*'`)
so your shell does not expand the `*` against your local working directory
before grumpwalk sees it.

Note the `--glob` on two of those examples. A glob that also happens to be a
valid regular expression is read as a regular expression, and `file?.txt` and
`test_*.py` both are - as regexes they mean something quite different, so
`--name 'test_*.py'` on its own does **not** find `test_foo.py`. grumpwalk warns
when a pattern is ambiguous like this; `--glob` settles it. Patterns whose
wildcard comes first (`*.log`, `*report*`) cannot be regexes, so they need
nothing extra.

### Regex Patterns
```bash
--name '^test_.*\.py$'   # Python test files (anchored)
--name '.*\.(jpg|png)$'  # Image files
--name 'file_.*'         # Regex (the '.' makes it regex): any name CONTAINING file_
```

**Auto-detection:** Patterns with `/`, `^`, `$`, or regex chars are treated as regex. Others as glob. Unlike globs, regex patterns are matched unanchored (substring); anchor them yourself with `^` and `$`.

**Overriding it:** `--glob` reads every pattern as a shell glob, `--regex` reads every one as a regular expression. Use them whenever a pattern could be read either way - grumpwalk warns when that happens. Both also apply to `--omit-subdirs`, which is read as a glob unless you pass `--regex`.

**Non-ASCII names:** patterns and names are matched as Unicode text, so wildcards work per character (`?` matches one accented or CJK character, not one byte) and case-insensitive matching works across scripts. Matching does **not** normalize, so a name stored in one Unicode form is not matched by a pattern typed in another - relevant when macOS clients write names like `café` in decomposed form. If an accented name will not match, copy the name straight from grumpwalk output rather than retyping it.

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
7. **If you see rate limiting** (429 warnings or an INCOMPLETE CRAWL report), lower **--max-concurrent** and re-run

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
