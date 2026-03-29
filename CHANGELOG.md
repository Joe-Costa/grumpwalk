# Changelog

All notable changes to grumpwalk will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.5.0] - 2026-03-29

### Added

- **Custom field selection** - `--fields` flag for explicit control over output columns
  - Comma-separated field list: `--fields path,size,modification_time`
  - Friendly aliases for nested fields: `owner_id`, `owner_type`, `group_id`, `group_type`
  - `attr.<name>` alias for extended attributes (e.g., `attr.archive`, `attr.hidden`)
  - Full dot notation also supported (e.g., `owner_details.id_value`)
  - Works with all output modes: JSON stdout, plain text (tab-separated), `--csv-out`, `--json-out`
  - Missing fields produce null in JSON, empty string in CSV/text
  - Including `owner_name` or `group_name` implicitly triggers identity resolution
- `--fields-list` flag to display all available field names with descriptions and exit
- `--unix-time` flag to output timestamps as unix epoch seconds instead of ISO 8601
  - Converts `creation_time`, `modification_time`, `access_time`, `change_time`
  - Applies to stdout and file output only; stderr/logging timestamps are unaffected
  - Works with all output modes and composable with `--fields`

### Documentation

- **README restructure**
  - Added table of contents with section links
  - Moved Output Formats section up (now appears after Quick Examples)
  - Removed Advanced Examples section (all examples already covered in User Guide)
  - Reorganized Command Reference: General and Connection sections at top, added missing flags (`--fields`, `--fields-list`, `--unix-time`, `--dry-run`, `--version`, `--retune`, `--show-tuning`, `--tuning-profile`, `--benchmark`)
  - Added `--fields` and `--fields` + `--json` examples to Output Formats
- **User Guide**
  - Added "How do I select specific output fields?" section with `--fields` usage, aliases, dot notation, and `--fields-list`
  - Added "How do I output timestamps as unix epoch seconds?" section with `--unix-time` usage

---

## [2.4.0] - 2026-03-27

### Added

- **Extended attribute filtering** - Find files by any of the nine Qumulo extended attributes
  - `--find-attribute-true ATTR[,ATTR,...]` - Find files where listed attributes are true
  - `--find-attribute-false ATTR[,ATTR,...]` - Find files where listed attributes are false
  - Findable attributes: `read_only`, `hidden`, `system`, `archive`, `temporary`, `compressed`, `not_content_indexed`, `sparse_file`, `offline`
  - Short aliases supported: `sparse`, `readonly`, `nci`, `not_indexed`
  - Typo detection with closest-match suggestions
- **Extended attribute modification** - Set the four DOS attributes (`read_only`, `hidden`, `system`, `archive`) on matched files
  - `--set-attribute-true ATTR[,ATTR,...]` - Set listed DOS attributes to true
  - `--set-attribute-false ATTR[,ATTR,...]` - Set listed DOS attributes to false
  - Works with `--propagate-changes` for recursive application
  - Supports `--dry-run` to preview changes before applying
  - Supports `--continue-on-error` to skip failures during propagation
  - Composable with all existing filters (time, size, name, owner, type)
- **Find/set pairing validation** - Positional pairing rules enforce correct usage
  - A find/set pair must use opposite booleans and appear adjacent on the command line
  - Both opposite-boolean pairs may appear in a single command
  - Same-boolean pairs and non-adjacent pairs produce clear error messages

### Documentation

- Added "How do I find and manage files by DOS extended attributes?" section to user guide with usage examples
- Noted that DOS attributes are only honored by SMB clients and have no impact on NFS, REST, FTP, or S3 access

---

## [2.3.0] - 2026-03-26

### Added

- **Timestamped log entries** - All tagged stderr output ([ERROR], [WARN], [INFO], [DEBUG], etc.) now includes timestamps in format `[YYYY-MM-DD HH:MM:SS] [TAG] message`
- **Scope header for propagation actions** - ACL cloning, ACE propagation, ACE restore propagation, and owner/group change modes now display directory aggregate counts (subdirectories and files) before the operation begins, matching the existing walk mode behavior
- `--dry-run` support for ACL cloning mode (`--source-acl --acl-target --propagate-acls --dry-run`) - Walks the tree and reports what would change without calling any write APIs
- `--log-file FILE` flag - Write log output to a file with timezone-aware timestamps (e.g. `[2026-03-26 11:09:38 PDT]`). Log file includes a header recording the local timezone. Config banner is included for context. Independent of `--verbose` and `--progress`.
- `--log-level DEBUG|INFO|ERROR` flag - Control minimum log level written to `--log-file` (default: INFO). ERROR includes errors, warnings, and hints. INFO adds operational messages. DEBUG adds all diagnostic output.

### Fixed

- ACL cloning mode (`--source-acl --acl-target`) ignored `--dry-run` flag and would apply ACLs despite dry-run being specified

### Documentation

- Documented `--verbose` flag: what each category of additional output shows, when to use it vs `--progress`, with example output
- Documented log file capture: `--log-file` usage and stderr redirection patterns
- Clarified that `--verbose` and `--progress` control terminal (stderr) output, independent of `--log-file`

### Changed

- Walk mode refactored to use `display_scope_aggregates()` helper (no behavior change)
- HTTP errors now route through `log_stderr` so they appear in log files
- Ephemeral progress lines (`\r` overwrite lines) intentionally excluded from timestamps to preserve terminal display

---

## [2.2.0] - 2026-03-02

### Added

- `--dont-resolve-ids` flag - Skip identity resolution for `--show-owner`/`--show-group` and output raw UID/GID/SID values instead of resolved names
  - Faster output when human-readable names are not needed
  - Output format: `UID:1001`, `GID:100`, `SID:S-1-5-21-...`, or `auth_id:<value>` for local accounts
  - Works with all output modes: plain text, JSON, CSV, and ACL reports

---

## [2.1.0] - 2026-02-13

### Added

- **Auto-tuning system** - Automatic performance tuning based on system resources
  - Detects platform (macOS, Linux, Windows, WSL)
  - Detects available RAM and file descriptor limits
  - Generates tuning profile on first run, saved to `tuning-profile`
  - Platform-specific multipliers for optimal performance
- `--retune` flag to regenerate tuning profile
- `--show-tuning` flag to display current tuning profile
- `--tuning-profile` option to select profile: conservative, balanced, aggressive
- `--benchmark` flag to test optimal concurrency for your specific cluster
  - Tests multiple concurrency levels (100-400)
  - Measures throughput and suggests optimal settings
  - Option to save benchmark results to tuning profile

---

## [2.0.1] - 2025-02-12

### Fixed

- ACL inheritance breaking now uses correct `PROTECTED` control flag (was using invalid `DACL_PROTECTED`)
- Trustee names now display correctly for Active Directory users/groups (was showing `unknown:auth_id`)

### Changed

- `--propagate-acls` is now accepted for ACE manipulation operations (auto-converts to `--propagate-changes`)

---

## [2.0.0] - 2025-02-06

Initial versioned release of grumpwalk.

### Core Features

- **Async directory tree walking** - High-performance crawling with configurable concurrency
- **Comprehensive filtering** - Filter by time, size, name patterns, owner, and file type
- **Smart directory skipping** - Uses aggregates API to skip directories that cannot match filters
- **Streaming output** - Memory-efficient NDJSON output for any file count
- **CSV/JSON file output** - Streaming file output to handle millions of files without OOM
- **Progress tracking** - Real-time progress with file counts and rates
- **Identity caching** - Persistent cache for auth_id to name resolution

### ACL Cloning

- `--source-acl` / `--acl-target` - Clone entire ACL from source path to target
- `--source-acl-file` - Clone ACL from a saved JSON file
- `--propagate-acls` - Apply cloned ACL to all children recursively
- `--copy-owner` / `--copy-group` - Copy owner and/or group along with ACL
- `--owner-group-only` - Copy only owner/group without modifying ACL
- `--continue-on-error` - Continue on errors without prompting

### ACE Manipulation

- `--add-ace` - Add ACE with format `Type:Flags:Trustee:Rights` (merges if exists)
- `--remove-ace` - Remove ACE matching `Type:Trustee`
- `--replace-ace` - Replace ACE in-place or with `--new-ace` for full replacement
- `--new-ace` - Paired with `--replace-ace` to change ACE type (Allow/Deny)
- `--add-rights` / `--remove-rights` - Surgically add or remove specific rights
- `--clone-ace-source` / `--clone-ace-target` - Clone ACEs from one trustee to another
- `--sync-cloned-aces` - Update existing target ACEs to match source rights
- `--migrate-trustees` - Bulk in-place trustee replacement from CSV file
- `--clone-ace-map` - Bulk ACE cloning from CSV file
- `--propagate-changes` - Apply ACE changes to all children recursively

### ACL Backup and Restore

- `--ace-backup` - Save original ACLs to JSON before making changes
- `--ace-restore` - Restore ACLs from backup with file_id verification
- `--force-restore` - Skip file_id verification during restore
- `--dry-run` - Preview changes without applying them

### Owner and Group Management

- `--change-owner` - Change owner from SOURCE to TARGET
- `--change-group` - Change group from SOURCE to TARGET
- `--change-owners-file` - Bulk owner changes from CSV file
- `--change-groups-file` - Bulk group changes from CSV file
- `--show-owner` / `--show-group` - Display owner/group in output

### Reporting

- `--owner-report` - Storage capacity breakdown by owner
- `--acl-report` - ACL inventory with unique ACL analysis
- `--acl-csv` - Export per-file ACL data to CSV
- `--acl-resolve-names` - Resolve auth_ids to human-readable names

### Added in This Release

- `--version` flag to display version information
- Early connection testing with descriptive error messages
- Authentication verification before operations begin
- Improved error messages for connection timeouts, DNS failures, and auth errors
- Memory planning documentation for large-scale deployments

### Fixed

- Owner filter now correctly returns no files when identity resolution fails
- Backslash escaping in DOMAIN\username format for identity lookups
- Multiple jq examples in user guide now include required `--json --all-attributes` flags

---

For installation and usage, see [README.md](README.md) and [grumpwalk_users_guide.md](grumpwalk_users_guide.md).

---

## Release Checklist

When releasing a new version, update the version number in:
1. `grumpwalk.py` - `__version__` variable
2. `README.md` - Version line at top
3. `grumpwalk_users_guide.md` - Version line at top
4. `CHANGELOG.md` - Add new version section
