# Changelog

All notable changes to grumpwalk will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
