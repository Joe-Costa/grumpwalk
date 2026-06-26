# Changelog

All notable changes to grumpwalk will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.3.1] - 2026-06-26

### Added

- **`--incremental` (faster multi-snapshot search)** - Speeds up a multi-snapshot search (`--all-snapshots`, `--snapshots-newer-than`/`--snapshots-older-than`, `--in-the-last-snapshots`) by crawling only the OLDEST covered snapshot in full and then using the snapshot **tree diff** (`changes-since`) between consecutive snapshots to update the match set for each later one - re-checking only the files that actually changed instead of re-crawling every snapshot. Each changed path is re-evaluated with the same walk and filter a full crawl uses (a created directory's whole subtree is walked; a deleted directory drops itself and every match beneath it), so the results are **identical** to crawling every snapshot, with far fewer API calls when snapshots are mostly alike - the common case for dense periodic snapshots. Validated at scale: a 5-snapshot search of a 1.1M-file directory ran in 165s vs 476s for the full-crawl search (2.9x), with output identical on every attribute. Requires `--path`; not supported with `--max-depth`. Consecutive diffs make this both fast and complete (no sampling, so nothing transient is missed). One caveat: `changes-since` does not report an entry whose only change between snapshots is its **access time**, so an `access_time` shown for an otherwise-unchanged entry may come from an earlier snapshot; access-time filters (`--accessed`/`--time-field access_time` with `--older-than`/`--newer-than`, or `--accessed-older-than`/`--accessed-newer-than`) are therefore rejected with `--incremental`.
- **`--revert` (revert a directory to a snapshot)** - With `--snapshot`, revert the directory at `--path` to its EXACT state in that snapshot. grumpwalk takes a temporary snapshot of the live tree, runs the snapshot **tree diff** (`changes-since`) against the chosen snapshot, and acts only on what changed: recreates files and directories deleted since (repopulating a deleted directory from the snapshot subtree, since the diff reports only the directory node), restores modified files (whole-file, or byte-range with `--delta`), and **deletes files and directories created since the snapshot**. The result is byte-identical to the snapshot. Discovery is proportional to the number of changes, not the size of the tree, so reverting a large directory with few changes is fast. This is a whole-directory operation - content filters (`--name`/`--type`/`--owner`) do not apply. Because it deletes data added after the snapshot it is destructive: it requires `--yes`, and `--dry-run` previews the full plan including every deletion. Needs the snapshot-write privilege (for the temporary snapshot), which is deleted when the run ends. NET-diff semantics are exactly right here: a file created and deleted between the snapshot and now is absent from both and correctly left alone.
- **`--delta` (delta restore)** - With `--restore-in-place`, patch each modified file in place by copying ONLY the byte ranges that differ from the snapshot, instead of rewriting the whole file. Also accepted with `--revert` (above) to byte-range-patch the modified files it restores. grumpwalk takes a temporary snapshot of the live tree, diffs it against the chosen snapshot per file (`/v2/snapshots/{newer}/changes-since/{older}/files/{ref}`), then `copy-chunk`s just the changed regions (server-side) back over the live file; the temporary snapshot is deleted when the run ends. Size changes are handled - the file is truncated/extended to the snapshot size, and a file that shrank live has its lost tail copied back (the byte-range diff covers only the overlapping range, so the truncated tail is restored explicitly). Far less data moves for large files with localized changes: in testing a 1 GB file with an 8 MB edit restored about 5x faster than a whole-file copy (128x less data), and the gap widens with file size. Files deleted since the snapshot have no live version to diff, so they still restore whole-file. Because it patches files in place (no temp-file + atomic rename) it overwrites live data and requires `--yes`; it needs the snapshot-write privilege to create the temporary snapshot, and degrades gracefully to whole-file restore if the temporary snapshot cannot be created. Cannot be combined with `--rename-on-conflict`. The restore summary reports how many files were delta-patched.


## [3.3.0] - 2026-06-26

### Added

- **Snapshots: search, copy, and restore.** Qumulo provides no native snapshot-restore call, so grumpwalk lists snapshots and uses the read endpoints' `?snapshot=` parameter (to crawl/search a snapshot) together with `copy-chunk`'s `source_snapshot` field (to copy a file's snapshot version into a live target). All existing filters and output apply in snapshot context.
- **`--list-snapshots`** - List available snapshots (id, timestamp, name, resolved source path) and exit. Honors `--snapshots-newer-than`/`--snapshots-older-than`; with `--path`, lists only the snapshots whose source covers that path (the path itself or an ancestor).
- **`--snapshot ID`** - Run the crawl/search in the context of snapshot ID (every read uses `?snapshot=ID`). Finds files as they were at snapshot time, **including files deleted since**. Composes with every universal filter and with `--copy-to`/`--restore-in-place`.
- **`--all-snapshots`** - Search across ALL snapshots instead of one. Each match is annotated with its snapshot (a `snapshot` field in `--json`, a `[snap N]` prefix otherwise). Used in place of `--path`; if `--path` is given, only snapshots whose source covers that path are searched (reliable `source_file_id` containment, not a read-probe). Search-only.
- **`--snapshots-newer-than DURATION` / `--snapshots-older-than DURATION`** - With `--all-snapshots`/`--in-the-last-snapshots`/`--list-snapshots`, limit the snapshot set by each snapshot's own age (distinct from `--older-than`/`--newer-than`, which filter files). DURATION accepts days or hours: `5`/`5d` = 5 days, `12h` = 12 hours. Ages are computed in UTC against the snapshots' UTC timestamps.
- **`--in-the-last-snapshots N`** - Search the N most recent snapshots (by UTC timestamp) and show only the **newest** matching result for each path, deduplicating the same file across snapshots. Composes with all filters and the snapshot-age limits. Search-only.
- **`--snapshot ID --copy-to DEST`** - Copy the snapshot version of matched files (incl. deleted ones) into a live destination. Reuses the full copy feature (`--rename-to`, `--preserve-permissions`/`--preserve-all` reading the snapshot's metadata, `--include-directories`, `--create-destination-directory`).
- **`--snapshot ID --restore-in-place`** - Restore matched files to their ORIGINAL live paths (undelete / roll back): recreate files and parent directories deleted since the snapshot, and with `--clobber` overwrite the current live version. Destructive: requires confirmation / `--yes`; `--dry-run` previews the plan.
  - **Directory restore** - With `--include-directories` (or `--type directory`), a matched directory is restored as a complete subtree: the directory and every descendant - including files that did not match the filter and **empty subdirectories** - are recreated at their original paths. Restoring into a directory that still exists live merges (existing files honor the skip/`--clobber`/`--rename-on-conflict` strategy; the directory itself is left in place). Without these flags, matched directories are skipped and only files are restored (their containing directories are recreated as needed) - the prior behavior, unchanged.
- **`--rename-on-conflict`** - Third conflict strategy alongside the default (skip) and `--clobber` (overwrite): on a name conflict, write the item under a `_restored_<local-date>_<HH-MM-SS>` suffix (stamped once per run; customizable via `--conflict-suffix` with `{date}`/`{time}`/`{datetime}`/`{snapshot}`). Mutually exclusive with `--clobber`.
- **`--show-details`** - Show the attributes of matched results instead of just their paths, for **snapshot search** (`--snapshot`/`--all-snapshots`/`--in-the-last-snapshots`) and the live filtered walk. Defaults to `path`, human-readable `size`, and `change_time` (ctime). Renders an aligned table to stdout, or honors `--csv-out` / `--json-out` / `--json` (in those machine formats `size` stays raw bytes). In multi-snapshot search each row carries the source snapshot (a `SNAPSHOT` column / `snapshot` field). `--limit` caps the rows shown.
  - **`--fields` chooses the columns**, and the new value **`--fields all`** selects every attribute (and implies `--show-details`). `--fields all` supersedes `--all-attributes` for snapshot search, where `--all-attributes` previously had no effect. Resolved-name fields (`owner_name`/`group_name`) trigger identity resolution. In the live walk, bare `--fields` keeps its existing streaming projection for backward compatibility; pair it with `--show-details` for the aligned table.
  - **Directory aggregate capacity.** With `--type directory --show-details`, the default columns show the directory's recursive aggregate **`capacity`** (data + metadata of the whole subtree, from the directory-aggregates API) instead of the uninformative inode `size`. Exposed as the `total_capacity` field (alias `capacity`); `--fields all` includes it for directory searches. Costs one aggregates call per matched directory.
- **`--path` can point at a single file** - Give `--path` a file or symlink (not just a directory) to search, restore, copy, or show details for that one object - e.g. `--path /Shared/dir/report.docx --snapshot 5 --restore-in-place`. Previously a file path matched nothing.
- **`--skip-unchanged`** - Incremental copy. With `--copy-to`, skip files already present at the destination with the same size and modification time, and copy only new or changed files. Re-run it on a schedule to keep a destination in sync with a changing source. Implies `--preserve-all`.
- **Live progress for copy and restore** - `--progress` now shows a status line during `--copy-to` and snapshot restores: files done, data copied, transfer rate, and ETA - including progress through a single large file.


## [3.2.0] - 2026-06-24

### Added

- **`--move-to DEST`** - Move every object matching the filters into the existing directory DEST, like POSIX `mv` (matches are flattened into DEST). A Qumulo move is a single RENAME metadata operation, so it is fast and works across directories on the same cluster. On a name collision the object is skipped with a warning unless `--clobber` is given. Composes with all universal filters.
- **`--copy-to DEST`** - Server-side copy every object matching the filters into the existing directory DEST, like POSIX `cp` (flattened). Files are copied with the Qumulo `copy-chunk` API (data is copied on the cluster, not streamed through grumpwalk), looping for files larger than the server's per-call limit. Each file is copied into a temp name and atomically renamed into place, so an interrupted copy never leaves a partial or truncated destination. On a name collision the file is skipped unless `--clobber` is given. Mutually exclusive with `--move-to`. Composes with `--rename-to`, `--preserve-permissions`/`--preserve-all`, `--include-directories`, and all universal filters.
- **`--preserve-permissions`** - With `--copy-to`, also copy each source's owner, group, and ACL/mode to the copy. Without it, a copy contains only the data (owner becomes the API user and permissions are inherited from the destination directory, like plain `cp`).
- **`--preserve-all`** - With `--copy-to`, preserve every settable attribute: owner, group, ACL/mode, DOS extended attributes (`read_only`, `hidden`, `system`, `archive`, etc.), GENERIC user-metadata tags, and timestamps (`modification_time`, `access_time`, `creation_time`). For directories the timestamps are applied after the subtree is copied so they are not re-bumped by populating the directory. `change_time` (ctime) always reflects the copy and cannot be preserved.
- **`--create-destination-directory`** - With `--copy-to` or `--move-to`, create the destination directory (and any missing parents, like `mkdir -p`) when it does not exist. You are prompted to either inherit permissions from the parent directory or set a specific POSIX mode for the new directories. Companion flags `--destination-directory-mode MODE` (octal, e.g. `0755`) chooses the POSIX mode non-interactively (non-interactive runs without it inherit from the parent), and `--destination-directory-owner OWNER` (name, `uid:N`, SID, or `DOMAIN\user`) sets the owner of the new directories. These two flags apply only to directories grumpwalk actually creates; if the destination already exists they are ignored with a warning and the existing directory's owner and permissions are left unchanged. Without these flags a missing destination is still an error.
- **`--rename-to PATTERN`** - Rename matching objects. `{old|new}` substitutes within the name and leaves the rest untouched (regex and `*`/`?` wildcards supported, e.g. `{my|our}`, `{IMG_*|photo_*}`, `{(\d+)|v\1}`); a pattern without braces is a whole-name template whose `*`/`?` are filled from the matching `--name` glob (e.g. `--name 'my_*' --rename-to 'our_*'`). Use it alone to rename in place, or together with `--move-to`/`--copy-to`.
- **`--clobber`** - Overwrite an existing destination entry during a move/copy/rename (default: skip with a warning). Two matched sources that map to the same target are always skipped, even with `--clobber`. For `--copy-to`, an existing target *directory* is skipped (no merge in this release).
- **`--include-directories`** - Also move/copy matched directories (the whole subtree). For `--copy-to`, a matched directory is recreated under the destination and its files, subdirectories, and symlinks are copied recursively. Objects that would travel inside a moved/copied directory are pruned so they are not transferred twice, and transferring a directory into its own subtree is refused. Default: only files and symlinks are moved/copied.
- **`--move-concurrency N` / `--copy-concurrency N`** - Number of concurrent move / copy operations.
- **`--yes`** - Skip the confirmation prompt before a move/copy/rename. Required when running non-interactively (grumpwalk refuses otherwise). `--dry-run` prints the full `source -> target` plan and makes no changes.
- **`--update-atime`** - Allow access times (atime) to be updated by grumpwalk's reads. By default, on clusters that support it (Qumulo Core 7.9.0+), grumpwalk automatically suppresses atime updates so that crawling does not disturb access-time metadata. This flag restores the cluster's normal atime behavior.

### Changed

- **atime is no longer updated by crawls on Qumulo Core 7.9.0+** - grumpwalk now sends the `skip-atime-update=true` query parameter on every read that would otherwise bump access time: directory enumeration (`entries/`), symlink target reads, and file-content sampling (`data`). The cluster version is detected once at startup via `GET /v1/version`; on older clusters that do not support the parameter, behavior is unchanged. Pass `--update-atime` to opt back into atime updates. If `--update-atime` is given against a cluster that does not support the option, a single warning is emitted and the cluster's default atime behavior applies.

### Fixed

- **`--name` glob patterns are now anchored to the whole name** - A glob such as `--name 'file_*'` matched any name *containing* `file_` (e.g. `myfile_1`, `profile_data`) because the glob-to-regex conversion anchored only the end of the name and matching used `re.search`. Globs now match the entire name, matching standard shell-glob semantics: `file_*` matches names that begin with `file_`, `*.log` matches names that end in `.log`, and a wildcard-free `--name report` matches only the exact name `report` (use `--name '*report*'` for "contains"). User-written regex patterns are unchanged and remain unanchored (substring) unless you anchor them with `^`/`$`. `--omit-subdirs` already used full-glob matching and is unaffected.

---

## [3.1.0] - 2026-06-15

### Added

- **`--add-tag`** - Add a custom key/value tag (Qumulo `GENERIC` user metadata) to every object at or under `--path` that matches the active filters. Requires `--key` and `--value`. Composes with all universal filters; use `--max-depth 0` to tag only the target object. A key already set to the same value is a no-op; a key already set to a different value is skipped with a warning unless `--overwrite` is given.
- **`--find-tag`** - Find objects whose tags match `--key` and/or `--value` (or any tagged object if neither is given) and stream them to stdout as NDJSON. `--limit` stops after N matches.
- **`--remove-tag`** - Remove the tag `--key` from matching objects. With `--value`, removes the key only when its current value matches, guarding against deleting an unexpected value.
- **`--overwrite`** - Used with `--add-tag` to replace an existing value when the key is already present with a different value.
- **`--tag-concurrency N`** - Number of concurrent tag operations during a walk.

All three tagging modes honor `--progress`, `--dry-run`, `--limit`, and `--continue-on-error`. As with the other action flags, `--dry-run` previews each object and a real run lists each object with `--verbose`.

---

## [3.0.0.1] - 2026-05-28

## Changed

- **Removed qumulo_api dependency from requirements.txt** - The `qumulo_api` library is not directly used by `grumpwalk` and is only used as an alternative method of getting API credentials.
- **Updated Documentation** - Updated docs with the correct method of using long-lived API keys as the preferred authentication method

## [3.0.0] - 2026-05-28

### Added

- **`--disable-inheritance`** - Disable ACL inheritance at `--path`, converting inherited ACEs to explicit entries. Equivalent to Windows "Disable Inheritance" > "Convert inherited permissions" or `icacls /inheritance:d`. Sets the PROTECTED control flag to block future inheritance from parent directories. Supports `--propagate` for recursive application, `--dry-run` for preview, and all standard filters.
- **`--remove-inherited`** - When used with `--disable-inheritance`, removes all inherited ACEs entirely instead of converting them to explicit. Equivalent to `icacls /inheritance:r`. Warns when all ACEs on an object are inherited (removal would leave no access control).

### Fixed

- **v2 API trustee format in `--propagate-changes`** - ACE manipulation with `--propagate-changes` would fail with HTTP 400 ("expected object") when writing modified ACLs to children. The v2 API requires trustees as objects (`{"auth_id": "..."}`) but newly added ACEs used bare auth_id strings. `normalize_acl_for_put()` now converts string trustees to object format before PUT.

---

## [2.9.1] - 2026-05-07

### Fixed

- **`--set-mode` now respects `--type` filter on the target path** - Previously, `--set-mode` with `--type file` would still modify the target directory itself before walking its children. The target path is now checked against the filter and skipped if it doesn't match.

---

## [2.9.0] - 2026-05-07

### Added

- **`--set-mode MODE`** - Set POSIX permissions using chmod-style octal mode (e.g., `755`, `2770`, `0644`). Replaces the ACL with POSIX-equivalent `OWNER@`, `GROUP@`, and `EVERYONE@` entries. Supports `--propagate` for recursive application. Setgid (`2xxx`) is applied to directories only.
- **`--new-owner IDENTITY`** - Set file owner when used with `--set-mode`. Accepts `uid:N`, username, `DOMAIN\user`, or SID. Replaces the `OWNER@` placeholder in the ACL with the specified identity and changes file ownership.
- **`--new-group IDENTITY`** - Set file group when used with `--set-mode`. Accepts `gid:N`, groupname, `DOMAIN\group`, or SID. Replaces the `GROUP@` placeholder in the ACL with the specified identity and changes file group ownership.
- **`--propagate`** - Short alias for `--propagate-acls`. Both flags are equivalent.

---

## [2.8.0] - 2026-05-06

### Changed

- **Bounded-memory tree walk** - Rewrote the directory tree walk to use constant memory regardless of filesystem size. Previously, crawling very large filesystems (100M+ directories) could exhaust available RAM and be killed by the OS. The new implementation keeps memory usage flat even on billion-file filesystems.
- **Improved output memory efficiency** - Streaming CSV and JSON output no longer tracks all previously seen paths in memory, eliminating a scaling bottleneck on very large result sets.

---

## [2.7.0] - 2026-04-22

### Fixed

- **Critical ACL bug: `--propagate-changes` with ACE manipulation no longer corrupts inheritance flags** - Previously, `--remove-ace` (and other ACE operations) combined with `--propagate-changes` would stamp the parent's modified ACL onto all children using `mark_inherited=True`, causing non-inherited/non-inheritable permissions to become inherited across the entire tree. For example, an explicit "Everyone Read/Execute" on the parent folder would suddenly propagate as an inherited permission to all children -- a security-impacting permission escalation. The fix replaces the old "stamp parent ACL" approach with per-file modification: each child's ACL is individually fetched, modified with the same patterns, and written back with its original inheritance flags preserved. Children without matching ACEs are detected and skipped (no unnecessary writes).

### Changed

- ACE manipulation with `--propagate-changes` now shows "Objects unchanged" count in addition to changed/failed/skipped, providing visibility into how many children did not have the targeted ACE
- Progress label changed from "ACL CLONE" to "ACE MODIFY" during recursive ACE modification to better distinguish from full ACL cloning operations

---

## [2.6.2] - 2026-04-10

### Performance

- **Smart skip for `--type directory` walks** - When walking a tree with `--type directory` (e.g. `--acl-report --type directory`), grumpwalk now skips enumeration of directories whose entire subtree contains no further subdirectories. Mirrors the existing `--type file` optimization.
- **Smart skip in `--stats` mode** - `collect_stats` now short-circuits enumeration when a directory's recursive subdirectory count is 0, avoiding paging through millions of file entries to find no subdirs.
- **Smart skip and memory safety in `--show-dir-stats` mode** - Same optimization applied; `--show-dir-stats` also now uses streaming enumeration instead of loading all directory entries into memory.

---

## [2.6.1] - 2026-04-09

### Added

- `--sort {size,count,name}` flag for `--stats` table output
  - `size` - sort by total size, largest first
  - `count` - sort by file count, most first
  - `name` - sort by path, alphabetical

---

## [2.6.0] - 2026-04-09

### Added

- **Directory statistics mode** - `--stats` flag to display directory aggregate statistics and exit without performing a tree walk
  - Shows files, subdirectories, and total size in a formatted table
  - Supports `--max-depth` for recursive subdirectory breakdown
  - Respects `--omit-subdirs` and `--omit-path` during recursion
  - Output options: `--json` (stdout), `--json-out FILE`, `--csv-out FILE`
  - Memory-safe: uses streaming enumeration to find subdirectories without loading all entries
  - Conflict validation prevents combining `--stats` with other operational modes
- **Universal scope display** - All modes with `--path` now show "Searching N directories and N files" immediately after connection verification, before any operation begins

### Documentation

- **User Guide** - Added "Directory Statistics" section with recipes for `--stats`, `--max-depth`, omit patterns, and export options
- **README** - Added `--stats` to Features list, Directory Options reference, and Quick Examples

---

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
