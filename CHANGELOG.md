# Changelog

All notable changes to grumpwalk will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.9.3] - 2026-08-25

### Changed

- **grumpwalk now verifies the cluster's TLS certificate.** Every request carries your bearer token, and until now every one of them went over a connection nobody had authenticated: certificate and hostname checking were switched off with no way to turn them back on. Anything able to sit on the route between you and the cluster could read the token and everything the crawl returned.

  Verification is now on by default. **If your cluster presents a self-signed certificate, or one signed by an internal CA, runs that used to work will now stop** with an explanation and three ways forward:

  ```
  Verifying cluster connection... FAILED
  [ERROR] TLS certificate verification failed for cluster.example.com:8000
  [HINT] [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate
  [HINT] If the cluster uses an internally signed or self-signed certificate, trust its CA
         with --ca-bundle /path/to/ca.pem
  [HINT] To connect without verifying, use --verify-tls no (or set GRUMPWALK_VERIFY_TLS=no).
         The bearer token is then sent over a connection nothing has authenticated.
  ```

### Added

- **`--ca-bundle PATH`** - Verify against a PEM bundle of your own CA certificates instead of the machine's trust store. This is the option to reach for with an internal CA: you keep verification rather than giving it up.
- **`--verify-tls yes|no`** - Turn verification off for a single run.
- **`GRUMPWALK_VERIFY_TLS=no`** - Turn it off for every run, so a site whose clusters all present self-signed certificates can set it once instead of appending a flag to every command. The flag beats the environment variable, and `--ca-bundle` implies verification. A value that is neither yes nor no is an error rather than a silent fallback, because guessing either way would be wrong for a setting that decides whether a credential crosses an authenticated connection.

### Fixed

- **A local `import os.path` inside the main routine shadowed the module-level `os`** for the whole function, so any use of `os` earlier in it failed with "cannot access local variable 'os'". Nothing hit it before now because nothing used `os` earlier in that function.

## [3.9.2] - 2026-08-15

### Changed

- **The line printed before a search now counts symlinks, and gives an object total.** It previously listed only directories and files, which read as a smaller job than the one that followed, because symlinks are walked too. A search that reports `21,002 directories, 460,569 files and 35,896 symlinks (517,467 objects total)` now ends on exactly 517,467 objects processed, so the figure you see at the start is the one `--progress` counts towards. Other object types are included in the total and listed when there are any.

### Fixed

- **`--progress` counted most objects twice.** The running "objects processed" figure could climb well past the number of objects that exist in the path -- a search of a directory holding 10.6 million objects reported over 18 million -- and the objects/sec rate was inflated by the same amount. Anything a directory contained was counted once as it was read and again when the directory finished, for every directory below 50,000 entries. Results were never affected: totals, matches and output were always correct, and only the progress display was wrong. `--limit` was affected, though, and could stop at roughly half the number of results asked for.

## [3.9.1] - 2026-08-14

### Fixed

- **A new install used the wrong settings on its very first run.** grumpwalk works out the right settings for your machine the first time it runs, saves them, and prints them on screen -- but that first crawl went ahead with a built-in value of 100 simultaneous directory reads instead, four to five times what it had just chosen, and only used the saved settings from the second run onwards. The first run after upgrading behaved the same way. Runs now use the settings they display.

## [3.9.0] - 2026-08-13

### Added

- **`--size-totals-only`** - Answers "how much space does this add up to?" without printing the files. It applies the same filters you would use for a listing and reports the number of matching objects and the capacity they occupy on disk:

  ```
  ./grumpwalk.py --host cluster --path /data --created-newer-than 200 --type file --size-totals-only

  ======================================================================
  Total matching objects:  1,284,552
  Total capacity used:     4.21 TiB
  ======================================================================
  ```

  Capacity is the space actually allocated, so sparse files count as what they really use, and the figure matches the total from `--per-directory-matches` for the same filters. Memory stays flat however many objects match. Add `--json`, `--json-out` or `--csv-out` for a single machine-readable row of raw bytes.

### Fixed

- **Large crawls use much less memory and finish faster.** grumpwalk read each directory into memory in full before doing anything with it, and every concurrent request held one at the same time, so memory grew with how many directories were being read at once rather than with anything you asked for - enough to run out of memory on a big filesystem. Directories are now handled as their contents arrive. Measured against a tree of 71 million files in 33 million directories, reaching two million objects went from about 2.2 GB down to about 0.5 GB, and took roughly half the time. This applies to every operation that walks a tree, not just reports.
- **`--per-directory-matches` no longer keeps track of directories it will never report.** The report lists the immediate children of `--path`, but every directory below them was being tallied too. On a filesystem with millions of directories that is millions of running totals kept in order to print a handful of lines. `--subdir-report` still tracks every subdirectory, because that is what it reports.
- **`--sort size` and `--sort count` now list tied directories in the same order every time.** Directories with matching sizes or counts came out in whatever order the walk happened to finish them, so the same report run twice could not be compared. Ties are now broken by path.

### Changed

- **Default settings now use far fewer simultaneous directory reads, and your existing settings have been reset.** grumpwalk used to work up to 200-500 at once. Testing across a 71-million-file system found that nothing above about 25 ran any faster - on a fast local link or a slow VPN alike - while each extra one added memory. The default is now 25, which uses roughly 200 MB instead of several gigabytes.

  The first run after upgrading replaces your tuning profile. Your old settings are written to `tuning-profile.previous` and printed on screen, so nothing is lost: pass them on the command line if you want them back for a particular job.

- **`--benchmark` now reports what each setting costs in memory, and only recommends a higher one when it is clearly worth it.** It previously reported speed alone and suggested whichever number came out fastest, even when the difference was noise. Repeating the same test on the same filesystem produced results three times apart for the same setting, because a walk speeds up and slows down depending on where it has reached. Each test now runs for a fixed time after a warm-up, shows memory alongside speed, and says plainly when a directory was too small to measure anything useful.

## [3.8.2] - 2026-08-10

### Fixed

- **Granting access by UID or GID number now works on any cluster.** On clusters that do not recognize a bare POSIX number, `--add-ace 'Allow:fd:gid:14052:rwxda' --propagate` looked like it had worked but applied nothing at all - not to the directory, not to anything under it. If a user or group genuinely cannot be found, the error now also tells you that nothing was changed.
- **`--add-ace` now applies the `f` and `d` inheritance flags when the trustee is already in the ACL.** Only the rights were added before, so the group ended up with access but new files and folders created underneath did not inherit it. This came up often, because `--set-mode --new-group` puts the group in the ACL to begin with.
- **`--set-mode --propagate` no longer marks child permissions as inherited.** Everything underneath came out flagged as inherited while the directory itself did not, including entries that had nothing to do with the change. Windows greys out inherited entries so they cannot be edited there, and turning inheritance off would have removed them altogether. Children are now written the same way as the directory you name.
- **Re-running the same `--add-ace` leaves matching objects alone** instead of rewriting every object in the tree, so a second pass over a large directory finishes quickly.

### Notes

- A bare number is still read as a **UID**, so keep the `uid:` or `gid:` prefix.
- Trees already changed by 3.8.1's `--set-mode --propagate` still carry the inherited flag. Re-running `--set-mode` with this version clears it.

## [3.8.1] - 2026-08-10

### Fixed

- **ACE commands now accept `uid:N`, `gid:N`, `auth_id:N` and SID trustees.** These were listed as valid trustee formats but none of them worked: `--add-ace 'Allow:fd:gid:14011:rwxda'` stopped with `Invalid add pattern: expected Type:Flags:Trustee:Rights` and never reached the cluster, because the colon inside `gid:14011` was read as a field separator. Granting a group or a user by number now works as documented, in `--add-ace`, `--remove-ace`, `--replace-ace`, `--new-ace`, `--add-rights` and `--remove-rights`. Mistyped patterns are still caught the same way as before, so `'Allow:fd:Group:Modify:oops'` and `'Allow:fd:gid:abc:rw'` are still rejected.
- **A SID can be pasted back in the form grumpwalk prints it.** ACL reports show SID trustees as `sid:S-1-5-...`, but using that in a command looked it up as a user name and failed to resolve. Both `sid:S-1-5-...` and a bare `S-1-5-...` now work.
- **`--dry-run` shows a new ACE's trustee the way you typed it.** Previewing a new ACE for `gid:14011` used to read `Allow:fd:auth_id:gid:14011:rwaxd`, and one for a named group read `auth_id:Group111`.

### Notes

- A UID or GID does not have to exist in Active Directory. Qumulo recognizes any NFS UID or GID on its own, so `uid:N` and `gid:N` work on a cluster with no AD, and for numbers never linked to an AD account.
- A bare number is still read as a **UID**, so `--add-ace 'Allow:fd:14011:rwxda'` grants access to user 14011, not group 14011. Always write the `uid:` or `gid:` prefix.
- `ad:name` and `local:name` are not accepted as ACE trustees. Use the plain name, `DOMAIN\name`, or the user's UID/GID/SID instead.

## [3.8.0] - 2026-08-06

### Added

- **`--base10` (decimal display units)** - Every human-readable size grumpwalk prints is now binary by default (KiB/MiB/GiB/TiB), matching how Qumulo allocates space in 4 KiB blocks. Pass `--base10` to see decimal units instead (KB/MB/GB/TB, powers of 1000), which is what drive vendors and cloud billing use. The flag changes display only: `--csv-out`, `--json-out` and `--json` still emit raw byte integers, and size filters always follow the unit you type - `--larger-than 1TB` is 10^12 bytes and `--larger-than 1TiB` is 2^40 bytes in either mode.

### Fixed

- **Reports no longer label binary sizes as decimal.** `--owner-report`, `--show-dir-stats`, `--per-directory-matches` and the snapshot listings divided by 1024 but printed `KB`/`MB`/`GB`/`TB`, so a reported `1.00 TB` was really 1 TiB - about 10% larger than the label claimed. Worse, `parse_size_to_bytes` reads `TB` correctly as 10^12, so `--larger-than 1TB` would match a 1,050,000,000,000-byte file and the owner report would then render it as `977.89 GB` - under the threshold you just asked for. Sizes are now labeled with the units they are actually computed in, and match `--show-details`, which was already correct.

### Notes

- This changes the text of existing reports: sizes that read `GB`/`TB` now read `GiB`/`TiB`. The numbers are unchanged - only the labels were wrong. Anything scraping units out of report text needs updating; `--csv-out` / `--json-out` were always raw bytes and are unaffected.
- The `--find-similar` scan summary moves the other way: its sizes were genuinely decimal and are now binary like everything else. Pass `--base10` to get its previous output.
- System memory in auto-tuning / `--benchmark` output is still reported as `GB` and is unaffected by `--base10`; it describes the client machine's RAM, not cluster capacity.

## [3.7.0] - 2026-07-22

### Added

- **`--not-name` (exclude by name)** - The inverse of `--name`: drops anything whose name matches. Repeatable, and an object is excluded if it matches any of the patterns. This is how you answer "everything except X" - for example "skip files starting with '.'": `--older-than 90 --glob --not-name '.*'`. Works with every other filter and in every mode. Like `--name`, it tests each object's own name rather than its full path, and it applies to directories as well as files unless you add `--type`. So `--not-name '.*'` drops the `.git` directory itself from the results, but the ordinary-named files stored inside it are still reported - add `--omit-subdirs` to skip a directory's contents too.
- **`--regex` and `--glob`** - Name patterns can be written as shell globs or as regular expressions, and grumpwalk works out which you meant. A few patterns are valid as both and mean different things, so these flags let you say which you want: `--glob --not-name '.*'` excludes hidden files, `--regex --not-name '^\.'` does the same thing the other way. Both apply to `--name`, `--name-and`, `--not-name` and `--omit-subdirs`, and `--regex` lets `--omit-subdirs` take regular expressions for the first time. Existing commands are unaffected.
- **Warning on ambiguous patterns** - When a pattern could be read either way and the two readings disagree, grumpwalk now says which one it used and points at `--regex` / `--glob`. This catches patterns that quietly did the opposite of what they looked like: `--not-name '.*'` matches every name as a regular expression, though it looks like "starts with a period", and `--name 'report.txt'` also matches `myreport.txt.bak`. Passing `--regex` or `--glob` silences it.

### Fixed

- **`--show-dir-stats` now honors `--omit-subdirs` and `--omit-path`.** Both were accepted and then ignored, so the report always covered every subdirectory. They now skip directories at every depth, matching `--stats` and a normal crawl.
- **An omitted directory is no longer listed in the results.** `--omit-subdirs` and `--omit-path` correctly skipped a directory's contents, but the directory itself still appeared in the normal streamed output - while `--show-details` left it out. The same command therefore gave a slightly different answer depending on the output format. Omitted directories are now absent from every output mode.
- **Corrected documented examples that did not do what they said.** Some example patterns are valid as both a glob and a regular expression, and were being read as regular expressions - `--name 'test_*.py'` did not match `test_foo.py` at all, and `--name 'file?.txt'` matched nothing. The examples now pass `--glob`, and the new warning flags this class of pattern when you hit it yourself.

### Notes

- `--omit-subdirs` is still read as a glob unless you pass `--regex`, so `--omit-subdirs '.snapshot'` and `--omit-subdirs '.*'` keep working as they always have.
- `--rename-to` templates using `*`/`?` fill those wildcards from the `--name` glob they matched, so they cannot be combined with `--regex`. That combination now reports an error pointing at the `{old|new}` form, which works either way.

## [3.6.0] - 2026-07-13

### Added

- **`--per-directory-matches` (per-directory match report)** - Reports, one row per directory, the number of files matching your filters and the disk capacity they use. Unlike `--stats` - which reads the cluster's whole-subtree aggregate totals and therefore ignores per-file filters - this walks the tree and applies every universal filter (time, size, name, type, owner) and `--max-depth`, so it answers questions like "how much data was modified in the last 30 days, per directory" or "which directories hold the most stale data." Each directory total is a rollup of everything beneath it; the default output lists the immediate subdirectories of `--path` plus a grand total. The capacity column is actual space used on disk (allocated blocks), so sparse files and small-file overhead are counted correctly. Sort with `--sort size|count|name`, and export with `--csv-out` / `--json-out` / `--json` (which add a `depth` column and a `depth=0` grand-total row).
- **`--subdir-report`** - With `--per-directory-matches`, expands the report from the immediate children of `--path` to every subdirectory that contains matches. Respects `--max-depth`.

### Fixed

- **Per-file filters combined with `--stats` no longer look like they worked.** `--stats` reads whole-subtree aggregate counts from the cluster and cannot apply per-file filters, so a command like `--stats --modified-newer-than 30` returned the totals for every file, not the filtered subset - and `--modified-older-than` and `--modified-newer-than` returned identical results. For a filtered per-directory breakdown, use the new `--per-directory-matches`.

## [3.5.0] - 2026-07-09

### Fixed

- **Rate limiting no longer silently drops parts of the tree.** When a cluster, proxy, or network refused a directory read - a rate limit (HTTP 429), a brief server error, or a dropped connection - grumpwalk skipped that directory and everything beneath it, mentioned it only under `--verbose`, and still exited 0 reporting success. On a heavily throttled run this could silently lose most of the tree while producing a normal-looking output file. Now grumpwalk retries refused requests automatically with increasing wait times (honoring the server's `Retry-After`), so a rate-limited crawl runs slower but returns complete results. Verified against a billion-file cluster: a crawl that lost 96% of its directories under forced rate limiting now returns 100% with identical output.
- **A crawl that could not read everything now reports it.** If a directory still cannot be read after every retry, grumpwalk prints an `INCOMPLETE CRAWL` warning naming the skipped directories (always, not just under `--verbose`) and exits with **code 2**, so scheduled jobs and scripts can detect a partial result instead of trusting it. This covers every operation that walks the tree: exports, owner and ACL reports, ACL/ACE changes, tagging, move/copy, and snapshot search.

### Added

- **`--max-retries N`** - How many times a refused read is retried before the directory is reported as failed (default: 5; `0` disables retrying). Increase it for heavily loaded clusters or strict proxies; if rate limiting is frequent, lowering `--max-concurrent` addresses the cause.

## [3.4.1] - 2026-07-06

### Fixed

- **`--dry-run` now previews the whole tree for ACE changes, not just the top folder.** When previewing an ACE change with `--propagate-changes` (`--remove-ace`, `--add-ace`, `--replace-ace`, `--add-rights`, `--remove-rights`, `--clone-ace-*`, `--migrate-trustees`), `--dry-run` used to show only the change to the `--path` folder and then stop - which made it look as though that one folder's ACL would be copied down onto everything beneath it. A real run never behaved that way: it checks each object's own permissions and removes only the targeted ACE, leaving all other entries untouched, and it does not stop at a folder that happens to lack the entry. The preview simply did not show any of that. Now `--dry-run` searches the entire tree without changing anything and reports how many objects would change, how many would be left untouched, and which objects would be modified, so the preview matches exactly what a real run will do.

## [3.4.0] - 2026-06-29

### Added

- **`--incremental` (faster multi-snapshot search)** - Speeds up a multi-snapshot search (`--all-snapshots`, `--snapshots-newer-than`/`--snapshots-older-than`, `--in-the-last-snapshots`) by crawling only the oldest covered snapshot in full, then using the snapshot **tree diff** (`changes-since`) between consecutive snapshots to update the match set for each later one - re-checking only the files that changed instead of re-crawling every snapshot. Each changed path is re-evaluated with the same walk and filter, so results are **identical** to crawling every snapshot, with far fewer API calls when snapshots are mostly alike. Requires `--path`; not supported with `--max-depth`. One caveat: `changes-since` does not report an entry whose only change is its **access time**, so a shown `access_time` may come from an earlier snapshot, and access-time filters (`--accessed`, `--accessed-older-than`/`--accessed-newer-than`) are rejected with `--incremental`.
- **`--revert` (restore a directory to a snapshot)** - With `--snapshot`, restore the directory at `--path` to its state in that snapshot. grumpwalk takes a temporary snapshot of the live tree, runs the snapshot **tree diff** (`changes-since`) against the chosen snapshot, and acts only on what changed: recreates files and directories deleted since (repopulating a deleted directory from the snapshot subtree, since the diff reports only the directory node) and restores modified files (whole-file, or byte-range with `--delta`). Files and directories **created since the snapshot are kept by default** (non-destructive to new data); add **`--delete-new`** to also remove them, making the directory byte-identical to the snapshot (an exact rollback/mirror). Discovery is proportional to the number of changes, not the size of the tree, and the restore phase runs the per-file recreate/restore/delete operations concurrently (bounded by `--copy-concurrency`), so reverting a large directory with few changes is fast. This is a whole-directory operation - content filters (`--name`/`--type`/`--owner`) do not apply. It overwrites modified files (restoring the snapshot version), so it requires `--yes`, and `--dry-run` previews the full plan (every recreate, restore, and - with `--delete-new` - deletion). Needs the snapshot-write privilege (for the temporary snapshot), which is deleted when the run ends. NET-diff semantics are exactly right here: a file created and deleted between the snapshot and now is absent from both and correctly left alone.
- **`--delta` (delta restore)** - With `--restore-in-place` or `--revert`, patch each modified file in place by copying only the byte ranges that differ from the snapshot, instead of rewriting the whole file - far less data for large files with localized edits (a 1 GB file with an 8 MB edit restored ~5x faster in testing). Uses a temporary snapshot of the live tree for the per-file diff (needs the snapshot-write privilege; deleted when done). Handles size changes, and patches in place so file mode is preserved; files deleted since the snapshot still restore whole-file. Requires `--yes`; cannot be combined with `--rename-on-conflict`; degrades to whole-file restore if the temporary snapshot can't be created.
- **`--delta-threshold SIZE`** - Size gate for `--delta` (default **1 MiB**): files at or above SIZE use the byte-range diff; smaller files are copied whole in place, skipping the per-file diff that saves nothing when there is little data to move. Keeps `--delta` optimal on mixed trees; `0` byte-range-diffs every file.

### Fixed

- **Two-sided time windows (`--older-than` + `--newer-than`)** - The validation that guards combining the two time bounds was inverted: it required `--newer-than < --older-than`, which rejected the only meaningful window (`--older-than 7 --newer-than 30` = files 7-30 days old) while accepting the contradictory pairing that always returns nothing. It now correctly requires `--newer-than` greater than `--older-than`, and the same guard is applied to the field-specific pairs (`--accessed-older-than`/`--accessed-newer-than`, `--modified-*`, `--created-*`, `--changed-*`), which previously had no validation. Cross-field combinations (e.g. `--accessed-older-than 90 --modified-newer-than 7`) are unaffected. Each bound on its own was already correct.


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
