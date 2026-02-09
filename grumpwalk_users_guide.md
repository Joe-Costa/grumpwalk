# Grumpwalk Users Guide

**Version 2.0.0** | [Changelog](CHANGELOG.md) | [README](README.md)

A practical guide with recipes for common storage administration tasks using grumpwalk.

---

## Table of Contents

1. [Getting Started](#getting-started)
2. [Finding Files](#finding-files)
3. [Storage Capacity Planning](#storage-capacity-planning)
4. [Data Lifecycle Management](#data-lifecycle-management)
5. [User and Access Management](#user-and-access-management)
6. [Domain Migration](#domain-migration)
7. [Compliance and Auditing](#compliance-and-auditing)
8. [Security and Incident Response](#security-and-incident-response)
9. [Duplicate and Similar File Detection](#duplicate-and-similar-file-detection)
10. [Media and Creative Workflows](#media-and-creative-workflows)
11. [Reporting and Analytics](#reporting-and-analytics)
12. [Performance Optimization](#performance-optimization)
13. [Scripting and Automation](#scripting-and-automation)
14. [Combining Filters with Actions](#combining-filters-with-actions)

---

## Getting Started

### Prerequisites

1. **Authentication**: Generate a Qumulo bearer token:
   ```bash
   qq login -h your-cluster.example.com
   ```

2. **Dependencies**: Install required packages:
   ```bash
   pip install aiohttp

   # Optional for better performance:
   pip install ujson xxhash
   ```

### Basic Usage Pattern

```bash
./grumpwalk.py --host CLUSTER --path /starting/path [FILTERS] [OPTIONS]
```

### Your First Crawl

```bash
# Basic crawl with progress
./grumpwalk.py --host cluster.example.com --path /data --progress > inventory.ndjson

# Quick file count
./grumpwalk.py --host cluster.example.com --path /data --progress 2>&1 | tail -1
```

---

## Finding Files

### How do I find files by name?

**Find all log files:**
```bash
./grumpwalk.py --host cluster --path /var --name '*.log' --type file
```

**Find files matching multiple patterns (OR logic):**
```bash
./grumpwalk.py --host cluster --path /data --name '*.tmp' --name '*.bak' --name '*.old'
```

**Find files matching ALL patterns (AND logic):**
```bash
./grumpwalk.py --host cluster --path /backups --name-and '*backup*' --name-and '*2024*'
```

**Case-sensitive search:**
```bash
./grumpwalk.py --host cluster --path /docs --name 'README' --name-case-sensitive
```

**Find using regex:**
```bash
# Find files starting with numbers
./grumpwalk.py --host cluster --path /data --name '^[0-9].*'

# Find files with version numbers (v1, v2, etc.)
./grumpwalk.py --host cluster --path /releases --name '.*_v[0-9]+\.'
```

### How do I find files by size?

**Find large files (over 1GB):**
```bash
./grumpwalk.py --host cluster --path /data --larger-than 1GB --type file --progress
```

**Find small files (under 1KB)**
```bash
./grumpwalk.py --host cluster --path /data --smaller-than 1KB --type file
```

**Find files in a size range:**
```bash
./grumpwalk.py --host cluster --path /media \
  --larger-than 100MB --smaller-than 1GB --type file
```


### How do I find files by age?

**Find files older than 90 days (by creation time):**
```bash
./grumpwalk.py --host cluster --path /data --older-than 90 --type file
```

**Find files modified in the last 7 days:**
```bash
./grumpwalk.py --host cluster --path /projects --modified --newer-than 7
```

**Find files not accessed in over a year:**
```bash
./grumpwalk.py --host cluster --path /archive --accessed --older-than 365
```

**Find files created recently but not modified (potential placeholders):**
```bash
./grumpwalk.py --host cluster --path /data \
  --created --newer-than 30 \
  --modified-older-than 30
```

### How do I find files by owner?

**Find all files owned by a specific user:**
```bash
./grumpwalk.py --host cluster --path /home --owner jsmith --progress
```

**Find files owned by a UID:**
```bash
./grumpwalk.py --host cluster --path /nfs-data --owner 1001 --uid
```

**Find files owned by an AD user:**
```bash
./grumpwalk.py --host cluster --path /shared --owner "jsmith" --ad
```

****Find files owned by an AD user (Alternate method):**

```bash
./grumpwalk.py --host cluster --path /shared --owner "AD\jsmith"
```

**Find files owned by multiple users (OR logic):**
```bash
./grumpwalk.py --host cluster --path /projects \
  --owner alice --owner bob --owner charlie
```

### How do I find specific file types?

**Find only directories:**
```bash
./grumpwalk.py --host cluster --path /data --type directory
```

**Find only symlinks:**
```bash
./grumpwalk.py --host cluster --path /opt --type symlink --resolve-links
```

**Find empty directories:**
```bash
./grumpwalk.py --host cluster --path /data --type directory \
  --json --all-attributes --progress | \
  jq 'select(.child_count == 0)'
```

### How do I search within specific directories?

**Limit search depth:**
```bash
./grumpwalk.py --host cluster --path /home --max-depth 2 --type file
```

**Skip certain directories:**
```bash
./grumpwalk.py --host cluster --path /data \
  --omit-subdirs '.snapshot' \
  --omit-subdirs 'node_modules' \
  --omit-subdirs '.git'
```

**Skip specific paths:**
```bash
./grumpwalk.py --host cluster --path / \
  --omit-path /var/log \
  --omit-path /tmp \
  --omit-path /proc
```

---

## Storage Capacity Planning

### How do I generate a storage report by owner?

```bash
./grumpwalk.py --host cluster --path /home --owner-report --progress
```

**Sample output:**
```
================================================================================
OWNER REPORT
================================================================================
Owner                          Domain               Files       Dirs      Total Size
------------------------------------------------------------------------------------------
alice@corp.com                 AD_USER              125,432    2,341     1.23 TB
bob@corp.com                   AD_USER               98,234    1,892     987.45 GB
UID 1001                       POSIX_USER            45,123      234     456.78 GB
------------------------------------------------------------------------------------------
TOTAL                                               268,789    4,467     2.67 TB
```

### How do I find who is using the most storage?

```bash
# Top 10 storage consumers
./grumpwalk.py --host cluster --path /shared --owner-report --progress 2>&1 | \
  grep -A 20 "OWNER REPORT"
```

### How do I identify cold data for tiering?

**Find data not accessed in 90+ days:**
```bash
./grumpwalk.py --host cluster --path /data \
  --accessed --older-than 90 \
  --type file --progress \
  --json-out cold_data_90days.json
```

**Summarize cold data by directory:**
```bash
./grumpwalk.py --host cluster --path /projects \
  --accessed --older-than 180 \
  --json --all-attributes \
  --type file | \
  jq -r '.path | split("/")[1:4] | join("/")' | sort | uniq -c | sort -rn | head -20
```

**Find large cold files (candidates for archival):**
```bash
./grumpwalk.py --host cluster --path /data \
  --accessed --older-than 365 \
  --larger-than 100MB \
  --type file --progress
```

### How do I estimate storage growth?

**Compare file counts by creation date:**
```bash
# Files created in the last 30 days
./grumpwalk.py --host cluster --path /data --created --newer-than 30 --type file | wc -l

# Files created 30-60 days ago
./grumpwalk.py --host cluster --path /data \
  --created --newer-than 60 --created-older-than 30 --type file | wc -l
```

**Analyze recent growth by owner:**
```bash
./grumpwalk.py --host cluster --path /home \
  --created --newer-than 30 \
  --owner-report --progress
```

### How do I find directories consuming the most space?

```bash
./grumpwalk.py --host cluster --path /data \
  --show-dir-stats --max-depth 2 --progress
```

---

## Data Lifecycle Management

### How do I find stale data for cleanup?

**Find files untouched for 2+ years:**
```bash
./grumpwalk.py --host cluster --path /archive \
  --accessed --older-than 730 \
  --modified --older-than 730 \
  --type file --progress \
  --csv-out stale_files.csv
```

**Find old temporary files:**
```bash
./grumpwalk.py --host cluster --path /data \
  --name '*.tmp' --name '*.temp' --name '*.bak' --name '~*' \
  --older-than 30 \
  --type file
```

### How do I implement a retention policy?

**Find files exceeding 7-year retention:**
```bash
./grumpwalk.py --host cluster --path /legal/documents \
  --created --older-than 2555 \
  --type file --progress \
  --json-out retention_exceeded.json
```

**Generate deletion candidate list by category:**
```bash
# Log files older than 90 days
./grumpwalk.py --host cluster --path /var/log \
  --name '*.log' --name '*.log.*' \
  --older-than 90 --type file \
  --csv-out logs_to_delete.csv

# Core dumps older than 30 days
./grumpwalk.py --host cluster --path /var \
  --name 'core.*' --name '*.core' \
  --older-than 30 --type file \
  --csv-out cores_to_delete.csv
```

### How do I find files that should be compressed?

```bash
# Large text/log files that could benefit from compression
./grumpwalk.py --host cluster --path /logs \
  --name '*.log' --name '*.txt' --name '*.csv' --name '*.json' \
  --larger-than 100MB \
  --type file
```

---

## User and Access Management

### How do I audit permissions for a user?

**Generate ACL report showing user's access:**
```bash
./grumpwalk.py --host cluster --path /shared \
  --acl-report --acl-resolve-names --progress
```

**Find all files a user owns:**
```bash
./grumpwalk.py --host cluster --path / \
  --owner "DOMAIN\\jsmith" --ad \
  --expand-identity \
  --progress \
  --json-out jsmith_files.json
```

### How do I handle employee offboarding?

**Step 1: Find all files owned by departing employee:**
```bash
./grumpwalk.py --host cluster --path /home/jsmith \
  --owner "DOMAIN\\jsmith" --ad \
  --type file --progress \
  --json-out departing_user_files.json
```

**Step 2: Clone their permissions to manager:**
```bash
./grumpwalk.py --host cluster --path /home/jsmith \
  --clone-ace-source "DOMAIN\\jsmith" \
  --clone-ace-target "DOMAIN\\manager" \
  --propagate-changes --progress
```

**Step 3: Remove departing user's ACEs:**
```bash
./grumpwalk.py --host cluster --path /home/jsmith \
  --remove-ace "Allow:DOMAIN\\jsmith" \
  --propagate-changes --progress
```

**Step 4: Transfer file ownership to manager:**
```bash
# Preview ownership changes first
./grumpwalk.py --host cluster --path /home/jsmith \
  --change-owner "DOMAIN\\jsmith:DOMAIN\\manager" \
  --propagate-changes --dry-run

# Execute the ownership transfer
./grumpwalk.py --host cluster --path /home/jsmith \
  --change-owner "DOMAIN\\jsmith:DOMAIN\\manager" \
  --propagate-changes --progress
```

### How do I transfer file ownership between users?

**Transfer ownership of a single directory:**
```bash
./grumpwalk.py --host cluster --path /projects/projectA \
  --change-owner "olduser:newuser"
```

**Transfer ownership recursively (all children):**
```bash
./grumpwalk.py --host cluster --path /shared/team-data \
  --change-owner "olduser:newuser" \
  --propagate-changes --progress
```

**Transfer ownership using UIDs (NFS environments):**
```bash
./grumpwalk.py --host cluster --path /nfs-exports/home \
  --change-owner "uid:1001:uid:2001" \
  --propagate-changes --progress
```

**Transfer both owner and group simultaneously:**
```bash
./grumpwalk.py --host cluster --path /projects/legacy \
  --change-owner "departed_user:new_owner" \
  --change-group "old_team:new_team" \
  --propagate-changes --progress
```

### How do I change ownership based on filters?

**Change ownership only for files (not directories):**
```bash
./grumpwalk.py --host cluster --path /data \
  --change-owner "olduser:newuser" \
  --type file \
  --propagate-changes --progress
```

**Change ownership only for old files:**
```bash
./grumpwalk.py --host cluster --path /archive \
  --change-owner "departed_user:archive_admin" \
  --older-than 365 \
  --propagate-changes --progress
```

**Change ownership only for large files:**
```bash
./grumpwalk.py --host cluster --path /media \
  --change-owner "contractor:media_team" \
  --larger-than 1GB \
  --type file \
  --propagate-changes --progress
```

**Change ownership for specific file types:**
```bash
./grumpwalk.py --host cluster --path /projects \
  --change-owner "developer1:developer2" \
  --name "*.py" --name "*.js" \
  --type file \
  --propagate-changes --progress
```

### How do I perform bulk ownership changes?

**Create a CSV file with ownership mappings:**
```csv
source,target
olduser1,newuser1
olduser2,newuser2
uid:1001,newuser3
OLDDOMAIN\jsmith,NEWDOMAIN\jsmith
```

**Preview bulk ownership changes:**
```bash
./grumpwalk.py --host cluster --path /data \
  --change-owners-file ownership_migration.csv \
  --propagate-changes --dry-run
```

**Execute bulk ownership changes:**
```bash
./grumpwalk.py --host cluster --path /data \
  --change-owners-file ownership_migration.csv \
  --propagate-changes --progress
```

**Bulk group changes from CSV:**
```bash
./grumpwalk.py --host cluster --path /shared \
  --change-groups-file group_migration.csv \
  --propagate-changes --progress
```

### How do I change group ownership?

**Change group for a directory tree:**
```bash
./grumpwalk.py --host cluster --path /projects/teamA \
  --change-group "old_team:new_team" \
  --propagate-changes --progress
```

**Change group using GIDs:**
```bash
./grumpwalk.py --host cluster --path /nfs-data \
  --change-group "gid:100:gid:200" \
  --propagate-changes --progress
```

**Combine owner and group changes:**
```bash
./grumpwalk.py --host cluster --path /shared/department \
  --change-owner "manager1:manager2" \
  --change-group "dept_old:dept_new" \
  --propagate-changes --progress
```

### How do I add a new team member to existing shares?

**Clone permissions from existing team member:**
```bash
./grumpwalk.py --host cluster --path /projects/teamA \
  --clone-ace-source "existing_member" \
  --clone-ace-target "new_member" \
  --propagate-changes --progress
```

**Or add explicit permissions:**
```bash
./grumpwalk.py --host cluster --path /projects/teamA \
  --add-ace "Allow:fd:new_member:Modify" \
  --propagate-changes --progress
```

### How do I copy an ACL from one directory to another?

Use `--source-acl` and `--acl-target` to clone an entire ACL (all ACEs, owner, and group) from a source path to a target path.

**Copy ACL to a single directory:**
```bash
./grumpwalk.py --host cluster \
  --source-acl /template/dir \
  --acl-target /target/dir
```

**Copy ACL and apply to all children recursively:**
```bash
./grumpwalk.py --host cluster \
  --source-acl /template/dir \
  --acl-target /target/dir \
  --propagate-acls --progress
```

**Copy ACL along with owner and group:**
```bash
./grumpwalk.py --host cluster \
  --source-acl /template/dir \
  --acl-target /target/dir \
  --copy-owner --copy-group \
  --propagate-acls --progress
```

**Copy only owner and group (no ACL changes):**
```bash
./grumpwalk.py --host cluster \
  --source-acl /template/dir \
  --acl-target /target/dir \
  --copy-owner --copy-group --owner-group-only \
  --propagate-acls
```

**Apply ACL only to files matching a filter:**
```bash
# Only apply to files older than 30 days
./grumpwalk.py --host cluster \
  --source-acl /template/dir \
  --acl-target /target/dir \
  --propagate-acls \
  --older-than 30 --type file \
  --progress
```

### How do I keep two users' permissions in sync?

Use `--sync-cloned-aces` to update existing ACEs to match the source user's rights.

**Default behavior (without --sync-cloned-aces):**
```bash
# If joe already has an Allow ACE, it's skipped (no change)
./grumpwalk.py --host cluster --path /shared \
  --clone-ace-source bob --clone-ace-target joe \
  --propagate-changes
```

**With --sync-cloned-aces (updates existing ACEs):**
```bash
# Joe's existing Allow ACE is updated to match Bob's rights
./grumpwalk.py --host cluster --path /shared \
  --clone-ace-source bob --clone-ace-target joe \
  --sync-cloned-aces \
  --propagate-changes --progress
```

**Team member replacement workflow:**
```bash
# Alice (leaving) has carefully tuned permissions
# Bob (replacement) should have identical access

# Step 1: Initial clone - creates ACEs where Bob has none
./grumpwalk.py --host cluster --path /projects \
  --clone-ace-source alice --clone-ace-target bob \
  --propagate-changes --progress

# Step 2: Later, if Alice's permissions changed, sync Bob to match
./grumpwalk.py --host cluster --path /projects \
  --clone-ace-source alice --clone-ace-target bob \
  --sync-cloned-aces \
  --propagate-changes --progress
```

**Behavior summary:**

| Scenario | Without --sync-cloned-aces | With --sync-cloned-aces |
|----------|---------------------------|------------------------|
| Target has no ACE | Create new ACE | Create new ACE |
| Target has existing ACE | Skip (no change) | Update rights to match source |

### How do I implement least privilege access?

Following [NTFS permissions best practices](https://activedirectorypro.com/ntfs-permissions-management-best-practices/):

**Remove overly broad permissions:**
```bash
# Remove Everyone access
./grumpwalk.py --host cluster --path /sensitive \
  --remove-ace "Allow:Everyone" \
  --propagate-changes --dry-run

# If satisfied, run without --dry-run
```

**Downgrade from FullControl to Modify:**
```bash
./grumpwalk.py --host cluster --path /shared \
  --replace-ace "Allow:Domain Users" \
  --new-ace "Allow:fd:Domain Users:Modify" \
  --propagate-changes --progress
```

### How do I grant read-only access?

```bash
./grumpwalk.py --host cluster --path /published \
  --add-ace "Allow:fd:Readers_Group:Read" \
  --propagate-changes --progress
```

### How do I revoke write access while keeping read?

```bash
./grumpwalk.py --host cluster --path /archive \
  --remove-rights "Allow:Domain Users:w" \
  --propagate-changes --progress
```

---

## Domain Migration

### How do I migrate permissions during an AD domain migration?

**Step 1: Create migration CSV file:**
```csv
source,target
OLDDOMAIN\user1,NEWDOMAIN\user1
OLDDOMAIN\user2,NEWDOMAIN\user2
OLDDOMAIN\GroupA,NEWDOMAIN\GroupA
OLDDOMAIN\Domain Users,NEWDOMAIN\Domain Users
OLDDOMAIN\Domain Admins,NEWDOMAIN\Domain Admins
```

**Step 2: Dry-run the migration:**
```bash
./grumpwalk.py --host cluster --path /data \
  --migrate-trustees domain_migration.csv \
  --dry-run
```

**Step 3: Execute the migration:**
```bash
./grumpwalk.py --host cluster --path /data \
  --migrate-trustees domain_migration.csv \
  --propagate-changes \
  --ace-backup pre_migration_acls.json \
  --progress
```

### How do I migrate from NFS UIDs to AD accounts?

**Create UID to AD mapping:**
```csv
source,target
uid:1001,NEWDOMAIN\alice
uid:1002,NEWDOMAIN\bob
uid:1003,NEWDOMAIN\charlie
gid:100,NEWDOMAIN\Engineering
gid:200,NEWDOMAIN\Sales
```

**Execute migration:**
```bash
./grumpwalk.py --host cluster --path /nfs-data \
  --migrate-trustees uid_to_ad.csv \
  --propagate-changes --progress
```

### How do I clone permissions for a new parallel structure?

```bash
# Create mapping for team restructuring
cat > team_restructure.csv << EOF
source,target
TeamA_Leads,NewTeam_Leads
TeamA_Members,NewTeam_Members
TeamB_Leads,NewTeam_Leads
TeamB_Members,NewTeam_Members
EOF

./grumpwalk.py --host cluster --path /projects \
  --clone-ace-map team_restructure.csv \
  --propagate-changes --progress
```

### How do I migrate file ownership during domain migration?

File ownership migration is separate from ACL/ACE migration. Use `--change-owner` and `--change-group` for ownership:

**Step 1: Create ownership migration CSV:**
```csv
source,target
OLDDOMAIN\user1,NEWDOMAIN\user1
OLDDOMAIN\user2,NEWDOMAIN\user2
OLDDOMAIN\service_account,NEWDOMAIN\service_account
```

**Step 2: Preview ownership changes:**
```bash
./grumpwalk.py --host cluster --path /data \
  --change-owners-file owner_migration.csv \
  --propagate-changes --dry-run
```

**Step 3: Execute ownership migration:**
```bash
./grumpwalk.py --host cluster --path /data \
  --change-owners-file owner_migration.csv \
  --propagate-changes --progress
```

### How do I migrate both ACLs and ownership together?

For a complete domain migration, you typically need to migrate both ACEs and file ownership:

**Complete domain migration script:**
```bash
#!/bin/bash
CLUSTER="cluster.example.com"
PATH="/data"
ACE_CSV="ace_migration.csv"
OWNER_CSV="owner_migration.csv"
GROUP_CSV="group_migration.csv"

# Step 1: Backup current ACLs
./grumpwalk.py --host $CLUSTER --path $PATH \
  --acl-report --acl-resolve-names \
  --json-out pre_migration_acls.json

# Step 2: Migrate ACE trustees (permissions)
./grumpwalk.py --host $CLUSTER --path $PATH \
  --migrate-trustees $ACE_CSV \
  --propagate-changes --progress

# Step 3: Migrate file owners
./grumpwalk.py --host $CLUSTER --path $PATH \
  --change-owners-file $OWNER_CSV \
  --propagate-changes --progress

# Step 4: Migrate file groups
./grumpwalk.py --host $CLUSTER --path $PATH \
  --change-groups-file $GROUP_CSV \
  --propagate-changes --progress
```

### How do I migrate NFS UID/GID ownership to AD accounts?

**Create ownership mapping CSV:**
```csv
source,target
uid:1001,NEWDOMAIN\alice
uid:1002,NEWDOMAIN\bob
uid:1003,NEWDOMAIN\charlie
```

**Create group ownership mapping CSV:**
```csv
source,target
gid:100,NEWDOMAIN\Engineering
gid:200,NEWDOMAIN\Sales
gid:300,NEWDOMAIN\Marketing
```

**Execute NFS to AD ownership migration:**
```bash
# Migrate owners
./grumpwalk.py --host cluster --path /nfs-data \
  --change-owners-file uid_to_ad_owners.csv \
  --propagate-changes --progress

# Migrate groups
./grumpwalk.py --host cluster --path /nfs-data \
  --change-groups-file gid_to_ad_groups.csv \
  --propagate-changes --progress
```

### How do I consolidate ownership after an acquisition?

When merging companies, you may need to consolidate file ownership:

**Create consolidation mapping:**
```csv
source,target
ACQUIRED_DOMAIN\user1,PARENT_DOMAIN\user1
ACQUIRED_DOMAIN\user2,PARENT_DOMAIN\user2
ACQUIRED_DOMAIN\admin,PARENT_DOMAIN\admin
```

**Migrate in phases by department:**
```bash
# Phase 1: Engineering
./grumpwalk.py --host cluster --path /acquired/engineering \
  --change-owners-file consolidation.csv \
  --propagate-changes --progress

# Phase 2: Sales
./grumpwalk.py --host cluster --path /acquired/sales \
  --change-owners-file consolidation.csv \
  --propagate-changes --progress

# Phase 3: Remaining
./grumpwalk.py --host cluster --path /acquired \
  --change-owners-file consolidation.csv \
  --propagate-changes --progress
```

### How do I handle mixed identity environments?

When migrating environments with both AD and NFS identities:

**Create comprehensive mapping:**
```csv
source,target
# AD users
OLDDOMAIN\alice,NEWDOMAIN\alice
OLDDOMAIN\bob,NEWDOMAIN\bob
# NFS UIDs that map to AD
uid:1001,NEWDOMAIN\alice
uid:1002,NEWDOMAIN\bob
# Service accounts
OLDDOMAIN\svc_backup,NEWDOMAIN\svc_backup
```

**Execute with combined CSV:**
```bash
./grumpwalk.py --host cluster --path /mixed-data \
  --change-owners-file comprehensive_migration.csv \
  --propagate-changes --progress
```

---

## Compliance and Auditing

### How do I generate a permissions audit report?

```bash
./grumpwalk.py --host cluster --path /sensitive \
  --acl-report \
  --acl-resolve-names \
  --acl-csv permissions_audit.csv \
  --progress
```

### How do I find files with specific permissions?

**Find files accessible by Everyone:**
```bash
./grumpwalk.py --host cluster --path /data \
  --acl-report --progress | \
  grep -i "everyone"
```

### How do I identify GDPR data retention violations?

**Find personal data older than retention period:**
```bash
./grumpwalk.py --host cluster --path /customer-data \
  --older-than 1095 \
  --type file \
  --csv-out gdpr_retention_review.csv
```

**Find files in regulated directories not accessed in required period:**
```bash
./grumpwalk.py --host cluster --path /financial-records \
  --accessed --older-than 2555 \
  --type file --progress
```

### How do I audit who has access to sensitive directories?

```bash
./grumpwalk.py --host cluster --path /hr/confidential \
  --acl-report --acl-resolve-names --max-depth 1
```


---

## Security and Incident Response

### How do I identify files modified during a suspected breach?

**Find files modified in the last 24 hours:**
```bash
./grumpwalk.py --host cluster --path /data \
  --modified --newer-than 1 \
  --type file --progress \
  --json-out modified_24h.json
```

**Find files modified during specific attack window (combined with timestamps):**
```bash
./grumpwalk.py --host cluster --path /data \
  --modified --newer-than 3 \
  --json --all-attributes \
  --type file | \
  jq 'select(.modification_time > "2024-01-15T00:00:00" and .modification_time < "2024-01-15T12:00:00")'
```

### How do I find potentially encrypted files (ransomware)?

**Find files with suspicious extensions:**
```bash
./grumpwalk.py --host cluster --path /data \
  --name '*.encrypted' --name '*.locked' --name '*.crypto' \
  --name '*.crypt' --name '*.enc' --name '*.crypted' \
  --type file --progress
```

**Find ransom note files:**
```bash
./grumpwalk.py --host cluster --path /data \
  --name '*README*' --name '*DECRYPT*' --name '*RECOVER*' \
  --name '*INSTRUCTION*' --name '*HOW_TO*' \
  --modified --newer-than 7 \
  --type file
```

### How do I identify unusual file permission changes?

**Find files where Everyone has write access:**
```bash
./grumpwalk.py --host cluster --path /data \
  --acl-report --json | \
  jq 'select(.trustees[] | contains("EVERYONE@") and contains("w"))'
```

### How do I find recently created executable content?

```bash
./grumpwalk.py --host cluster --path /data \
  --name '*.exe' --name '*.dll' --name '*.bat' --name '*.ps1' \
  --name '*.sh' --name '*.py' --name '*.js' \
  --created --newer-than 7 \
  --type file
```

### How do I audit access after a security incident?

```bash
# Generate comprehensive ACL report
./grumpwalk.py --host cluster --path /compromised-share \
  --acl-report \
  --acl-resolve-names \
  --show-owner \
  --show-group \
  --acl-csv incident_acl_audit.csv \
  --progress
```

### How do I lock down a directory during investigation?

**Backup current ACLs and add deny:**
```bash
./grumpwalk.py --host cluster --path /investigation \
  --add-ace "Deny::Everyone:w" \
  --ace-backup investigation_original_acls.json \
  --propagate-changes --progress
```

### How do I restore ACLs after investigation is complete?

**Preview the restore (dry run):**
```bash
./grumpwalk.py --host cluster \
  --ace-restore investigation_original_acls.json --dry-run
```

**Restore ACLs to the original path:**
```bash
./grumpwalk.py --host cluster \
  --ace-restore investigation_original_acls.json
```

**Restore and propagate to all children:**
```bash
./grumpwalk.py --host cluster \
  --ace-restore investigation_original_acls.json \
  --propagate-changes --progress
```

**If the file/directory was renamed, use --force-restore:**
```bash
# The backup contains the original file_id for safety verification
# If the current path has a different file_id (e.g., path was reused),
# grumpwalk will refuse to restore unless --force-restore is used
./grumpwalk.py --host cluster \
  --ace-restore investigation_original_acls.json \
  --force-restore
```

**Restore to a different path:**
```bash
# Use --path to override the original path stored in the backup
./grumpwalk.py --host cluster --path /new/location \
  --ace-restore investigation_original_acls.json \
  --force-restore --propagate-changes
```

---

## Duplicate and Similar File Detection

### How do I find duplicate files?

**Find similar files using content sampling:**
```bash
./grumpwalk.py --host cluster --path /backups \
  --find-similar \
  --progress \
  --csv-out potential_duplicates.csv
```

**Estimate data transfer before scanning:**
```bash
./grumpwalk.py --host cluster --path /data \
  --find-similar --estimate-size
```

### How do I find duplicates quickly (less accurate)?

```bash
./grumpwalk.py --host cluster --path /data \
  --find-similar --by-size \
  --progress
```

### How do I tune similarity detection for accuracy?

**Higher accuracy (more data transfer):**
```bash
./grumpwalk.py --host cluster --path /important \
  --find-similar \
  --sample-size 256KB \
  --sample-points 11 \
  --progress
```

**Lower accuracy, faster (less data transfer):**
```bash
./grumpwalk.py --host cluster --path /archives \
  --find-similar \
  --sample-size 32KB \
  --sample-points 5 \
  --progress
```

### How do I find duplicate large files specifically?

```bash
./grumpwalk.py --host cluster --path /data \
  --larger-than 100MB \
  --type file \
  --find-similar \
  --progress \
  --csv-out large_duplicates.csv
```

---

## Media and Creative Workflows

### How do I find large media files?

```bash
./grumpwalk.py --host cluster --path /media \
  --name '*.mov' --name '*.mp4' --name '*.mxf' --name '*.r3d' \
  --name '*.ari' --name '*.braw' --name '*.prores' \
  --larger-than 1GB \
  --type file --progress
```

### How do I find old project files for archival?

```bash
./grumpwalk.py --host cluster --path /projects \
  --accessed --older-than 180 \
  --modified --older-than 180 \
  --larger-than 100MB \
  --type file \
  --csv-out archive_candidates.csv
```

### How do I identify render cache files for cleanup?

```bash
./grumpwalk.py --host cluster --path /renders \
  --name '*.tmp' --name '*cache*' --name '*preview*' \
  --name '*.peak' --name '*.pek' --name '*.pkf' \
  --older-than 30 \
  --type file
```

### How do I find proxy files vs original media?

```bash
# Find proxy files
./grumpwalk.py --host cluster --path /media \
  --name '*proxy*' --name '*_lowres*' --name '*_small*' \
  --type file \
  --json-out proxies.json

# Find original high-res
./grumpwalk.py --host cluster --path /media \
  --name '*.r3d' --name '*.braw' --name '*.ari' \
  --larger-than 1GB \
  --type file \
  --json-out originals.json
```

### How do I audit project folder structures?

```bash
./grumpwalk.py --host cluster --path /projects \
  --show-dir-stats --max-depth 3 --progress
```

---

## Reporting and Analytics

### How do I generate a full inventory?

```bash
./grumpwalk.py --host cluster --path / \
  --all-attributes \
  --progress \
  > full_inventory.ndjson
```

### How do I export to CSV for Excel analysis?

```bash
./grumpwalk.py --host cluster --path /data \
  --older-than 365 \
  --type file \
  --csv-out old_files.csv
```

### How do I analyze results with jq?

**Note:** These examples assume `inventory.ndjson` was created with `--json --all-attributes`:
```bash
./grumpwalk.py --host cluster --path /data --json --all-attributes > inventory.ndjson
```

**Count files by extension:**
```bash
cat inventory.ndjson | \
  jq -r '.name | split(".") | .[-1] | ascii_downcase' | \
  sort | uniq -c | sort -rn | head -20
```

**Sum total size:**
```bash
cat inventory.ndjson | jq -s 'map(.size | tonumber) | add'
```

**Group by owner:**
```bash
cat inventory.ndjson | \
  jq -r '.owner' | sort | uniq -c | sort -rn
```

**Find paths with most files:**
```bash
cat inventory.ndjson | \
  jq -r '.path | split("/")[1:3] | join("/")' | \
  sort | uniq -c | sort -rn | head -20
```

### How do I analyze with DuckDB?

```sql
-- Create table from NDJSON
CREATE TABLE files AS SELECT * FROM read_ndjson_auto('inventory.ndjson');

-- Storage by owner (top 20)
SELECT owner,
       COUNT(*) as file_count,
       SUM(size) / (1024*1024*1024) as total_gb
FROM files
GROUP BY owner
ORDER BY total_gb DESC
LIMIT 20;

-- Files by age bucket
SELECT
  CASE
    WHEN creation_time > CURRENT_DATE - INTERVAL 30 DAY THEN '0-30 days'
    WHEN creation_time > CURRENT_DATE - INTERVAL 90 DAY THEN '30-90 days'
    WHEN creation_time > CURRENT_DATE - INTERVAL 365 DAY THEN '90-365 days'
    ELSE '1+ years'
  END as age_bucket,
  COUNT(*) as file_count,
  SUM(size) / (1024*1024*1024) as total_gb
FROM files
GROUP BY age_bucket;
```

### How do I analyze with Python?

```python
import json

total_size = 0
file_count = 0
owners = {}

with open('inventory.ndjson') as f:
    for line in f:
        file = json.loads(line)
        total_size += file.get('size', 0)
        file_count += 1

        owner = file.get('owner', 'unknown')
        if owner not in owners:
            owners[owner] = {'count': 0, 'size': 0}
        owners[owner]['count'] += 1
        owners[owner]['size'] += file.get('size', 0)

print(f"Total files: {file_count:,}")
print(f"Total size: {total_size / (1024**4):.2f} TB")

# Top 10 owners by size
for owner, stats in sorted(owners.items(), key=lambda x: x[1]['size'], reverse=True)[:10]:
    print(f"{owner}: {stats['count']:,} files, {stats['size'] / (1024**3):.2f} GB")
```

---

## Performance Optimization

### How do I maximize crawl speed?

**For large clusters (>10M files): REVIEW RAM USE GUIDELINES FIRST!**
```bash
./grumpwalk.py --host cluster --path /data \
  --max-concurrent 500 \
  --connector-limit 500 \
  --progress
```

### How do I profile performance bottlenecks?

```bash
./grumpwalk.py --host cluster --path /data \
  --profile --progress \
  --limit 10000
```

### How do I reduce memory usage?

Memory usage scales primarily with the number of subdirectories being traversed, not the number of files. The main memory consumers are:

| Component | Impact | Tunable |
|-----------|--------|---------|
| Subdirectory queue | O(num_dirs) - paths held for processing | Partial |
| Concurrency buffers | O(max_concurrent) - async task overhead | Yes |
| Identity cache | O(unique_owners) - auth_id mappings | No |
| Connection pool | O(connector_limit) - HTTP connections | Yes |

**Reduce concurrency for memory-constrained systems:**
```bash
# For systems with <8GB RAM
./grumpwalk.py --host cluster --path /data \
  --max-concurrent 25 \
  --connector-limit 25 \
  --progress
```

**Process output in streaming fashion:**
```bash
# Stream directly to compressed file (minimal memory)
./grumpwalk.py --host cluster --path /data --progress | \
  gzip > inventory.ndjson.gz

# Stream to CSV file (writes rows incrementally)
./grumpwalk.py --host cluster --path /data \
  --csv-out inventory.csv \
  --progress
```

**Limit traversal depth:**
```bash
# Process shallower trees to limit queued directories
./grumpwalk.py --host cluster --path /data \
  --max-depth 5 \
  --progress
```

**Process large trees in segments:**
```bash
# Instead of crawling /data with 500k subdirectories at once,
# process top-level directories separately
for dir in project1 project2 project3; do
  ./grumpwalk.py --host cluster --path /data/$dir \
    --csv-out ${dir}_inventory.csv \
    --progress
done
```

**Limit results for quick checks:**
```bash
./grumpwalk.py --host cluster --path /data \
  --older-than 365 \
  --limit 1000
```

### Memory Planning Guide

Use this formula to estimate RAM requirements:

```
RAM (GB) ~ (subdirectories / 50000) + (max_concurrent * 0.05) + 0.5
```

**Example calculations:**
- 50k subdirs, default concurrency: `50000/50000 + 100*0.05 + 0.5 = 6.5 GB`
- 500k subdirs, default concurrency: `500000/50000 + 100*0.05 + 0.5 = 15.5 GB`
- 500k subdirs, reduced concurrency: `500000/50000 + 25*0.05 + 0.5 = 11.75 GB`

**Recommended configurations by available RAM:**

| Available RAM | --max-concurrent | --connector-limit | Notes |
|---------------|------------------|-------------------|-------|
| 4 GB | 25 | 25 | Use --max-depth or segment paths |
| 8 GB | 50 | 50 | OK for <100k directories |
| 16 GB | 100 | 100 | Default, handles most cases |
| 32+ GB | 200-500 | 200 | High performance mode |

**Low-memory configuration example:**
```bash
# For 4GB RAM systems with large directory trees
./grumpwalk.py --host cluster --path /data \
  --max-concurrent 25 \
  --connector-limit 25 \
  --max-depth 3 \
  --csv-out inventory.csv \
  --progress
```

### How do I handle very large directories?

**Skip directories with too many entries:**
```bash
./grumpwalk.py --host cluster --path /data \
  --max-entries-per-dir 100000 \
  --progress
```

**Skip known large or irrelevant directories:**
```bash
./grumpwalk.py --host cluster --path /data \
  --omit-subdirs '.snapshot' \
  --omit-subdirs 'tmp' \
  --omit-subdirs 'cache' \
  --progress
```

**Skip specific paths entirely:**
```bash
./grumpwalk.py --host cluster --path / \
  --omit-path /var/log \
  --omit-path /tmp \
  --omit-path /scratch \
  --progress
```

---

## Scripting and Automation

### How do I run grumpwalk in a scheduled job?

```bash
#!/bin/bash
# daily_inventory.sh

DATE=$(date +%Y%m%d)
CLUSTER="cluster.example.com"
OUTPUT_DIR="/reports"

# Generate daily inventory
./grumpwalk.py --host $CLUSTER --path /data \
  --progress \
  > "${OUTPUT_DIR}/inventory_${DATE}.ndjson" 2> "${OUTPUT_DIR}/inventory_${DATE}.log"

# Compress older inventories
find ${OUTPUT_DIR} -name "inventory_*.ndjson" -mtime +7 -exec gzip {} \;

# Clean up inventories older than 30 days
find ${OUTPUT_DIR} -name "inventory_*.ndjson.gz" -mtime +30 -delete
```

### How do I create an alerting script for stale data?

```bash
#!/bin/bash
# stale_data_alert.sh

THRESHOLD_GB=1000
CLUSTER="cluster.example.com"

# Find stale data (not accessed in 365 days)
STALE_SIZE=$(./grumpwalk.py --host $CLUSTER --path /data \
  --accessed --older-than 365 \
  --json --all-attributes \
  --type file 2>/dev/null | \
  jq -s 'map(.size | tonumber) | add // 0' | \
  awk '{print int($1/1024/1024/1024)}')

if [ "$STALE_SIZE" -gt "$THRESHOLD_GB" ]; then
  echo "ALERT: ${STALE_SIZE}GB of stale data found (threshold: ${THRESHOLD_GB}GB)"
  # Send email/Slack notification here
fi
```

### How do I automate permission reports?

```bash
#!/bin/bash
# weekly_permission_audit.sh

DATE=$(date +%Y%m%d)
CLUSTER="cluster.example.com"
SENSITIVE_PATHS="/hr/confidential /finance/restricted /legal/privileged"

for PATH in $SENSITIVE_PATHS; do
  SAFE_NAME=$(echo $PATH | tr '/' '_')
  ./grumpwalk.py --host $CLUSTER --path $PATH \
    --acl-report \
    --acl-resolve-names \
    --acl-csv "acl_audit${SAFE_NAME}_${DATE}.csv" \
    --progress 2>&1 | tee "acl_audit${SAFE_NAME}_${DATE}.log"
done
```

### How do I pipe grumpwalk output to other tools?

**To jq for filtering:**
```bash
./grumpwalk.py --host cluster --path /data \
  --json --all-attributes | \
  jq 'select((.size | tonumber) > 1073741824)' > large_files.json
```

**To gzip for compression:**
```bash
./grumpwalk.py --host cluster --path / --progress | \
  gzip > full_inventory.ndjson.gz
```

**To xargs for further processing:**
```bash
# Default output is one path per line, perfect for xargs
./grumpwalk.py --host cluster --path /tmp \
  --name '*.tmp' --older-than 7 --type file | \
  xargs -I {} echo "Would delete: {}"
```

---

## Quick Reference Card

### Most Common Commands

| Task | Command |
|------|---------|
| Full inventory | `--path / --progress > inventory.ndjson` |
| Find large files | `--larger-than 1GB --type file` |
| Find old files | `--older-than 365 --type file` |
| Find by name | `--name '*.log'` |
| Owner report | `--owner-report --progress` |
| ACL audit | `--acl-report --acl-resolve-names` |
| Add permission | `--add-ace 'Allow:fd:Group:Modify' --propagate-changes` |
| Remove permission | `--remove-ace 'Allow:Everyone' --propagate-changes` |
| Change owner | `--change-owner 'old:new' --propagate-changes` |
| Change group | `--change-group 'old:new' --propagate-changes` |
| Bulk owner migration | `--change-owners-file migration.csv --propagate-changes` |
| Backup ACL | `--ace-backup backup.json` (with any ACE operation) |
| Restore ACL | `--ace-restore backup.json` |
| Find duplicates | `--find-similar --progress` |
| Dry run | `--dry-run` (add to any modification command) |

### Size Suffixes

| Suffix | Meaning |
|--------|---------|
| `KB` | Kilobytes (1000) |
| `KiB` | Kibibytes (1024) |
| `MB` | Megabytes |
| `MiB` | Mebibytes |
| `GB` | Gigabytes |
| `GiB` | Gibibytes |
| `TB` | Terabytes |
| `TiB` | Tebibytes |

### Time Field Shortcuts

| Flag | Time Field |
|------|------------|
| `--created` | creation_time |
| `--modified` | modification_time |
| `--accessed` | access_time |
| `--changed` | change_time |

### ACE Pattern Quick Reference

| Pattern | Meaning |
|---------|---------|
| `Allow:fd:User:Modify` | Allow, file+dir inherit, Modify rights |
| `Deny::Everyone:w` | Deny, no inheritance, write only |
| `Allow:fd:Group:Read` | Allow, file+dir inherit, Read rights |
| `Allow:fd:User:FullControl` | Allow, file+dir inherit, all rights |

### ACE Operation Behavior

| Operation | When trustee exists | When trustee doesn't exist |
|-----------|--------------------|-----------------------------|
| `--add-ace` | Merges rights with existing ACE | Creates new ACE |
| `--replace-ace` (alone) | Replaces flags and rights in-place | No change |
| `--replace-ace` + `--new-ace` | Replaces first match, removes duplicates | No change |

**Important:** When using `--replace-ace` with `--new-ace`:
- The `--replace-ace` pattern is a **search pattern** using `Type:Trustee` format only
- If multiple ACEs match the same trustee, all are consolidated into one
- The first match is replaced; additional matches are deleted

**Example:** If an ACL has three ACEs for "Domain Users" (Read, Write, Execute), running:
```bash
--replace-ace "Allow:Domain Users" --new-ace "Allow:fd:Domain Users:Modify"
```
Results in a single ACE with Modify rights; the other two are removed.

### Owner/Group Change Pattern Quick Reference

| Pattern | Meaning |
|---------|---------|
| `olduser:newuser` | Simple username change |
| `uid:1001:uid:2001` | UID to UID (NFS) |
| `gid:100:gid:200` | GID to GID (NFS) |
| `DOMAIN\old:DOMAIN\new` | AD user/group change |
| `uid:1001:DOMAIN\user` | UID to AD user |
| `OLDDOMAIN\user:NEWDOMAIN\user` | Cross-domain migration |

### Propagation Flag

The `--propagate-changes` flag applies modifications recursively to all children:

| Without flag | Only the target path is modified |
|--------------|----------------------------------|
| With flag | Target path and all descendants are modified |

Works with:
- ACE operations (`--add-ace`, `--remove-ace`, `--replace-ace`, etc.)
- Owner/group changes (`--change-owner`, `--change-group`)
- Trustee migration (`--migrate-trustees`)
- ACE cloning (`--clone-ace-source/--clone-ace-target`)
- ACL restore (`--ace-restore`)

### ACL Backup and Restore

| Operation | Command |
|-----------|---------|
| Backup ACL | `--ace-backup backup.json` (with any ACE operation) |
| Restore ACL | `--ace-restore backup.json` |
| Preview restore | `--ace-restore backup.json --dry-run` |
| Force restore | `--ace-restore backup.json --force-restore` |

The backup file includes:
- Original path
- File ID (for safety verification)
- Complete ACL with all ACEs
- Timestamp

---

## Combining Filters with Actions

One of grumpwalk's most powerful capabilities is combining multiple filters with modification actions. This allows surgical precision when making changes across large file systems.

### Complex Ownership Migration with Exclusions

**Scenario:** Change owners from multiple sources, but only for large cold files, excluding archive directories:

```bash
./grumpwalk.py --host cluster --path /data \
  --change-owner "DOMAIN\\joe:DOMAIN\\bob" \
  --change-owner "uid:1000:uid:3000" \
  --larger-than 100GB \
  --accessed --older-than 30 \
  --omit-path /data/deep_archive \
  --type file \
  --propagate-changes --progress
```

This command:
- Changes owner from `DOMAIN\joe` to `DOMAIN\bob`
- Also changes owner from `uid:1000` to `uid:3000`
- Only affects files larger than 100GB
- Only affects files not accessed in 30+ days
- Excludes everything under `/data/deep_archive`
- Only processes files (not directories)

### Targeted Permission Cleanup by File Age and Type

**Scenario:** Remove "Everyone" access from old documents, but keep it on recent files and exclude temp directories:

```bash
./grumpwalk.py --host cluster --path /shared \
  --remove-ace "Allow:Everyone" \
  --name "*.docx" --name "*.xlsx" --name "*.pdf" \
  --modified --older-than 90 \
  --omit-subdirs "temp" --omit-subdirs ".tmp" \
  --type file \
  --propagate-changes --dry-run
```

### Contractor Offboarding with Scope Limits

**Scenario:** Remove contractor access and transfer ownership, but only in project directories and only 3 levels deep:

```bash
./grumpwalk.py --host cluster --path /projects \
  --remove-ace "Allow:DOMAIN\\contractor_group" \
  --change-owner "DOMAIN\\contractor1:DOMAIN\\project_lead" \
  --max-depth 3 \
  --omit-subdirs ".git" --omit-subdirs "node_modules" \
  --propagate-changes --progress
```

### Size-Based Permission Tiering

**Scenario:** Large media files should only be accessible by the media team, not general users:

```bash
./grumpwalk.py --host cluster --path /media \
  --remove-ace "Allow:Domain Users" \
  --add-ace "Allow:fd:Media_Team:Modify" \
  --larger-than 1GB \
  --name "*.mov" --name "*.mp4" --name "*.mxf" --name "*.r3d" \
  --type file \
  --propagate-changes --progress
```

### Stale Data Ownership Consolidation

**Scenario:** Transfer ownership of all files not accessed in 2 years to an archive administrator, but only in specific departments:

```bash
./grumpwalk.py --host cluster --path /home \
  --change-owner "DOMAIN\\departed_user1:DOMAIN\\archive_admin" \
  --change-owner "DOMAIN\\departed_user2:DOMAIN\\archive_admin" \
  --change-owner "DOMAIN\\departed_user3:DOMAIN\\archive_admin" \
  --accessed --older-than 730 \
  --omit-path /home/executives \
  --omit-path /home/legal \
  --type file \
  --propagate-changes --progress
```

### Compliance-Driven Permission Lockdown

**Scenario:** Make financial documents read-only for everyone except finance team after fiscal year close:

```bash
./grumpwalk.py --host cluster --path /finance/FY2024 \
  --remove-rights "Allow:Domain Users:w" \
  --add-ace "Allow:fd:Finance_Team:Modify" \
  --name "*.xlsx" --name "*.pdf" --name "*.csv" \
  --created --older-than 365 \
  --type file \
  --propagate-changes --ace-backup fy2024_acl_backup.json \
  --progress
```

### Multi-Domain Migration with File Type Filtering

**Scenario:** Migrate ACEs and ownership from old domain to new, but only for source code files:

```bash
./grumpwalk.py --host cluster --path /development \
  --migrate-trustees domain_migration.csv \
  --change-owners-file owner_migration.csv \
  --name "*.py" --name "*.js" --name "*.java" --name "*.go" --name "*.rs" \
  --omit-subdirs "vendor" --omit-subdirs "node_modules" --omit-subdirs ".venv" \
  --type file \
  --propagate-changes --progress
```

### Ransomware Recovery Permission Reset

**Scenario:** After a security incident, reset permissions on recently modified files while excluding known-good directories:

```bash
./grumpwalk.py --host cluster --path /data \
  --remove-ace "Allow:Everyone" \
  --remove-ace "Allow:Authenticated Users" \
  --add-ace "Allow:fd:IT_Admins:FullControl" \
  --modified --newer-than 7 \
  --omit-path /data/system \
  --omit-path /data/backups \
  --type file \
  --propagate-changes --ace-backup incident_recovery_backup.json \
  --progress
```

### Selective Group Migration for NFS to AD Transition

**Scenario:** Migrate group ownership from NFS GIDs to AD groups, but only for files owned by specific UIDs:

```bash
./grumpwalk.py --host cluster --path /nfs-share \
  --change-group "gid:100:DOMAIN\\Engineering" \
  --change-group "gid:200:DOMAIN\\Sales" \
  --owner 1001 --owner 1002 --owner 1003 --uid \
  --type file \
  --propagate-changes --progress
```

### Project Handoff with Comprehensive Filters

**Scenario:** Transfer a project from one team to another - change owners, groups, and permissions, but only for active project files:

```bash
./grumpwalk.py --host cluster --path /projects/legacy_app \
  --change-owner "DOMAIN\\old_lead:DOMAIN\\new_lead" \
  --change-group "Old_Team:New_Team" \
  --clone-ace-source "Old_Team" \
  --clone-ace-target "New_Team" \
  --remove-ace "Allow:Old_Team" \
  --modified --newer-than 365 \
  --omit-subdirs ".git" --omit-subdirs "archive" \
  --max-depth 5 \
  --propagate-changes --dry-run
```

### Quota Enforcement Preparation

**Scenario:** Before implementing quotas, transfer ownership of oversized user directories to a shared service account:

```bash
./grumpwalk.py --host cluster --path /home \
  --change-owner "uid:1001:DOMAIN\\storage_service" \
  --change-owner "uid:1002:DOMAIN\\storage_service" \
  --larger-than 500GB \
  --type file \
  --propagate-changes --progress
```

### Combining CSV Mappings with Runtime Filters

**Scenario:** Use CSV files for bulk mappings while applying runtime filters:

```bash
# Create mapping files
cat > owners.csv << EOF
source,target
OLDDOMAIN\user1,NEWDOMAIN\user1
OLDDOMAIN\user2,NEWDOMAIN\user2
OLDDOMAIN\service,NEWDOMAIN\service
EOF

cat > groups.csv << EOF
source,target
OLDDOMAIN\Team_A,NEWDOMAIN\Team_A
OLDDOMAIN\Team_B,NEWDOMAIN\Team_B
EOF

# Apply with filters
./grumpwalk.py --host cluster --path /shared \
  --change-owners-file owners.csv \
  --change-groups-file groups.csv \
  --accessed --newer-than 365 \
  --omit-subdirs ".snapshot" \
  --type file \
  --propagate-changes --progress
```

### Filter Combination Quick Reference

| Filter Type | Flag | Combines With |
|-------------|------|---------------|
| Size | `--larger-than`, `--smaller-than` | All actions |
| Time | `--older-than`, `--newer-than` with `--accessed`, `--modified`, `--created` | All actions |
| Name | `--name` (OR), `--name-and` (AND) | All actions |
| Type | `--type file/directory/symlink` | All actions |
| Owner | `--owner` with `--ad`, `--uid`, `--local` | All actions |
| Exclusion | `--omit-subdirs`, `--omit-path` | All actions |
| Depth | `--max-depth` | All propagating actions |

### Best Practices for Complex Operations

1. **Always use `--dry-run` first** - Preview what will change before executing
2. **Use `--ace-backup`** - Save original ACLs before permission changes
3. **Start narrow, expand** - Test on a subdirectory before running on entire tree
4. **Combine `--progress` with `--verbose`** - Monitor what's happening in real-time
5. **Use `--max-depth` for testing** - Limit scope during validation
6. **Chain operations carefully** - Some filters may interact unexpectedly; verify with dry-run


