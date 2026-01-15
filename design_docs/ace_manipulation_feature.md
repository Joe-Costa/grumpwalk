# Plan: ACE Manipulation Feature for grumpwalk

## Overview

Add surgical ACE (Access Control Entry) manipulation capabilities to grumpwalk, allowing users to add, remove, or modify ACEs within ACLs across a directory tree.

## Research Findings

### Qumulo API Structure (Verified)

**v1 API GET Response** (used by grumpwalk):
```json
{
  "generated": false,
  "acl": {
    "control": ["PRESENT", "AUTO_INHERIT"],
    "posix_special_permissions": [],
    "aces": [
      {
        "type": "ALLOWED",
        "flags": ["OBJECT_INHERIT", "CONTAINER_INHERIT"],
        "trustee": "21474836993",
        "trustee_details": {
          "id_type": "SMB_SID",
          "id_value": "S-1-5-21-..."
        },
        "rights": ["READ", "EXECUTE", "SYNCHRONIZE"]
      }
    ]
  }
}
```

**PUT Request Format** (no wrapper):
```json
{
  "control": ["PRESENT"],
  "posix_special_permissions": [],
  "aces": [...]
}
```

### ACE Canonical Ordering (Critical)
Windows NTFS requires ACEs in canonical order:
1. **Explicit DENY** ACEs (no INHERITED flag)
2. **Explicit ALLOW** ACEs (no INHERITED flag)
3. **Inherited DENY** ACEs (with INHERITED flag)
4. **Inherited ALLOW** ACEs (with INHERITED flag)

### Existing grumpwalk Infrastructure
- NFSv4-style ACE formatting: `qacl_flags_to_nfsv4()`, `qacl_rights_to_nfsv4()`, `qacl_trustee_to_nfsv4()`
- API methods: `get_file_acl()`, `set_file_acl()` in modules/client.py
- Tree operations: `apply_acl_to_tree()` for recursive propagation
- Trustee parsing: `parse_trustee()` for user input
- Progress tracking and error handling patterns established

## Design Decisions (User Confirmed)

1. **Duplicate ACE handling**: Merge rights into existing ACE (same type+trustee)
2. **Empty ACE after revoke**: Remove the ACE entirely
3. **Inherited ACE modification**: Auto-break inheritance at starting path, establish new inheritance chain
4. **Flag naming**: `--add-rights` / `--remove-rights` (consistent with --add-ace / --remove-ace)

## Proposed CLI Interface

### 1. Remove ACE(s)
```bash
# Remove any ACE matching type:trustee pattern
--remove-ace 'Allow:Everyone'
--remove-ace 'Deny:uid:1001'
--remove-ace 'Allow:DOMAIN\\jsmith'

# Multiple removals (processed in order)
--remove-ace 'Allow:Everyone' --remove-ace 'Deny:Guest'
```

### 2. Add ACE(s)
```bash
# Format: Type:Flags:Trustee:Rights
--add-ace 'Allow:fd:jsmith:rwx'      # fd = file+dir inherit
--add-ace 'Deny::Everyone:w'         # No inheritance flags

# Multiple additions (inserted in canonical order)
--add-ace 'Deny::baduser:rwx' --add-ace 'Allow:fd:gooduser:rx'

# If ACE with same type+trustee exists, rights are merged
```

### 3. Modify Rights on Existing ACE(s)
```bash
# Add rights to matching ACE(s)
--add-rights 'Allow:Everyone:r'      # Add read right to Allow:Everyone ACE
--add-rights 'Allow:jsmith:wax'      # Add write, append, execute

# Remove rights from matching ACE(s)
--remove-rights 'Allow:Everyone:w'   # Remove write from Allow:Everyone ACE
--remove-rights 'Deny:Guest:rx'      # Remove read, execute from Deny:Guest

# If all rights removed, ACE is deleted
```

### 4. Supporting Flags
```bash
--propagate-ace-changes              # Apply to all children (inherits modified ACL)
--ace-dry-run                        # Show what would change without applying
--ace-backup FILE                    # Save original ACLs to JSON file before modification
```

## ACE Pattern Matching Syntax

### Trustee Formats (reuse existing parse_trustee logic)
- `Everyone` or `EVERYONE@` - Well-known Everyone group
- `uid:1001` - NFS UID
- `gid:100` - NFS GID
- `DOMAIN\\user` - AD user (NetBIOS format)
- `user@domain.com` - AD user (UPN format)
- `S-1-5-21-...` - SID directly
- `jsmith` - Plain name (resolved via identity API)

### Rights (NFSv4 shorthand)
- `r` = READ, `w` = MODIFY, `a` = EXTEND, `x` = EXECUTE
- `d` = DELETE, `D` = DELETE_CHILD, `t` = READ_ATTR, `T` = WRITE_ATTR
- `n` = READ_EA, `N` = WRITE_EA, `c` = READ_ACL, `C` = WRITE_ACL
- `o` = CHANGE_OWNER, `y` = SYNCHRONIZE
- Common shortcuts: `rwx` (read/write/execute), `rx` (read/execute)

### Flags (NFSv4 shorthand)
- `f` = OBJECT_INHERIT, `d` = CONTAINER_INHERIT
- `n` = NO_PROPAGATE_INHERIT, `i` = INHERIT_ONLY
- `I` = INHERITED (use with caution)

## Implementation Architecture

### New Functions in grumpwalk.py

```python
def parse_ace_pattern(pattern: str) -> dict:
    """
    Parse ACE pattern strings into structured dict.

    Formats:
    - 'Type:Trustee' for removal/rights modification (e.g., 'Allow:Everyone')
    - 'Type:Flags:Trustee:Rights' for adding (e.g., 'Allow:fd:jsmith:rwx')

    Returns: {type, flags, trustee, rights, trustee_auth_id}
    """

def match_ace(ace: dict, pattern: dict) -> bool:
    """Check if ACE matches pattern (by type and trustee)."""

def nfsv4_rights_to_qacl(rights_str: str) -> List[str]:
    """Convert 'rwx' to ['READ', 'MODIFY', 'EXECUTE']."""

def nfsv4_flags_to_qacl(flags_str: str) -> List[str]:
    """Convert 'fd' to ['OBJECT_INHERIT', 'CONTAINER_INHERIT']."""

def sort_aces_canonical(aces: List[dict]) -> List[dict]:
    """Sort ACEs into canonical order (deny before allow, explicit before inherited)."""

def break_inheritance(acl: dict) -> dict:
    """
    Break inheritance at this path:
    1. Add DACL_PROTECTED to control flags
    2. Remove INHERITED flag from all ACEs (they become explicit)
    3. Remove AUTO_INHERIT from control
    """

def apply_ace_modifications(
    acl: dict,
    remove_patterns: List[dict],
    add_aces: List[dict],
    add_rights_patterns: List[dict],
    remove_rights_patterns: List[dict]
) -> Tuple[dict, dict]:
    """
    Apply all modifications to ACL in memory.
    Returns: (modified_acl, stats_dict)
    """

async def apply_ace_changes_to_tree(
    client, session, path: str,
    remove_patterns, add_aces, add_rights_patterns, remove_rights_patterns,
    propagate: bool, progress: bool, dry_run: bool, backup_file: str
) -> dict:
    """
    Main entry point for ACE modifications.

    1. Get ACL at starting path
    2. If modifying inherited ACEs: break inheritance, add DACL_PROTECTED
    3. Apply modifications
    4. PUT modified ACL
    5. If propagate: walk children and apply inherited version
    """
```

### Processing Order (within apply_ace_modifications)
1. **Break inheritance** if any inherited ACEs will be modified
2. **Remove** matching ACEs
3. **Remove rights** from remaining ACEs (delete ACE if empty)
4. **Add rights** to matching ACEs (merge)
5. **Add new ACEs** (merge if duplicate type+trustee)
6. **Re-sort** into canonical order

### Inheritance Handling Logic
```python
def needs_inheritance_break(acl: dict, patterns: List[dict]) -> bool:
    """Check if any pattern targets an inherited ACE."""
    for ace in acl.get('aces', []):
        if 'INHERITED' in ace.get('flags', []):
            for pattern in patterns:
                if match_ace(ace, pattern):
                    return True
    return False

def break_inheritance(acl: dict) -> dict:
    """
    Convert inherited ACEs to explicit, block future inheritance.
    - Remove 'INHERITED' flag from all ACEs
    - Add 'DACL_PROTECTED' to control (blocks inheritance from parent)
    - Keep 'PRESENT' in control
    """
```

### Propagation to Children
When `--propagate-ace-changes` is used:
1. Modified ACL at starting path has `DACL_PROTECTED` (new parent)
2. Children inherit via tree walk with `mark_inherited=True`
3. Reuses existing `apply_acl_to_tree()` pattern

## Files to Modify

### grumpwalk.py
- **Lines ~3280-3400**: Add new argument group "Feature: ACE Manipulation"
  - `--remove-ace`, `--add-ace`, `--add-rights`, `--remove-rights`
  - `--propagate-ace-changes`, `--ace-dry-run`, `--ace-backup`
- **Lines ~78-550**: Add new ACE manipulation functions (near existing ACL functions)
- **Lines ~1768-2920**: Add ACE operation handling in `main_async()`

### modules/client.py
- May need `resolve_trustee_to_auth_id()` helper (or reuse identity expansion)

## Verification Plan

### Manual Testing on qq.qumulotest.local

```bash
# 1. Create test directory structure
# (manually or via qq CLI)

# 2. Test --remove-ace
./grumpwalk.py --host qq.qumulotest.local --path /test/dir \
    --remove-ace 'Allow:Everyone' --ace-dry-run

# 3. Test --add-ace with canonical ordering
./grumpwalk.py --host qq.qumulotest.local --path /test/dir \
    --add-ace 'Deny::baduser:w' --add-ace 'Allow:fd:gooduser:rx' --ace-dry-run

# 4. Test --add-rights / --remove-rights
./grumpwalk.py --host qq.qumulotest.local --path /test/dir \
    --add-rights 'Allow:Everyone:x' --ace-dry-run

# 5. Test inheritance breaking
./grumpwalk.py --host qq.qumulotest.local --path /test/inherited_dir \
    --remove-ace 'Allow:Domain Users' --ace-dry-run

# 6. Test propagation
./grumpwalk.py --host qq.qumulotest.local --path /test/parent \
    --add-ace 'Allow:fd:newuser:rx' --propagate-ace-changes --progress

# 7. Test backup
./grumpwalk.py --host qq.qumulotest.local --path /test/dir \
    --remove-ace 'Allow:Everyone' --ace-backup backup.json
```

### Edge Cases to Verify
- Remove non-existent ACE: warn, no error
- Add ACE with same type+trustee: merge rights
- Remove all rights from ACE: ACE deleted
- Empty ACL after all removals: warn user
- Invalid trustee name: error with helpful message
- Dry run shows accurate preview

## Implementation Steps

1. **Create design_docs directory** and save this plan for future reference
2. **Add argument parsing** (~30 lines) in grumpwalk.py
3. **Implement ACE pattern parsing** functions
4. **Implement ACE manipulation** functions (sort, break inheritance, modify)
5. **Integrate into main_async()** with existing ACL operation flow
6. **Test on qq.qumulotest.local** using dry-run first
7. **Test propagation** with real ACL changes
