"""
Auto-tuning module for grumpwalk.

Detects system resources and generates optimal performance settings.
Profile is saved to 'tuning-profile' on first run.
"""

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Tuple

# Profile version for future compatibility
# Bumped to 2 when the recommended concurrency was lowered. A profile written
# before that still carries the old, much higher values, so it is retired on
# upgrade rather than reused.
PROFILE_VERSION = 2
PROFILE_FILENAME = "tuning-profile"
PREVIOUS_PROFILE_FILENAME = "tuning-profile.previous"


def detect_platform() -> Tuple[str, bool]:
    """
    Detect the operating system and whether running under WSL.

    Returns:
        Tuple of (os_name, is_wsl)
        os_name: 'darwin', 'linux', 'windows'
        is_wsl: True if running under Windows Subsystem for Linux
    """
    platform = sys.platform

    if platform == 'darwin':
        return ('darwin', False)

    elif platform == 'win32':
        return ('windows', False)

    elif platform.startswith('linux'):
        # Check for WSL by examining /proc/version
        is_wsl = False
        try:
            with open('/proc/version', 'r') as f:
                version_info = f.read().lower()
                if 'microsoft' in version_info or 'wsl' in version_info:
                    is_wsl = True
        except (FileNotFoundError, PermissionError):
            pass
        return ('linux', is_wsl)

    else:
        # Unknown platform, treat as Linux
        return ('linux', False)


def detect_available_memory() -> float:
    """
    Detect available system memory in gigabytes.

    Returns:
        Available memory in GB (float)
    """
    try:
        # Try cross-platform approach using os.sysconf (Unix/Linux/macOS)
        if hasattr(os, 'sysconf'):
            page_size = os.sysconf('SC_PAGE_SIZE')
            total_pages = os.sysconf('SC_PHYS_PAGES')
            total_bytes = page_size * total_pages
            return total_bytes / (1024 ** 3)
    except (ValueError, OSError):
        pass

    # Windows fallback using ctypes
    if sys.platform == 'win32':
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            c_ulonglong = ctypes.c_ulonglong

            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ('dwLength', ctypes.c_ulong),
                    ('dwMemoryLoad', ctypes.c_ulong),
                    ('ullTotalPhys', c_ulonglong),
                    ('ullAvailPhys', c_ulonglong),
                    ('ullTotalPageFile', c_ulonglong),
                    ('ullAvailPageFile', c_ulonglong),
                    ('ullTotalVirtual', c_ulonglong),
                    ('ullAvailVirtual', c_ulonglong),
                    ('ullAvailExtendedVirtual', c_ulonglong),
                ]

            memory_status = MEMORYSTATUSEX()
            memory_status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            if kernel32.GlobalMemoryStatusEx(ctypes.byref(memory_status)):
                return memory_status.ullTotalPhys / (1024 ** 3)
        except Exception:
            pass

    # Default fallback: assume 8GB
    return 8.0


def detect_file_descriptor_limit() -> int:
    """
    Detect the file descriptor limit for the current process.

    Returns:
        Soft limit on file descriptors (int)
    """
    # Unix/Linux/macOS
    try:
        import resource
        soft_limit, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        return soft_limit
    except (ImportError, ValueError):
        pass

    # Windows doesn't have the same fd limit concept
    if sys.platform == 'win32':
        # Windows has a higher practical limit
        return 8192

    # Default fallback
    return 256


def get_platform_multiplier(os_name: str, is_wsl: bool) -> float:
    """
    Get the performance multiplier for the detected platform.

    Args:
        os_name: Platform name ('darwin', 'linux', 'windows')
        is_wsl: Whether running under WSL

    Returns:
        Multiplier (0.0-1.0) to apply to base concurrency values
    """
    if is_wsl:
        return 0.75  # WSL shares memory with Windows host

    multipliers = {
        'linux': 1.0,    # Best async performance
        'darwin': 0.8,   # More aggressive memory pressure
        'windows': 0.7,  # IOCP overhead
    }

    return multipliers.get(os_name, 0.8)


# Roughly how much memory each concurrent directory read costs, measured on a
# 71M-file tree: peak RSS rose from 171 MB at 25 concurrent reads to 818 MB at
# 400, so each one holds on to about 1.7 MB while it is in flight.
MB_PER_CONCURRENT_READ = 1.7


def calculate_base_concurrency(memory_gb: float) -> Dict[str, int]:
    """
    Calculate base concurrency values from available memory.

    Reading directories concurrently is what drives grumpwalk's memory use, and
    measurements across a 71-million-file tree found no throughput gained above
    about 25-50 concurrent reads -- on both a 6ms link and a 300ms one -- while
    memory kept climbing with every extra one. The defaults are therefore low
    and barely vary with RAM: more memory does not make extra concurrency
    useful, it only makes it affordable.

    ACL and metadata operations are counted separately. Those send small
    requests and hold nothing between them, so they are not part of the memory
    problem and stay high enough to keep bulk permission changes fast.

    Args:
        memory_gb: Available system memory in GB

    Returns:
        Dict with base values for max_concurrent, connector_limit, acl_concurrency
    """
    if memory_gb < 2:
        walk, acl = 10, 50
    elif memory_gb < 4:
        walk, acl = 15, 50
    else:
        walk, acl = 25, 100

    return {
        'max_concurrent': walk,
        # The pool is shared with ACL/metadata work, so it has to cover both.
        'connector_limit': max(walk, acl),
        'acl_concurrency': acl,
    }


# Caps per profile. 'aggressive' exists for unusual environments (very high
# latency, or a cluster that rewards more parallelism); measurements on the
# clusters tested showed no benefit above 50 concurrent directory reads.
PROFILE_CAPS = {
    'conservative': {'max_concurrent': 15, 'connector_limit': 50, 'acl_concurrency': 50},
    'balanced': {'max_concurrent': 25, 'connector_limit': 100, 'acl_concurrency': 100},
    'aggressive': {'max_concurrent': 50, 'connector_limit': 200, 'acl_concurrency': 200},
}


def calculate_recommended_settings(
    memory_gb: float,
    os_name: str,
    is_wsl: bool,
    fd_limit: int,
    profile: str = 'balanced'
) -> Dict[str, int]:
    """
    Calculate recommended settings based on system characteristics.

    Values are capped low on purpose: measured throughput stopped improving
    above roughly 25-50 concurrent directory reads, while memory kept rising
    with each one, so the caps trade an unmeasurable amount of speed for a
    large amount of memory. See calculate_base_concurrency for the numbers.

    Args:
        memory_gb: Available memory in GB
        os_name: Platform name
        is_wsl: Whether running under WSL
        fd_limit: File descriptor limit
        profile: Tuning profile ('conservative', 'balanced', 'aggressive')

    Returns:
        Dict with recommended max_concurrent, connector_limit, acl_concurrency
    """
    # Get base values from memory
    base = calculate_base_concurrency(memory_gb)

    # Apply platform multiplier
    platform_mult = get_platform_multiplier(os_name, is_wsl)

    # Apply profile multiplier (scales within profile caps)
    profile_multipliers = {
        'conservative': 0.8,
        'balanced': 1.0,
        'aggressive': 1.5,
    }
    profile_mult = profile_multipliers.get(profile, 1.0)

    # Calculate values with both multipliers. The floor is deliberately small:
    # the recommended range is now 10-50, so a larger floor would quietly
    # discard the settings chosen for small machines.
    final_mult = platform_mult * profile_mult
    recommended = {
        'max_concurrent': max(5, int(base['max_concurrent'] * final_mult)),
        'connector_limit': max(5, int(base['connector_limit'] * final_mult)),
        'acl_concurrency': max(5, int(base['acl_concurrency'] * final_mult)),
    }

    # Apply profile caps (cluster/network is typically the bottleneck)
    caps = PROFILE_CAPS.get(profile, PROFILE_CAPS['balanced'])
    for key in recommended:
        recommended[key] = min(recommended[key], caps[key])

    # Also cap at file descriptor limit (leave headroom for other operations)
    fd_cap = max(25, fd_limit - 50)
    recommended['max_concurrent'] = min(recommended['max_concurrent'], fd_cap)
    recommended['connector_limit'] = min(recommended['connector_limit'], fd_cap)

    return recommended


def get_profile_path() -> Path:
    """
    Get the path to the tuning profile file.

    Returns:
        Path to tuning-profile in the grumpwalk directory
    """
    # Profile lives in the same directory as grumpwalk.py
    script_dir = Path(__file__).parent.parent
    return script_dir / PROFILE_FILENAME


def get_previous_profile_path() -> Path:
    """
    Get the path where a retired tuning profile is kept.

    Returns:
        Path to tuning-profile.previous in the grumpwalk directory
    """
    return get_profile_path().parent / PREVIOUS_PROFILE_FILENAME


def retire_outdated_profile() -> Optional[Dict]:
    """
    Set aside a tuning profile written by an older version of grumpwalk.

    The old settings are copied to tuning-profile.previous and the profile is
    removed, so the next run measures the machine again and picks up the
    current (much lower) concurrency defaults. Nothing is lost: the caller
    reports where the old values went, and a user who wants them back can pass
    them on the command line or copy the file back.

    Returns:
        The retired profile dict, or None if there was nothing to retire.
    """
    profile_path = get_profile_path()

    if not profile_path.exists():
        return None

    try:
        with open(profile_path, 'r') as f:
            old = json.load(f)
    except (json.JSONDecodeError, IOError):
        return None

    if old.get('version') == PROFILE_VERSION:
        return None

    try:
        with open(get_previous_profile_path(), 'w') as f:
            json.dump(old, f, indent=2)
        profile_path.unlink()
    except IOError:
        # Could not set it aside; leave it alone rather than silently
        # discarding the user's settings.
        return None

    return old


def format_retired_profile_notice(old: Dict) -> str:
    """
    Explain what happened to a retired profile and how to get it back.

    Args:
        old: The retired profile dict

    Returns:
        Formatted, user-facing message
    """
    rec = old.get('recommended', {})
    lines = [
        "Your tuning settings have been reset.",
        "",
        "grumpwalk now uses far fewer simultaneous directory reads. Testing on a",
        "71-million-file system found no speed gained from the previous, higher",
        "settings, while they used several times more memory -- enough to run a",
        "large crawl out of memory.",
        "",
        "Your previous settings were:",
    ]
    for key in ('max_concurrent', 'connector_limit', 'acl_concurrency'):
        if key in rec:
            lines.append(f"  --{key.replace('_', '-')} {rec[key]}")
    lines += [
        "",
        f"They are saved in: {get_previous_profile_path()}",
        "To use them for a single run, pass them on the command line.",
    ]
    return '\n'.join(lines)


def load_tuning_profile() -> Optional[Dict]:
    """
    Load the tuning profile from disk.

    Returns:
        Profile dict if exists and valid, None otherwise
    """
    profile_path = get_profile_path()

    if not profile_path.exists():
        return None

    try:
        with open(profile_path, 'r') as f:
            profile = json.load(f)

        # Validate profile version
        if profile.get('version') != PROFILE_VERSION:
            return None

        # Validate required fields
        required = ['platform', 'recommended', 'profile']
        if not all(key in profile for key in required):
            return None

        return profile

    except (json.JSONDecodeError, IOError):
        return None


def save_tuning_profile(profile: Dict) -> bool:
    """
    Save the tuning profile to disk.

    Args:
        profile: Profile dict to save

    Returns:
        True if saved successfully, False otherwise
    """
    profile_path = get_profile_path()

    try:
        with open(profile_path, 'w') as f:
            json.dump(profile, f, indent=2)
        return True
    except IOError:
        return False


def generate_tuning_profile(profile_name: str = 'balanced') -> Dict:
    """
    Generate a new tuning profile based on current system.

    Args:
        profile_name: Profile type ('conservative', 'balanced', 'aggressive')

    Returns:
        Complete profile dict
    """
    os_name, is_wsl = detect_platform()
    memory_gb = detect_available_memory()
    fd_limit = detect_file_descriptor_limit()

    recommended = calculate_recommended_settings(
        memory_gb=memory_gb,
        os_name=os_name,
        is_wsl=is_wsl,
        fd_limit=fd_limit,
        profile=profile_name
    )

    profile = {
        'version': PROFILE_VERSION,
        'created': datetime.now(timezone.utc).isoformat(),
        'platform': {
            'os': os_name,
            'is_wsl': is_wsl,
            'memory_gb': round(memory_gb, 1),
            'fd_limit': fd_limit,
        },
        'recommended': recommended,
        'profile': profile_name,
    }

    return profile


def get_platform_display_name(os_name: str, is_wsl: bool) -> str:
    """
    Get human-readable platform name for display.

    Args:
        os_name: Platform name
        is_wsl: Whether running under WSL

    Returns:
        Display string like "Linux" or "Linux (WSL)"
    """
    names = {
        'darwin': 'macOS',
        'linux': 'Linux',
        'windows': 'Windows',
    }

    display = names.get(os_name, os_name.capitalize())

    if is_wsl:
        display += ' (WSL)'

    return display


def format_profile_summary(profile: Dict) -> str:
    """
    Format profile for display to user.

    Args:
        profile: Profile dict

    Returns:
        Formatted multi-line string
    """
    platform = profile['platform']
    recommended = profile['recommended']

    os_display = get_platform_display_name(platform['os'], platform['is_wsl'])

    lines = [
        f"  Platform:        {os_display}",
        f"  Memory:          {platform['memory_gb']:.1f} GB",
        f"  FD Limit:        {platform['fd_limit']}",
        f"  Profile:         {profile['profile']}",
        "",
        f"  max-concurrent:  {recommended['max_concurrent']}",
        f"  connector-limit: {recommended['connector_limit']}",
        f"  acl-concurrency: {recommended['acl_concurrency']}",
    ]

    return '\n'.join(lines)


# Benchmark configuration
# Levels start low because that is where the useful range turned out to be.
BENCHMARK_CONCURRENCY_LEVELS = [10, 25, 50, 100, 200]

# Each level runs for a fixed time rather than a fixed number of files. A file
# count is the wrong yardstick: on a directory-heavy filesystem, reaching a set
# number of files means visiting far more directories and can take minutes,
# while on a small directory it finishes instantly and measures nothing.
#
# The first seconds are discarded. A walk starts knowing only the root and
# discovers work as it goes, so early on there is not enough queued to keep
# many requests busy -- timing from a standing start flatters high concurrency
# by measuring how quickly it fills up rather than how fast it then runs.
BENCHMARK_WARMUP_SECONDS = 5.0
BENCHMARK_MEASURE_SECONDS = 10.0
BENCHMARK_SECONDS_PER_LEVEL = BENCHMARK_WARMUP_SECONDS + BENCHMARK_MEASURE_SECONDS
BENCHMARK_FILE_LIMIT = 500000  # Backstop so a tiny tree still ends promptly

# How much throughput a higher level must add to be worth its extra memory.
# Anything within this margin of the best result counts as a tie, and the
# cheapest tied level wins.
BENCHMARK_TIE_MARGIN = 0.05

# How much faster than the standard setting a higher one has to be before it is
# worth the memory. Set high on purpose. Repeating the same benchmark on the
# same filesystem produced 27,864 obj/sec and then 7,389 obj/sec for the very
# same setting -- a walk speeds up and slows down depending on which part of the
# tree it happens to be in -- so anything short of a large, obvious margin is
# indistinguishable from where the walk got to. The extra memory, by contrast,
# is paid on every run afterwards.
BENCHMARK_UPGRADE_FACTOR = 2.0

# A level that finishes this fast has measured startup noise rather than
# throughput. On a small directory the same level can vary threefold between
# runs, which is more than enough to pick a setting for the wrong reason.
BENCHMARK_MIN_SECONDS = 2.0


def benchmark_is_reliable(results: list) -> bool:
    """
    Whether a benchmark ran long enough for its numbers to mean anything.

    Args:
        results: List of benchmark result dicts

    Returns:
        True if the tests ran long enough to compare
    """
    if not results:
        return False
    return max(r['time'] for r in results) >= BENCHMARK_MIN_SECONDS


def current_rss_mb() -> Optional[float]:
    """
    Current resident memory of this process in MB, or None if unavailable.

    Used to show what each benchmark level costs in memory, since that is the
    thing that actually differs between them.
    """
    try:
        # Linux: statm reports pages
        with open('/proc/self/statm', 'r') as f:
            pages = int(f.read().split()[1])
        return pages * os.sysconf('SC_PAGE_SIZE') / (1024 * 1024)
    except (IOError, IndexError, ValueError, AttributeError, OSError):
        pass

    try:
        # macOS and other BSDs
        out = subprocess.run(
            ['ps', '-o', 'rss=', '-p', str(os.getpid())],
            capture_output=True, text=True, timeout=5,
        )
        return int(out.stdout.strip()) / 1024
    except (subprocess.SubprocessError, ValueError, OSError):
        return None


def format_benchmark_results(results: list) -> str:
    """
    Format benchmark results for display.

    Args:
        results: List of dicts with 'concurrent', 'rate', 'time' keys

    Returns:
        Formatted table string
    """
    if not results:
        return "  No benchmark results"

    has_memory = any(r.get('rss_mb') for r in results)
    if has_memory:
        lines = [
            "  Concurrent | Rate (obj/sec) | Time   | Memory",
            "  -----------|----------------|--------|-------",
        ]
    else:
        lines = [
            "  Concurrent | Rate (obj/sec) | Time",
            "  -----------|----------------|------",
        ]

    chosen = suggest_from_benchmark(results)['max_concurrent']

    for r in results:
        marker = " <- recommended" if r['concurrent'] == chosen else ""
        if has_memory:
            mem = f"{r['rss_mb']:,.0f} MB" if r.get('rss_mb') else "n/a"
            lines.append(
                f"  {r['concurrent']:>10} | {r['rate']:>14,.0f} | {r['time']:>5.1f}s | {mem:>6}{marker}"
            )
        else:
            lines.append(
                f"  {r['concurrent']:>10} | {r['rate']:>14,.0f} | {r['time']:.1f}s{marker}"
            )

    if not benchmark_is_reliable(results):
        lines += [
            "",
            "  These tests finished too quickly to compare -- the differences above",
            "  are startup noise, not throughput. Standard settings were kept.",
            "  Benchmark against a larger directory for a meaningful result.",
        ]
    else:
        lines += [
            "",
            "  Rates vary between runs depending on which part of the filesystem",
            "  each test reaches, so a higher setting is only recommended when it",
            "  is far faster -- not merely faster. Memory, on the other hand, is",
            "  spent on every run.",
        ]

    return '\n'.join(lines)


def suggest_from_benchmark(results: list) -> Dict[str, int]:
    """
    Suggest settings from benchmark results.

    Picks the lowest concurrency that is within BENCHMARK_TIE_MARGIN of the
    fastest result, rather than the fastest result itself. Measured rates
    across these levels usually differ by only a few percent -- which is
    within run-to-run noise -- while memory keeps rising with every level, so
    taking the fastest number would trade real memory for an imagined gain.

    Args:
        results: List of benchmark result dicts

    Returns:
        Dict with suggested max_concurrent, connector_limit, acl_concurrency
    """
    base = calculate_base_concurrency(detect_available_memory())
    standard = base['max_concurrent']
    acl = base['acl_concurrency']

    def settings(level: int) -> Dict[str, int]:
        # ACL and metadata operations do not buffer directory listings, so they
        # are not held to the walk's limit.
        return {
            'max_concurrent': level,
            'connector_limit': max(level, acl),
            'acl_concurrency': acl,
        }

    if not results or not benchmark_is_reliable(results):
        # Nothing measured, or every test finished too quickly to compare.
        # Keep the standard settings rather than reading noise.
        return settings(standard)

    best_rate = max(r['rate'] for r in results)

    # Cheapest level that is not meaningfully slower than the best.
    tied = [r for r in results if r['rate'] >= best_rate * (1 - BENCHMARK_TIE_MARGIN)]
    optimal = min(tied, key=lambda r: r['concurrent'])['concurrent']

    if optimal <= standard:
        return settings(optimal)

    # Going above the standard setting costs memory on every future run, so it
    # takes a decisive win rather than a good-looking one. Repeated timings of
    # the same filesystem varied by more than the gaps between these levels,
    # because a walk speeds up and slows down depending on which part of the
    # tree it is in, so a modest lead here is not evidence of anything.
    at_standard = [r['rate'] for r in results if r['concurrent'] <= standard]
    if at_standard and best_rate < max(at_standard) * BENCHMARK_UPGRADE_FACTOR:
        return settings(standard)

    return settings(optimal)
