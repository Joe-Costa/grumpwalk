"""
Auto-tuning module for grumpwalk.

Detects system resources and generates optimal performance settings.
Profile is saved to 'tuning-profile' on first run.
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Tuple

# Profile version for future compatibility
PROFILE_VERSION = 1
PROFILE_FILENAME = "tuning-profile"


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


def calculate_base_concurrency(memory_gb: float) -> Dict[str, int]:
    """
    Calculate base concurrency values from available memory.

    Args:
        memory_gb: Available system memory in GB

    Returns:
        Dict with base values for max_concurrent, connector_limit, acl_concurrency
    """
    if memory_gb < 4:
        return {'max_concurrent': 50, 'connector_limit': 50, 'acl_concurrency': 50}
    elif memory_gb < 8:
        return {'max_concurrent': 100, 'connector_limit': 100, 'acl_concurrency': 100}
    elif memory_gb < 16:
        return {'max_concurrent': 200, 'connector_limit': 200, 'acl_concurrency': 150}
    elif memory_gb < 32:
        return {'max_concurrent': 400, 'connector_limit': 400, 'acl_concurrency': 300}
    elif memory_gb < 64:
        return {'max_concurrent': 700, 'connector_limit': 700, 'acl_concurrency': 500}
    else:
        return {'max_concurrent': 1000, 'connector_limit': 1000, 'acl_concurrency': 800}


def calculate_recommended_settings(
    memory_gb: float,
    os_name: str,
    is_wsl: bool,
    fd_limit: int,
    profile: str = 'balanced'
) -> Dict[str, int]:
    """
    Calculate recommended settings based on system characteristics.

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
    multiplier = get_platform_multiplier(os_name, is_wsl)

    # Apply profile adjustment
    profile_multipliers = {
        'conservative': 0.6,
        'balanced': 1.0,
        'aggressive': 1.4,
    }
    profile_mult = profile_multipliers.get(profile, 1.0)

    # Calculate final values
    final_multiplier = multiplier * profile_mult

    recommended = {
        'max_concurrent': max(25, int(base['max_concurrent'] * final_multiplier)),
        'connector_limit': max(25, int(base['connector_limit'] * final_multiplier)),
        'acl_concurrency': max(25, int(base['acl_concurrency'] * final_multiplier)),
    }

    # Cap at file descriptor limit (leave headroom for other operations)
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
