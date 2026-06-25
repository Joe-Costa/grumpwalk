"""
Filename transform engine for grumpwalk's --rename-to.

Two pattern styles are supported, chosen by the shape of the pattern:

1. Brace substitution (pattern starts with '{'):
   A chain of one or more ``{MATCH|REPLACE}`` tokens applied, left to right, to
   the basename. Text the tokens do not touch passes through unchanged.

       {my|our}            my_file_1.jpg -> our_file_1.jpg
       {IMG_*|photo_*}     IMG_2024.jpg  -> photo_2024.jpg   (* captures)
       {(\\d+)|v\\1}         scan12.tif    -> scanv12.tif      (regex + backref)
       {_old|}             a_old.txt     -> a.txt            (empty REPLACE deletes)

   Inside MATCH, ``*`` and ``?`` are glob wildcards that capture (``*`` -> ``(.*)``,
   ``?`` -> ``(.)``); everything else is treated as a regular expression. Inside
   REPLACE, ``*`` and ``?`` are filled, in order, from those captures, and ``\\1``
   style backreferences are honored. All non-overlapping matches are replaced.

2. Whole-name template (pattern does NOT start with '{'):
   The pattern is the entire new name. ``*`` and ``?`` are filled, in order, from
   the wildcards of the first ``--name`` glob that matches the basename.

       --name 'my_*'  --rename-to 'our_*'    my_file_1.jpg -> our_file_1.jpg

   A pattern with no wildcards is a literal new name.

build_renamer() validates the pattern once and returns a callable
``basename -> new_basename``. The callable returns None when it cannot produce a
name for a given input (template mode with no matching glob); the caller treats
that as a skip. Output validity (no '/', non-empty, no-op detection) is the
caller's responsibility so move-vs-rename context can be considered.
"""

import re
from typing import Callable, List, Optional, Tuple


class RenamePatternError(ValueError):
    """Raised when a --rename-to pattern is malformed (reported once, at startup)."""


def _has_substitution_token(pattern: str) -> bool:
    """True if the pattern contains a balanced ``{...|...}`` token.

    Used to catch a substitution token written somewhere other than the start
    (e.g. ``pre{a|b}``), which is almost always a mistake, rather than silently
    treating it as a literal name. A ``{...}`` with no top-level ``|`` (such as a
    regex quantifier ``\\d{2}`` or a literal ``file{1}.txt``) is not a token.
    """
    depth = 0
    sep_at_depth1 = False
    for c in pattern:
        if c == "{":
            if depth == 0:
                sep_at_depth1 = False
            depth += 1
        elif c == "}":
            if depth == 1 and sep_at_depth1:
                return True
            if depth > 0:
                depth -= 1
        elif c == "|" and depth == 1:
            sep_at_depth1 = True
    return False


def _parse_substitution_tokens(pattern: str) -> List[Tuple[str, str]]:
    """Split a brace-substitution pattern into (match, replace) pairs.

    The pattern must be a concatenation of ``{...|...}`` tokens with nothing
    between or around them. Token boundaries are tracked by brace depth so that
    regex quantifier braces (e.g. ``\\d{2}``) inside a token are preserved; the
    MATCH/REPLACE separator is the first ``|`` at the token's top level.
    """
    tokens: List[Tuple[str, str]] = []
    i, n = 0, len(pattern)
    while i < n:
        if pattern[i] != "{":
            raise RenamePatternError(
                f"invalid substitution pattern near {pattern[i:]!r}: "
                "expected only {match|replace} tokens"
            )
        depth = 0
        sep = -1          # index of the separating '|' (depth 1)
        j = i
        while j < n:
            c = pattern[j]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    break
            elif c == "|" and depth == 1 and sep == -1:
                sep = j
            j += 1
        if depth != 0:
            raise RenamePatternError(f"unbalanced braces in pattern: {pattern!r}")
        if sep == -1:
            raise RenamePatternError(
                f"token {pattern[i:j + 1]!r} is missing a '|' separator"
            )
        match = pattern[i + 1:sep]
        replace = pattern[sep + 1:j]
        if match == "":
            raise RenamePatternError(
                f"token {pattern[i:j + 1]!r} has an empty match side"
            )
        tokens.append((match, replace))
        i = j + 1
    if not tokens:
        raise RenamePatternError("empty substitution pattern")
    return tokens


def _glob_match_to_regex(match: str) -> "re.Pattern":
    """Compile a substitution MATCH side into a regex.

    ``*`` and ``?`` become capturing groups; every other run of characters is
    passed through as-is (so regular expressions keep working). Greedy ``*`` is
    used to mirror shell-glob intuition.
    """
    out = []
    for c in match:
        if c == "*":
            out.append("(.*)")
        elif c == "?":
            out.append("(.)")
        else:
            out.append(c)
    try:
        return re.compile("".join(out))
    except re.error as exc:
        raise RenamePatternError(f"invalid regex in match {match!r}: {exc}")


def _compile_replacement(replace: str) -> Callable[[Tuple[Optional[str], ...]], str]:
    """Parse a REPLACE side into a renderer that builds output from match groups.

    Using a function replacement (rather than an re.sub template string) avoids
    all backslash/`\\g<>` escaping hazards. ``*``/``?`` consume capture groups in
    order (1, 2, ...); ``\\N`` references group N explicitly; ``\\x`` is a literal
    x; everything else is literal. A reference past the available groups renders
    as empty. (Do not mix glob ``*`` with explicit regex groups in one token --
    positional and explicit numbering share the same space; use one or the other.)
    """
    instrs: List[Tuple[str, object]] = []   # ('lit', str) or ('grp', int)
    buf: List[str] = []
    pos = 0
    i, n = 0, len(replace)

    def flush():
        if buf:
            instrs.append(("lit", "".join(buf)))
            buf.clear()

    while i < n:
        c = replace[i]
        if c in "*?":
            flush()
            pos += 1
            instrs.append(("grp", pos))
            i += 1
        elif c == "\\" and i + 1 < n and replace[i + 1].isdigit():
            flush()
            instrs.append(("grp", int(replace[i + 1])))
            i += 2
        elif c == "\\" and i + 1 < n:
            buf.append(replace[i + 1])      # escaped literal (e.g. \\ -> \)
            i += 2
        else:
            buf.append(c)
            i += 1
    flush()

    def render(groups: Tuple[Optional[str], ...]) -> str:
        out = []
        for kind, val in instrs:
            if kind == "lit":
                out.append(val)
            else:
                idx = val - 1
                out.append(groups[idx] if 0 <= idx < len(groups) and groups[idx] is not None else "")
        return "".join(out)

    return render


def _build_substitution(pattern: str) -> Callable[[str], str]:
    tokens = _parse_substitution_tokens(pattern)
    compiled = [(_glob_match_to_regex(m), _compile_replacement(r)) for m, r in tokens]

    def rename(basename: str) -> str:
        name = basename
        for regex, render in compiled:
            name = regex.sub(lambda mo: render(mo.groups()), name)
        return name

    return rename


def _glob_to_capture_regex(glob: str) -> Optional["re.Pattern"]:
    """Translate a --name glob into a full-match regex with one group per wildcard.

    Returns None if the pattern contains no ``*``/``?`` wildcard (nothing to
    capture from, so it cannot drive a template).
    """
    if "*" not in glob and "?" not in glob:
        return None
    out = ["^"]
    for c in glob:
        if c == "*":
            out.append("(.*)")
        elif c == "?":
            out.append("(.)")
        else:
            out.append(re.escape(c))
    out.append("$")
    try:
        return re.compile("".join(out))
    except re.error:
        return None


def _count_template_wildcards(template: str) -> int:
    return sum(1 for c in template if c in "*?")


def _build_template(pattern: str, name_patterns: List[str]) -> Callable[[str], Optional[str]]:
    n_wild = _count_template_wildcards(pattern)
    if n_wild == 0:
        # Literal new name; same for every object.
        return lambda basename: pattern

    capture_regexes = [r for r in (_glob_to_capture_regex(p) for p in name_patterns) if r]
    if not capture_regexes:
        raise RenamePatternError(
            f"--rename-to {pattern!r} uses '*'/'?' but no --name glob has a wildcard "
            "to match against; use brace {old|new} syntax instead"
        )

    def rename(basename: str) -> Optional[str]:
        for regex in capture_regexes:
            m = regex.match(basename)
            if not m:
                continue
            groups = m.groups()
            if len(groups) < n_wild:
                # This glob cannot satisfy the template's wildcard count.
                continue
            out = []
            gi = 0
            for c in pattern:
                if c in "*?":
                    out.append(groups[gi])
                    gi += 1
                else:
                    out.append(c)
            return "".join(out)
        return None

    return rename


def build_renamer(
    rename_to: str,
    name_patterns: Optional[List[str]] = None,
) -> Callable[[str], Optional[str]]:
    """Validate a --rename-to pattern and return a basename transform.

    Raises RenamePatternError on a malformed pattern. The returned callable maps
    an input basename to a new basename, or to None when no transform applies
    (template mode with no matching glob).
    """
    if rename_to is None or rename_to == "":
        raise RenamePatternError("--rename-to pattern is empty")
    if rename_to.startswith("{"):
        return _build_substitution(rename_to)
    if _has_substitution_token(rename_to):
        raise RenamePatternError(
            f"{rename_to!r} looks like a substitution but does not start with '{{'; "
            "a substitution pattern must be a chain of {match|replace} tokens with "
            "nothing around them"
        )
    return _build_template(rename_to, name_patterns or [])
