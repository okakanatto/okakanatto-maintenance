"""版番号の比較（semver 風。PyPI・Cargo・npm の一般的な形式で使える範囲）。"""

from __future__ import annotations

import re

_V = re.compile(r"^v?(\d+(?:\.\d+)*)(?:[-+.]?([A-Za-z].*|\d*[A-Za-z].*))?$")


def parse(v: str) -> tuple[tuple[int, ...], str | None] | None:
    m = _V.match(str(v).strip())
    if not m:
        return None
    nums = tuple(int(x) for x in m.group(1).split("."))
    pre = m.group(2)
    if pre and pre.startswith("+"):
        pre = None  # ビルドメタデータ
    return nums, pre


def _key(p: tuple[tuple[int, ...], str | None]):
    nums, pre = p
    nums = nums + (0,) * (4 - len(nums)) if len(nums) < 4 else nums
    return (nums, 0 if pre else 1, pre or "")


def compare(a: str, b: str) -> int | None:
    pa, pb = parse(a), parse(b)
    if pa is None or pb is None:
        return None
    ka, kb = _key(pa), _key(pb)
    return (ka > kb) - (ka < kb)


def is_prerelease(v: str) -> bool:
    p = parse(v)
    return bool(p and p[1])


def classify(installed: str, latest: str) -> str:
    """same / patch / minor / major / newer / unknown。0.x の minor 差は破壊的変更として major に数える。"""
    pi, pl = parse(installed), parse(latest)
    if pi is None or pl is None:
        return "unknown"
    c = compare(installed, latest)
    if c == 0:
        return "same"
    if c is not None and c > 0:
        return "newer"
    ni, nl = pi[0] + (0, 0), pl[0] + (0, 0)
    if ni[0] != nl[0]:
        return "major"
    if ni[0] == 0 and ni[1] != nl[1]:
        return "major"
    if ni[1] != nl[1]:
        return "minor"
    return "patch"


def major_lag(installed: str, latest: str) -> int:
    pi, pl = parse(installed), parse(latest)
    if pi is None or pl is None:
        return 0
    return max(0, pl[0][0] - pi[0][0])


def max_version(versions: list[str], stable_only: bool = True) -> str | None:
    best = None
    for v in versions:
        p = parse(v)
        if p is None or (stable_only and p[1]):
            continue
        if best is None or _key(p) > _key(parse(best)):
            best = v
    return best
