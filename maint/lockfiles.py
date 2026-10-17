"""ロックファイル・依存定義の解析器。

各解析器は (packages, notes) を返す。notes には「解析できなかった行」など、
カバレッジを PARTIAL にすべき理由を書く。外部の内容は信頼しないので、型を確かめながら読む。
新しい形式を足すときは PARSERS に登録する（inventory.MANIFEST_PATTERNS の parser=True も合わせる）。
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass


@dataclass(frozen=True)
class Package:
    ecosystem: str  # OSV のエコシステム名（npm / crates.io / PyPI / Go / NuGet / Packagist）
    name: str
    version: str
    path: str  # どのファイルで見つかったか
    direct: bool | None = None  # 直接依存か（不明なら None）
    dev: bool | None = None  # 開発用依存か（不明なら None）


class ParseError(Exception):
    pass


def _json(raw: bytes):
    try:
        return json.loads(raw.decode("utf-8-sig"))
    except (ValueError, UnicodeDecodeError) as e:
        raise ParseError(f"JSON として読めません: {e}") from e


def _toml(raw: bytes):
    try:
        return tomllib.loads(raw.decode("utf-8-sig"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as e:
        raise ParseError(f"TOML として読めません: {e}") from e


def parse_npm_lock(raw: bytes, path: str) -> tuple[list[Package], list[str]]:
    d = _json(raw)
    if not isinstance(d, dict):
        raise ParseError("package-lock の形式ではありません")
    notes: list[str] = []
    out: list[Package] = []
    pkgs = d.get("packages")
    if isinstance(pkgs, dict):  # lockfileVersion 2/3
        root = pkgs.get("", {}) if isinstance(pkgs.get(""), dict) else {}
        direct = set((root.get("dependencies") or {}).keys()) | set((root.get("devDependencies") or {}).keys()) | set(
            (root.get("optionalDependencies") or {}).keys()
        )
        for key, meta in pkgs.items():
            if not key or not isinstance(meta, dict):
                continue
            if meta.get("link"):
                continue  # ワークスペース内リンク（レジストリのパッケージではない）
            if "node_modules/" not in key:
                continue  # ワークスペースのソース
            name = meta.get("name") or key.rsplit("node_modules/", 1)[1]
            ver = meta.get("version")
            if not isinstance(ver, str) or not ver:
                continue
            resolved = meta.get("resolved") or ""
            if isinstance(resolved, str) and resolved and not resolved.startswith("https://registry.npmjs.org/"):
                if resolved.startswith(("git", "file:", "http://")) or "github.com" in resolved:
                    notes.append(f"レジストリ外の依存（照合対象外）: {name}")
                    continue
            top = key.count("node_modules/") == 1
            out.append(Package("npm", name, ver, path, direct=(name in direct and top), dev=bool(meta.get("dev"))))
        return out, notes
    deps = d.get("dependencies")
    if isinstance(deps, dict):  # lockfileVersion 1

        def walk(tree: dict, top: bool):
            for name, meta in tree.items():
                if not isinstance(meta, dict):
                    continue
                ver = meta.get("version")
                if isinstance(ver, str) and re.match(r"^\d", ver):
                    out.append(Package("npm", name, ver, path, direct=None if top else False, dev=bool(meta.get("dev"))))
                elif isinstance(ver, str):
                    notes.append(f"レジストリ外の依存（照合対象外）: {name}")
                if isinstance(meta.get("dependencies"), dict):
                    walk(meta["dependencies"], False)

        walk(deps, True)
        notes.append("lockfileVersion 1: 直接依存かどうかは package.json と突き合わせないと分からない")
        return out, notes
    raise ParseError("packages / dependencies がありません")


def parse_cargo_lock(raw: bytes, path: str) -> tuple[list[Package], list[str]]:
    d = _toml(raw)
    notes: list[str] = []
    out: list[Package] = []
    for p in d.get("package", []) or []:
        if not isinstance(p, dict):
            continue
        name, ver, src = p.get("name"), p.get("version"), p.get("source")
        if not isinstance(name, str) or not isinstance(ver, str):
            continue
        if src is None:
            continue  # ワークスペース内のクレート自身
        if isinstance(src, str) and src.startswith(("registry+https://github.com/rust-lang/crates.io-index", "sparse+https://index.crates.io/")):
            out.append(Package("crates.io", name, ver, path))
        else:
            notes.append(f"crates.io 以外の取得元（照合対象外）: {name}")
    if not d.get("package"):
        notes.append("package エントリがありません")
    return out, notes


DEV_REQ_NAME = re.compile(r"(dev|test|lint|format|doc|ci|tool|check|bench)", re.I)
_REQ_LINE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*==\s*([A-Za-z0-9._+!-]+)\s*(;.*)?$")


def parse_requirements(raw: bytes, path: str) -> tuple[list[Package], list[str]]:
    out: list[Package] = []
    notes: list[str] = []
    unpinned = 0
    # requirements-dev.txt / requirements-test.txt 等は開発用とみなす（ファイル名だけが根拠。README に明記）
    dev = bool(DEV_REQ_NAME.search(path.rsplit("/", 1)[-1]))
    for line in raw.decode("utf-8-sig", "replace").splitlines():
        line = line.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-r", "-c", "--requirement", "--constraint")):
            notes.append(f"参照先ファイルは別途解析: {line}")
            continue
        if line.startswith("-"):
            continue
        line = line.split("--hash", 1)[0].strip().rstrip("\\").strip()
        m = _REQ_LINE.match(line)
        if m:
            out.append(Package("PyPI", m.group(1).lower(), m.group(3), path, direct=True, dev=dev))
        else:
            unpinned += 1
    if unpinned:
        notes.append(f"版が固定されていない行が {unpinned} 件（照合できない）")
    return out, notes


def parse_poetry_or_uv_lock(raw: bytes, path: str) -> tuple[list[Package], list[str]]:
    d = _toml(raw)
    out = []
    for p in d.get("package", []) or []:
        if isinstance(p, dict) and isinstance(p.get("name"), str) and isinstance(p.get("version"), str):
            src = p.get("source")
            if isinstance(src, dict) and any(k in src for k in ("editable", "virtual", "directory", "path")):
                continue
            out.append(Package("PyPI", p["name"].lower(), p["version"], path))
    return out, []


def parse_pipenv_lock(raw: bytes, path: str) -> tuple[list[Package], list[str]]:
    d = _json(raw)
    out = []
    for section, dev in (("default", False), ("develop", True)):
        for name, meta in (d.get(section) or {}).items():
            v = meta.get("version") if isinstance(meta, dict) else None
            if isinstance(v, str) and v.startswith("=="):
                out.append(Package("PyPI", name.lower(), v[2:], path, dev=dev))
    return out, []


def parse_go_mod(raw: bytes, path: str) -> tuple[list[Package], list[str]]:
    out = []
    in_block = False
    for line in raw.decode("utf-8", "replace").splitlines():
        s = line.split("//", 1)[0].strip()
        indirect = "// indirect" in line
        if s.startswith("require ("):
            in_block = True
            continue
        if in_block and s == ")":
            in_block = False
            continue
        if s.startswith("require "):
            s = s[len("require ") :].strip()
        elif not in_block:
            continue
        parts = s.split()
        if len(parts) >= 2 and parts[1].startswith("v"):
            out.append(Package("Go", parts[0], parts[1], path, direct=not indirect))
    return out, ["go.mod の require のみ（go.sum の全推移依存は未解析）"]


def parse_nuget_lock(raw: bytes, path: str) -> tuple[list[Package], list[str]]:
    d = _json(raw)
    out = []
    seen = set()
    for fw, deps in (d.get("dependencies") or {}).items():
        if not isinstance(deps, dict):
            continue
        for name, meta in deps.items():
            if isinstance(meta, dict) and isinstance(meta.get("resolved"), str) and meta.get("type") != "Project":
                k = (name, meta["resolved"])
                if k not in seen:
                    seen.add(k)
                    out.append(Package("NuGet", name, meta["resolved"], path, direct=meta.get("type") == "Direct"))
    return out, []


def parse_composer_lock(raw: bytes, path: str) -> tuple[list[Package], list[str]]:
    d = _json(raw)
    out = []
    for section, dev in (("packages", False), ("packages-dev", True)):
        for p in d.get(section) or []:
            if isinstance(p, dict) and isinstance(p.get("name"), str) and isinstance(p.get("version"), str):
                out.append(Package("Packagist", p["name"], p["version"].lstrip("v"), path, dev=dev))
    return out, []


PARSERS = {
    "npm-lock": parse_npm_lock,
    "cargo-lock": parse_cargo_lock,
    "pip-requirements": parse_requirements,
    "poetry-lock": parse_poetry_or_uv_lock,
    "uv-lock": parse_poetry_or_uv_lock,
    "pipenv-lock": parse_pipenv_lock,
    "go-mod": parse_go_mod,
    "nuget-lock": parse_nuget_lock,
    "composer-lock": parse_composer_lock,
}


# --- 直接依存の取得（依存更新の検査で使う） -----------------------------------


def npm_direct(raw: bytes) -> dict[str, dict]:
    """package.json → {name: {"spec": "^1.2.3", "dev": bool}}"""
    d = _json(raw)
    out: dict[str, dict] = {}
    for section, dev in (("dependencies", False), ("devDependencies", True), ("optionalDependencies", False)):
        for name, spec in (d.get(section) or {}).items():
            if isinstance(spec, str):
                out[name] = {"spec": spec, "dev": dev}
    return out


def cargo_direct(raw: bytes) -> dict[str, dict]:
    """Cargo.toml → {crate名: {"spec": "2.10.0", "dev": bool}}（target 別依存を含む）"""
    d = _toml(raw)
    out: dict[str, dict] = {}

    def take(table, dev: bool):
        for name, spec in (table or {}).items():
            if isinstance(spec, dict):
                if "path" in spec or "git" in spec:
                    continue
                real = spec.get("package", name)
                out[real] = {"spec": str(spec.get("version", "")), "dev": dev}
            elif isinstance(spec, str):
                out[name] = {"spec": spec, "dev": dev}

    take(d.get("dependencies"), False)
    take(d.get("build-dependencies"), True)
    take(d.get("dev-dependencies"), True)
    for tgt in (d.get("target") or {}).values():
        if isinstance(tgt, dict):
            take(tgt.get("dependencies"), False)
            take(tgt.get("build-dependencies"), True)
            take(tgt.get("dev-dependencies"), True)
    return out


def vcpkg_list_from_json(raw: bytes) -> list[dict] | None:
    """vcpkg の一覧を含む JSON（`vcpkg_packages` 配列や Package/Version 形式）を読む。該当しなければ None。"""
    try:
        d = _json(raw)
    except ParseError:
        return None
    cand = None
    if isinstance(d, dict):
        for k, v in d.items():
            if "vcpkg" in k.lower() and isinstance(v, list):
                cand = v
                break
    if cand is None:
        return None
    out = []
    for p in cand:
        if isinstance(p, dict) and isinstance(p.get("Package"), str) and isinstance(p.get("Version"), str) and not p.get("Feature"):
            out.append({"name": p["Package"], "version": p["Version"]})
    return out
