"""棚卸し: Git ツリーから依存定義・サブモジュール・CI・ビルド方式を見つける。

外部リポジトリのコードは実行しない。ファイルはデータとして API 経由で読むだけ。
"""

from __future__ import annotations

import fnmatch
import posixpath
import re
from dataclasses import dataclass, field

from .github import GitHubReader
from .http import HttpError
from .model import Repo

# basename パターン → (種別, エコシステム, 解析器があるか)
MANIFEST_PATTERNS: list[tuple[str, str, str, bool]] = [
    ("package-lock.json", "npm-lock", "npm", True),
    ("npm-shrinkwrap.json", "npm-lock", "npm", True),
    ("yarn.lock", "yarn-lock", "npm", False),
    ("pnpm-lock.yaml", "pnpm-lock", "npm", False),
    ("bun.lock", "bun-lock", "npm", False),
    ("bun.lockb", "bun-lock", "npm", False),
    ("package.json", "npm-manifest", "npm", True),
    ("Cargo.lock", "cargo-lock", "crates.io", True),
    ("Cargo.toml", "cargo-manifest", "crates.io", True),
    ("requirements*.txt", "pip-requirements", "PyPI", True),
    ("poetry.lock", "poetry-lock", "PyPI", True),
    ("uv.lock", "uv-lock", "PyPI", True),
    ("Pipfile.lock", "pipenv-lock", "PyPI", True),
    ("pyproject.toml", "py-manifest", "PyPI", False),
    ("go.mod", "go-mod", "Go", True),
    ("packages.lock.json", "nuget-lock", "NuGet", True),
    ("*.csproj", "nuget-manifest", "NuGet", False),
    ("composer.lock", "composer-lock", "Packagist", True),
    ("Gemfile.lock", "gem-lock", "RubyGems", False),
    ("pom.xml", "maven-manifest", "Maven", False),
    ("gradle.lockfile", "gradle-lock", "Maven", False),
    ("vcpkg.json", "vcpkg-manifest", "vcpkg", False),
    ("conanfile.txt", "conan-manifest", "conan", False),
    ("conanfile.py", "conan-manifest", "conan", False),
    ("conan.lock", "conan-lock", "conan", False),
]
LOCK_KINDS = {
    "npm-lock", "yarn-lock", "pnpm-lock", "bun-lock", "cargo-lock", "pip-requirements", "poetry-lock",
    "uv-lock", "pipenv-lock", "go-mod", "nuget-lock", "composer-lock", "gem-lock", "gradle-lock", "conan-lock",
}
# C/C++ のソース・ビルド定義
NATIVE_SOURCE = re.compile(r"\.(c|cc|cpp|cxx|h|hh|hpp|hxx)$", re.I)
BUILD_FILES = {
    "CMakeLists.txt": "CMake",
    "meson.build": "Meson",
    "Makefile": "Make",
    "tauri.conf.json": "Tauri",
    "next.config.js": "Next.js",
    "next.config.mjs": "Next.js",
    "next.config.ts": "Next.js",
    "electron-builder.yml": "Electron",
    "electron-builder.json": "Electron",
}
BUILD_SUFFIX = {".sln": "MSBuild", ".vcxproj": "MSBuild", ".csproj": ".NET", ".pro": "qmake"}
# ソース以外とみなす拡張子（「ソース非公開」判定に使う）
NON_SOURCE = re.compile(r"\.(md|txt|png|jpe?g|gif|svg|ico|icns|webp|pdf|zip|exe|msi)$|^(LICENSE|COPYING|NOTICE)(\..*)?$", re.I)
DEFAULT_IGNORE = ["node_modules/*", "*/node_modules/*", "*/fixtures/*", "*/testdata/*", "*/__fixtures__/*"]


@dataclass
class Manifest:
    path: str
    kind: str
    ecosystem: str
    sha: str
    size: int
    parser: bool

    @property
    def is_lock(self) -> bool:
        return self.kind in LOCK_KINDS

    def to_dict(self) -> dict:
        return {"path": self.path, "kind": self.kind, "ecosystem": self.ecosystem, "size": self.size, "parser": self.parser}


@dataclass
class Inventory:
    repo: Repo
    ref: str
    commit_sha: str = ""
    empty: bool = False
    truncated: bool = False
    files: dict[str, tuple[str, int]] = field(default_factory=dict)  # path -> (blob sha, size)
    manifests: list[Manifest] = field(default_factory=list)
    submodules: list[dict] = field(default_factory=list)  # {path, sha, url}
    workflows: list[str] = field(default_factory=list)
    build_systems: list[str] = field(default_factory=list)
    native_sources: int = 0
    custom_locks: list[str] = field(default_factory=list)  # 形式不明の *lock*.json（中身で判定）
    ignored: list[str] = field(default_factory=list)
    languages: dict = field(default_factory=dict)

    @property
    def has_source(self) -> bool:
        """ドキュメント・画像・ライセンス以外のファイルがあるか。"""
        return any(not NON_SOURCE.search(posixpath.basename(p)) for p in self.files)

    def summary(self) -> dict:
        return {
            "ref": self.ref,
            "commit": self.commit_sha[:12],
            "empty": self.empty,
            "truncated": self.truncated,
            "file_count": len(self.files),
            "has_source": self.has_source,
            "languages": sorted(self.languages, key=lambda k: -self.languages[k])[:5],
            "manifests": [m.to_dict() for m in self.manifests],
            "submodules": [{"path": s["path"], "url": s.get("url"), "sha": s["sha"][:12]} for s in self.submodules],
            "workflows": self.workflows,
            "build_systems": self.build_systems,
            "native_sources": self.native_sources,
            "custom_locks": self.custom_locks,
            "ignored_manifest_paths": self.ignored[:20],
        }


def _classify(path: str) -> tuple[str, str, bool] | None:
    base = posixpath.basename(path)
    for pat, kind, eco, parser in MANIFEST_PATTERNS:
        if fnmatch.fnmatchcase(base, pat):
            return kind, eco, parser
    return None


def _ignored(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(path, p) or fnmatch.fnmatchcase("/" + path, "*/" + p.lstrip("*/")) for p in patterns)


def parse_gitmodules(text: str) -> dict[str, str]:
    """path -> url"""
    out: dict[str, str] = {}
    cur_path = cur_url = None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("[submodule"):
            if cur_path:
                out[cur_path] = cur_url or ""
            cur_path = cur_url = None
        elif "=" in line:
            k, v = (x.strip() for x in line.split("=", 1))
            if k == "path":
                cur_path = v
            elif k == "url":
                cur_url = v
    if cur_path:
        out[cur_path] = cur_url or ""
    return out


def build_inventory(reader: GitHubReader, repo: Repo, ref: str, ignore: list[str] | None = None, with_languages: bool = True) -> Inventory:
    """ref はブランチ名・タグ名・コミット SHA。空リポジトリは empty=True で返す（例外にしない）。"""
    inv = Inventory(repo=repo, ref=ref)
    patterns = DEFAULT_IGNORE + list(ignore or [])
    try:
        tree = reader.tree(repo.full_name, ref)
    except HttpError as e:
        if e.kind == "conflict":  # 409: Git Repository is empty
            inv.empty = True
            return inv
        if e.kind == "not_found" and repo.size == 0:
            inv.empty = True
            return inv
        raise
    inv.commit_sha = tree.get("sha", "")
    inv.truncated = bool(tree.get("truncated"))
    gitlinks: dict[str, str] = {}
    for node in tree.get("tree", []):
        path, typ = node.get("path", ""), node.get("type")
        if typ == "commit":
            gitlinks[path] = node.get("sha", "")
            continue
        if typ != "blob":
            continue
        inv.files[path] = (node.get("sha", ""), int(node.get("size") or 0))
        base = posixpath.basename(path)
        if path.startswith(".github/workflows/") and base.endswith((".yml", ".yaml")) and path.count("/") == 2:
            inv.workflows.append(path)
        if NATIVE_SOURCE.search(base):
            inv.native_sources += 1
        if base in BUILD_FILES and BUILD_FILES[base] not in inv.build_systems:
            inv.build_systems.append(BUILD_FILES[base])
        suffix = posixpath.splitext(base)[1]
        if suffix in BUILD_SUFFIX and BUILD_SUFFIX[suffix] not in inv.build_systems:
            inv.build_systems.append(BUILD_SUFFIX[suffix])
        c = _classify(path)
        if c:
            if _ignored(path, patterns):
                inv.ignored.append(path)
                continue
            kind, eco, parser = c
            inv.manifests.append(Manifest(path, kind, eco, node.get("sha", ""), int(node.get("size") or 0), parser))
        elif base.endswith(".json") and "lock" in base.lower() and not _ignored(path, patterns):
            inv.custom_locks.append(path)
    for m in inv.manifests:
        label = {"npm": "npm", "crates.io": "Cargo", "PyPI": "Python", "Go": "Go", "NuGet": ".NET"}.get(m.ecosystem)
        if label and label not in inv.build_systems:
            inv.build_systems.append(label)
    if gitlinks:
        urls: dict[str, str] = {}
        if ".gitmodules" in inv.files:
            try:
                urls = parse_gitmodules(reader.blob(repo.full_name, inv.files[".gitmodules"][0]).decode("utf-8", "replace"))
            except HttpError:
                urls = {}
        for p, sha in sorted(gitlinks.items()):
            inv.submodules.append({"path": p, "sha": sha, "url": urls.get(p, "")})
    if with_languages:
        try:
            inv.languages = reader.languages(repo.full_name)
        except HttpError:
            inv.languages = {}
    return inv


def read_blob(reader: GitHubReader, inv: Inventory, path: str) -> bytes:
    sha, _ = inv.files[path]
    return reader.blob(inv.repo.full_name, sha)
