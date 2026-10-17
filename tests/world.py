"""統合テスト用の標準シナリオ（架空のリポジトリ群）と実行ヘルパー。"""

from __future__ import annotations

import copy
import datetime as dt
import json

from maint import config as config_mod
from maint.context import Context
from maint.github import GitHubReader, IssueWriter
from maint.http import HttpClient
from maint.model import Repo  # noqa: F401（テストから参照）
from maint.osv import OSVClient
from maint.runner import RunOptions, run

from . import fakes
from .fakes import CENTRAL, FakeRepo, FakeWorld, Snapshot, cargo_lock, npm_lock, osv_vuln

WORKFLOW_PUSH = b"""name: Source checks
on:
  push:
  pull_request:
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
"""
ACTION_NODE20 = b"name: checkout\nruns:\n  using: node20\n  main: dist/index.js\n"


def app_files(next_ver: str = "16.1.6", vitest_ver: str = "4.0.0", tauri_ver: str = "2.0.0") -> dict[str, bytes]:
    return {
        "package.json": json.dumps({"dependencies": {"next": "16.1.6"}, "devDependencies": {"vitest": "^4.0.0"}}).encode(),
        "package-lock.json": npm_lock({"next": (next_ver, False), "vitest": (vitest_ver, True), "leftpad": ("1.0.0", False)}, ["next", "vitest"]),
        "src-tauri/Cargo.toml": b'[package]\nname="app"\nversion="0.1.0"\n[dependencies]\ntauri = "2"\n',
        "src-tauri/Cargo.lock": cargo_lock({"tauri": tauri_ver, "fxhash": "0.2.1"}),
        "src-tauri/tauri.conf.json": b"{}",
        "README.md": "Windows 11 用。WebView2 が必要".encode(),
        "src/index.js": b"console.log(1)",
    }


def build_world() -> FakeWorld:
    w = FakeWorld()
    w.add_repo(FakeRepo(100, "okakanatto-maintenance"))
    app = w.add_repo(FakeRepo(101, "AppA", head=Snapshot("1" * 40, app_files())))
    app.tags["v1.0.0"] = app.head
    app.releases = [{"tag_name": "v1.0.0", "draft": False, "prerelease": False, "published_at": "2026-09-01T00:00:00Z",
                     "html_url": "https://github.com/okakanatto/AppA/releases/tag/v1.0.0",
                     "assets": [{"name": "AppA_setup.exe", "size": 100, "digest": "sha256:abc", "download_count": 3}]}]
    native = w.add_repo(FakeRepo(102, "NativeApp", head=Snapshot("2" * 40, {
        "CMakeLists.txt": b"find_package(Qt6 REQUIRED)",
        "src/main.cpp": b"int main(){}",
        ".gitmodules": b'[submodule "vendor/lib"]\n\tpath = vendor/lib\n\turl = https://github.com/upstream/lib.git\n',
        "dependency-lock.json": json.dumps({"qt": {"version": "6.9.3"}, "vcpkg_packages": [{"Package": "zlib", "Version": "1.3.1"}]}).encode(),
        ".github/workflows/source-checks.yml": WORKFLOW_PUSH,
        "README.md": b"PDF tool",
    }, {"vendor/lib": "c" * 40})))
    native.workflows = [{"id": 9001, "name": "Source checks", "path": ".github/workflows/source-checks.yml", "state": "active", "html_url": "https://github.com/okakanatto/NativeApp/actions"}]
    binonly = w.add_repo(FakeRepo(103, "BinOnly", head=Snapshot("3" * 40, {"README.md": "Windows 用。ソース非公開".encode(), "LICENSE": b"MIT"})))
    binonly.tags["v0.1.0"] = binonly.head
    binonly.releases = [{"tag_name": "v0.1.0", "draft": False, "prerelease": False, "published_at": "2026-09-13T00:00:00Z", "assets": [{"name": "BinOnly.zip", "size": 5}]}]
    w.add_repo(FakeRepo(104, "EmptyRepo", empty=True))
    w.add_repo(FakeRepo(105, "ForkRepo", fork=True))
    w.add_repo(FakeRepo(106, "OldRepo", archived=True))
    # 上流（アクション・サブモジュール）
    actions = w.add_repo(FakeRepo(900, "checkout", owner="actions", head=Snapshot("11d5960a326750d5838078e36cf38b85af677262", {"action.yml": ACTION_NODE20})))
    actions.releases = [{"tag_name": "v7.0.1", "draft": False, "prerelease": False, "published_at": "2026-07-20T00:00:00Z", "assets": []}]
    w.add_repo(FakeRepo(901, "lib", owner="upstream", head=Snapshot("c" * 40, {"README": b"x"})))

    w.osv_db = {
        ("npm", "next", "16.1.6"): ["GHSA-next-0001"],
        ("npm", "vitest", "4.0.0"): ["GHSA-vite-0001"],
        ("crates.io", "tauri", "2.0.0"): ["RUSTSEC-2026-0001"],
        ("crates.io", "fxhash", "0.2.1"): ["RUSTSEC-2025-0057"],
    }
    w.vulns = {
        "GHSA-next-0001": osv_vuln("GHSA-next-0001", "npm", "next", "16.1.7", "CRITICAL", aliases=["CVE-2026-1111"]),
        "GHSA-vite-0001": osv_vuln("GHSA-vite-0001", "npm", "vitest", "4.0.5", "HIGH"),
        "RUSTSEC-2026-0001": {**osv_vuln("RUSTSEC-2026-0001", "crates.io", "tauri", "2.0.1", None),
                              "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"}]},
        "RUSTSEC-2025-0057": osv_vuln("RUSTSEC-2025-0057", "crates.io", "fxhash", "9.9.9", None, informational="unmaintained"),
    }
    w.npm = {"next": {"dist-tags": {"latest": "16.4.2"}, "versions": {"16.1.6": {}, "16.1.7": {}}},
             "vitest": {"dist-tags": {"latest": "4.1.0"}, "versions": {"4.0.0": {}, "4.0.5": {}}}}
    w.crates = {"tauri": [{"name": "tauri", "vers": "2.0.0", "yanked": False}, {"name": "tauri", "vers": "2.0.1", "yanked": False}]}
    w.eol = {
        "qt": [{"name": "6.12", "isEol": False, "eolFrom": "2027-04-01"}, {"name": "6.9", "isEol": True, "eolFrom": "2025-10-07", "latest": {"name": "6.9.3"}}],
        "github-actions-runner-images": [{"name": "ubuntu-24.04", "isEol": False}, {"name": "windows-2019", "isEol": True, "eolFrom": "2025-06-30"}],
        "nextjs": [{"name": "16", "isEol": False, "eolFrom": None}],
    }
    return w


class Runner:
    """同じ FakeWorld に対して、時刻を進めながら何度でも実行する。"""

    def __init__(self, world: FakeWorld, cfg=None):
        self.w = world
        self.cfg = cfg or config_mod.load()
        self.now = fakes.now()

    def run(self, checks: str = "daily", dry_run: bool = False, only=None, advance_hours: float = 24) -> dict:
        http = HttpClient(transport=self.w, sleep=lambda s: None, max_retries=2, backoff=0.01)
        ctx = Context(self.cfg, GitHubReader(http, "test-token"), http, OSVClient(http), self.now)
        ctx.cache["_frozen_clock"] = True
        writer = IssueWriter(http, "test-token", CENTRAL, dry_run=dry_run)
        rep = run(ctx, writer, RunOptions(checks=checks, dry_run=dry_run, only=only))
        self.now = self.now + dt.timedelta(hours=advance_hours)
        return rep

    def managed(self) -> list[dict]:
        return [i for i in self.w.issues if "maint:dashboard" not in {lb["name"] for lb in i["labels"]}]

    def by_key(self, key: str) -> dict | None:
        for i in self.w.issues:
            if f"<!-- maint-key: {key} -->" in i["body"]:
                return i
        return None


def with_suppressions(cfg, entries: list[dict]):
    c = copy.deepcopy(cfg)
    c.suppressions = config_mod._parse_suppressions({"suppressions": entries})
    return c
