"""配布済みバージョン（GitHub Releases）の把握。

最新ソース（既定ブランチ）と、利用者に配布済みのリリースを区別する。
配布バイナリがどのソースから作られたかは検証できないので、タグ時点のソースで「推定」するに留め、
ソースが無い・タグが解決できない場合は UNKNOWN とする。
"""

from __future__ import annotations

import re

from ..context import Context
from ..http import HttpError
from ..inventory import Inventory, build_inventory
from ..model import COV_PARTIAL, NOT_APPLICABLE, UNKNOWN, CheckResult, Repo

SBOM_NAME = re.compile(r"(sbom|spdx|cyclonedx|\.cdx\.json$|bom\.json$)", re.I)


def check_release(ctx: Context, repo: Repo, inv: Inventory) -> tuple[CheckResult, Inventory | None]:
    """戻り値の Inventory はリリースタグ時点の棚卸し（脆弱性検査で使う）。既定ブランチと同じコミットなら inv をそのまま返す。"""
    r = CheckResult("release")
    try:
        rels = ctx.reader.releases(repo.full_name)
    except HttpError as e:
        r.fail(f"Releases を取得できません: {e.kind} ({e.status})", fatal=True)
        r.cover("release", UNKNOWN, "Releases の取得に失敗")
        return r, None
    published = [x for x in rels if not x.get("draft")]
    if not published:
        try:
            tags = ctx.reader.tags(repo.full_name)
        except HttpError as e:
            tags = []
            r.fail(f"タグを取得できません: {e.kind}")
        r.data = {"releases": 0, "tags": len(tags)}
        note = "GitHub Releases なし"
        if tags:
            note += f"（タグ {len(tags)} 件。タグ以外の経路で配布しているかは不明）"
        r.cover("release", NOT_APPLICABLE, note)
        return r, None

    latest = max(published, key=lambda x: x.get("published_at") or x.get("created_at") or "")
    stable = [x for x in published if not x.get("prerelease")]
    tag = latest.get("tag_name", "")
    assets = [
        {
            "name": a.get("name"),
            "size": a.get("size"),
            "digest": a.get("digest"),
            "downloads": a.get("download_count"),
        }
        for a in latest.get("assets") or []
    ]
    data = {
        "releases": len(published),
        "latest_tag": tag,
        "latest_published": latest.get("published_at"),
        "latest_prerelease": bool(latest.get("prerelease")),
        "latest_stable_tag": max(stable, key=lambda x: x.get("published_at") or "")["tag_name"] if stable else None,
        "html_url": latest.get("html_url"),
        "assets": assets,
        "sbom_attached": any(SBOM_NAME.search(a["name"] or "") for a in assets),
    }
    r.data = data
    try:
        tag_sha = ctx.reader.commit_sha(repo.full_name, tag)
    except HttpError as e:
        r.fail(f"タグ {tag} のコミットを解決できません: {e.kind}")
        r.cover("release", UNKNOWN, f"{tag} のコミットを解決できない")
        return r, None
    data["tag_commit"] = tag_sha
    if inv.commit_sha and tag_sha == inv.commit_sha:
        data["unreleased_commits"] = 0
    else:
        try:
            cmp = ctx.reader.compare(repo.full_name, tag_sha, repo.default_branch)
            data["unreleased_commits"] = cmp.get("ahead_by")
            data["release_not_on_default"] = cmp.get("behind_by", 0) > 0
        except HttpError as e:
            data["unreleased_commits"] = None
            r.notes.append(f"既定ブランチとの比較に失敗: {e.kind}")
    if data.get("unreleased_commits"):
        r.notes.append(f"最新リリース {tag} 以降、既定ブランチに未リリースのコミットが {data['unreleased_commits']} 件")

    if not inv.has_source:
        r.cover("release", UNKNOWN, f"{tag} の配布物あり。ソース・依存定義が公開されていないため中身を検査できない")
        return r, None
    if tag_sha == inv.commit_sha:
        rel_inv = inv
    else:
        try:
            rel_inv = build_inventory(ctx.reader, repo, tag_sha, ctx.cfg.repo_policy(repo.id, repo.name).get("ignore_paths"), with_languages=False)
        except HttpError as e:
            r.fail(f"{tag} 時点のツリーを取得できません: {e.kind}")
            r.cover("release", UNKNOWN, f"{tag} 時点のソースを取得できない")
            return r, None
    note = f"{tag} 時点のソースの依存定義で推定。配布バイナリとソースの一致は未検証"
    note += "（SBOM 添付あり・未解析）" if data["sbom_attached"] else "（SBOM・来歴証明なし）"
    r.cover("release", COV_PARTIAL, note)
    return r, rel_inv
