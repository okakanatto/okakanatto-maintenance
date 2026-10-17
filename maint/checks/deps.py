"""依存関係の更新（毎週）。

新しい版があるだけでは Issue にしない。Issue にするのは README「Issue 化の基準」に書いた条件だけ:
- 使用中の版が非推奨（npm deprecated）・取り下げ（crates.io yanked / PyPI yanked）
- 直接依存が最新から update_policy.major_lag_issue 以上メジャー遅れ
それ以外（パッチ・マイナー・1 メジャー差・アクションの新版・上流の新リリース）はサマリーに集約する。
"""

from __future__ import annotations

import datetime as dt
import json
import re
import time
import urllib.parse

from ..context import Context
from ..http import HttpError
from ..inventory import Inventory, read_blob
from ..lockfiles import PARSERS, ParseError, cargo_direct, npm_direct
from ..model import COV_PARTIAL, LOW, MEDIUM, NOT_APPLICABLE, SUPPORTED, UNKNOWN, UNSUPPORTED, CheckResult, Finding, Repo
from ..versions import classify, is_prerelease, major_lag, max_version

NPM = "https://registry.npmjs.org"
CRATES_INDEX = "https://index.crates.io"
PYPI = "https://pypi.org/pypi"


def _crate_index_path(name: str) -> str:
    n = name.lower()
    if len(n) <= 2:
        return f"{len(n)}/{n}"
    if len(n) == 3:
        return f"3/{n[0]}/{n}"
    return f"{n[:2]}/{n[2:4]}/{n}"


def npm_info(ctx: Context, name: str, version: str) -> dict:
    cache = ctx.cache.setdefault("npm", {})
    if name not in cache:
        url = f"{NPM}/{urllib.parse.quote(name, safe='@')}"
        d, _ = ctx.http.request("GET", url, {"Accept": "application/vnd.npm.install-v1+json"})
        cache[name] = d or {}
    d = cache[name]
    latest = (d.get("dist-tags") or {}).get("latest")
    meta = (d.get("versions") or {}).get(version) or {}
    return {"latest": latest, "deprecated": meta.get("deprecated"), "exists": bool(meta)}


def crate_info(ctx: Context, name: str, version: str) -> dict:
    cache = ctx.cache.setdefault("crates", {})
    if name not in cache:
        raw, _ = ctx.http.request("GET", f"{CRATES_INDEX}/{_crate_index_path(name)}", raw=True)
        rows = []
        for line in raw.decode("utf-8", "replace").splitlines():
            try:
                rows.append(json.loads(line))
            except ValueError:
                continue
        cache[name] = rows
    rows = cache[name]
    yanked = {r.get("vers"): bool(r.get("yanked")) for r in rows}
    latest = max_version([r.get("vers") for r in rows if not r.get("yanked") and isinstance(r.get("vers"), str)])
    return {"latest": latest, "deprecated": "yanked" if yanked.get(version) else None, "exists": version in yanked}


def pypi_info(ctx: Context, name: str, version: str) -> dict:
    cache = ctx.cache.setdefault("pypi", {})
    if name not in cache:
        d, _ = ctx.http.request("GET", f"{PYPI}/{urllib.parse.quote(name)}/json")
        cache[name] = d or {}
    d = cache[name]
    files = (d.get("releases") or {}).get(version) or []
    yanked = bool(files) and all(f.get("yanked") for f in files)
    return {"latest": (d.get("info") or {}).get("version"), "deprecated": "yanked" if yanked else None, "exists": bool(files)}


LOOKUP = {"npm": npm_info, "crates.io": crate_info, "PyPI": pypi_info}


def _direct_deps(ctx: Context, inv: Inventory, r: CheckResult) -> tuple[list[dict], set[str]]:
    """([{eco, name, version, spec, dev, path}], 読めなかったエコシステム)。同じ依存が複数ファイルにあれば 1 件にまとめる。"""
    out: list[dict] = []
    failed: set[str] = set()
    installed: dict[tuple[str, str], str] = {}
    for m in inv.manifests:
        if m.kind in ("npm-lock", "cargo-lock", "pip-requirements"):
            try:
                pkgs, _ = PARSERS[m.kind](read_blob(ctx.reader, inv, m.path), m.path)
            except (HttpError, ParseError) as e:
                r.fail(f"{m.path} を読めない: {e}")
                failed.add(m.ecosystem)
                continue
            for p in pkgs:
                if m.kind == "npm-lock" and not p.direct:
                    continue
                k = (p.ecosystem, p.name)
                if k not in installed or (classify(installed[k], p.version) in ("patch", "minor", "major")):
                    installed[k] = p.version
                if m.kind == "pip-requirements":
                    out.append({"eco": "PyPI", "name": p.name, "version": p.version, "spec": "==" + p.version, "dev": p.dev, "path": m.path})
    for m in inv.manifests:
        try:
            if m.kind == "npm-manifest":
                direct, eco = npm_direct(read_blob(ctx.reader, inv, m.path)), "npm"
            elif m.kind == "cargo-manifest":
                direct, eco = cargo_direct(read_blob(ctx.reader, inv, m.path)), "crates.io"
            else:
                continue
        except (HttpError, ParseError, ValueError) as e:
            r.fail(f"{m.path} を読めない: {e}")
            failed.add(m.ecosystem)
            continue
        for name, meta in direct.items():
            v = installed.get((eco, name))
            if v:
                out.append({"eco": eco, "name": name, "version": v, "spec": meta["spec"], "dev": meta["dev"], "path": m.path})
    merged: dict[tuple[str, str, str], dict] = {}
    for d in out:
        k = (d["eco"], d["name"], d["version"])
        if k in merged:
            g = merged[k]
            g["path"] = ", ".join(sorted(set(g["path"].split(", ")) | {d["path"]}))
            g["dev"] = bool(g["dev"]) and bool(d["dev"])  # どこかで本番依存なら本番扱い
        else:
            merged[k] = dict(d)
    return list(merged.values()), failed


def check_deps(ctx: Context, repo: Repo, inv: Inventory) -> CheckResult:
    r = CheckResult("deps")
    if inv.empty or not inv.has_source:
        r.cover("deps", NOT_APPLICABLE if inv.empty else UNSUPPORTED, "コード未登録" if inv.empty else "依存定義が非公開")
        return r
    deps, read_failed = _direct_deps(ctx, inv, r)
    if inv.truncated:
        r.fail("ツリーが大きすぎて一部しか取得できていない（未取得部分の依存定義は未検査）")
    major_threshold = ctx.policy("update_policy", "major_lag_issue", 2, repo.id, repo.name)
    rows = []
    failed_ecos: set[str] = set(read_failed)
    for d in deps:
        fn = LOOKUP.get(d["eco"])
        if not fn:
            continue
        try:
            info = fn(ctx, d["name"], d["version"])
            if d["eco"] == "crates.io":
                time.sleep(float(ctx.cfg.section("update_policy").get("crates_delay_sec", 0)))
        except HttpError as e:
            failed_ecos.add(d["eco"])
            r.fail(f"{d['eco']} {d['name']} の最新版を取得できない: {e.kind}")
            continue
        latest = info.get("latest")
        kind = classify(d["version"], latest) if latest else "unknown"
        row = {**d, "latest": latest, "update": kind, "deprecated": info.get("deprecated")}
        rows.append(row)
        if info.get("deprecated"):
            reason = "取り下げ（yanked）" if info["deprecated"] == "yanked" else f"非推奨: {str(info['deprecated'])[:160]}"
            r.findings.append(Finding(
                key=f"deps-deprecated:{repo.id}:{d['eco']}:{d['name']}", kind="deps", repo_id=repo.id, repo_name=repo.name,
                title=f"[依存] {repo.name}: {d['name']} {d['version']} が{'取り下げ済み' if info['deprecated'] == 'yanked' else '非推奨'}",
                severity=LOW if d.get("dev") else MEDIUM, summary=reason + ("（開発用依存）" if d.get("dev") else ""),
                evidence=[_registry_url(d["eco"], d["name"])],
                recommendation=f"後継・修正版（最新 {latest}）への移行を検討する", scope=[f"{d['path']}（直接依存）"],
                unverified=["非推奨の理由がこのアプリの使い方に影響するか"],
                material={"version": d["version"], "deprecated": bool(info["deprecated"])}, verify=[f"deps:{repo.id}:{d['eco']}"],
            ))
        lag = major_lag(d["version"], latest) if latest and not is_prerelease(latest) else 0
        # 開発用依存の遅れはサマリーのみ（配布物の保守リスクではないため）
        if major_threshold and lag >= int(major_threshold) and not d.get("dev"):
            r.findings.append(Finding(
                key=f"deps-major:{repo.id}:{d['eco']}:{d['name']}", kind="deps", repo_id=repo.id, repo_name=repo.name,
                title=f"[依存] {repo.name}: {d['name']} が {lag} メジャー遅れ（{d['version']} → {latest}）",
                severity=LOW, summary=f"直接依存 {d['name']} が最新から {lag} メジャー以上遅れている。古いメジャーは修正が提供されなくなることが多い",
                evidence=[_registry_url(d["eco"], d["name"])], recommendation="移行コストを見積もり、更新するか据え置くか決める（据え置くなら suppressions.json に期限付きで記録）",
                scope=[f"{d['path']}（直接依存）"], unverified=["旧メジャーにまだ修正が提供されているか"],
                material={"from_major": d["version"].split(".")[0], "lag": lag}, verify=[f"deps:{repo.id}:{d['eco']}"],
            ))
    if not inv.truncated:
        for eco in sorted({d["eco"] for d in deps} - failed_ecos):
            r.verified_scopes.append(f"deps:{repo.id}:{eco}")
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["update"]] = counts.get(row["update"], 0) + 1
    r.data["direct"] = rows
    r.data["counts"] = counts
    if counts:
        r.notes.append("直接依存の更新: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items()) if k != "same"))
    _upstreams(ctx, repo, inv, r)
    _actions(ctx, r, inv, repo)
    unsupported = sorted({m.ecosystem for m in inv.manifests if m.is_lock and m.ecosystem not in LOOKUP})
    if not deps and not inv.submodules and not inv.custom_locks:
        r.cover("deps", UNSUPPORTED if unsupported else NOT_APPLICABLE, "対応レジストリの依存定義なし" + (f"（未対応: {', '.join(unsupported)}）" if unsupported else ""))
    elif failed_ecos:
        r.cover("deps", COV_PARTIAL, f"取得失敗: {', '.join(sorted(failed_ecos))}")
    elif unsupported or inv.custom_locks or inv.submodules:
        extra = (f"未対応レジストリ: {', '.join(unsupported)}。" if unsupported else "") + "サブモジュール・固定上流はリリース差のみ確認"
        r.cover("deps", COV_PARTIAL, extra)
    else:
        r.cover("deps", SUPPORTED, f"直接依存 {len(rows)} 件を npm/crates.io/PyPI と照合")
    return r


def _registry_url(eco: str, name: str) -> str:
    return {"npm": f"https://www.npmjs.com/package/{name}", "crates.io": f"https://crates.io/crates/{name}", "PyPI": f"https://pypi.org/project/{name}/"}.get(eco, "")


def _gh_repo(url: str) -> str | None:
    m = re.search(r"github\.com[/:]([\w.-]+/[\w.-]+?)(?:\.git)?/?$", url or "")
    return m.group(1) if m else None


def _upstreams(ctx: Context, repo: Repo, inv: Inventory, r: CheckResult) -> None:
    """サブモジュールと、ロック JSON に書かれた固定上流（source + commit/tag）の新しさ。"""
    pins: list[dict] = []
    for sm in inv.submodules:
        if _gh_repo(sm.get("url", "")):
            pins.append({"what": sm["path"], "repo": _gh_repo(sm["url"]), "commit": sm["sha"], "tag": None})
    for path in inv.custom_locks:
        try:
            d = json.loads(read_blob(ctx.reader, inv, path).decode("utf-8-sig"))
        except (HttpError, ValueError):
            continue
        if not isinstance(d, dict):
            continue
        for k, v in d.items():
            if isinstance(v, dict) and _gh_repo(str(v.get("source", ""))) and v.get("commit"):
                gh = _gh_repo(v["source"])
                if not any(p["repo"] == gh and p["commit"] == v["commit"] for p in pins):
                    pins.append({"what": f"{path}:{k}", "repo": gh, "commit": v["commit"], "tag": v.get("tag")})
    rows = []
    for p in pins:
        row = dict(p)
        try:
            rel = ctx.reader.latest_release(p["repo"])
            row["latest_release"] = rel.get("tag_name") if rel else None
            c = ctx.reader.commit(p["repo"], p["commit"])
            date = ((c.get("commit") or {}).get("committer") or {}).get("date")
            row["pinned_date"] = date
            if date:
                age = (ctx.now - dt.datetime.fromisoformat(date.replace("Z", "+00:00"))).days
                row["pinned_age_days"] = age
        except HttpError as e:
            row["error"] = e.kind
            r.notes.append(f"上流 {p['repo']} の情報を取得できない（{e.kind}）")
        rows.append(row)
        if row.get("latest_release") and p.get("tag") and row["latest_release"] != p["tag"]:
            r.notes.append(f"{p['what']}: 固定 {p['tag']} / 上流の最新リリース {row['latest_release']}")
        elif row.get("pinned_age_days") is not None and row["pinned_age_days"] > 365:
            r.notes.append(f"{p['what']}: 固定コミットが {row['pinned_age_days']} 日前（{p['repo']}）")
    if rows:
        r.data["upstream_pins"] = rows


def _actions(ctx: Context, r: CheckResult, inv: Inventory, repo: Repo) -> None:
    from .ci import parse_workflow  # 循環 import を避ける

    seen = {}
    for path in inv.workflows:
        try:
            wf = parse_workflow(read_blob(ctx.reader, inv, path).decode("utf-8", "replace"))
        except HttpError:
            continue
        for ref, comment in wf["uses"]:
            if ref.startswith(("./", "docker://")) or "@" not in ref:
                continue
            name, ver = ref.split("@", 1)
            label = comment if re.fullmatch(r"[0-9a-f]{40}", ver) else ver
            seen.setdefault("/".join(name.split("/")[:2]), set()).add(label or ver[:12])
    cache = ctx.cache.setdefault("action_latest", {})
    rows = []
    for name, used in sorted(seen.items()):
        if name not in cache:
            try:
                rel = ctx.reader.latest_release(name)
                cache[name] = rel.get("tag_name") if rel else None
            except HttpError:
                cache[name] = None
        latest = cache[name]
        rows.append({"action": name, "used": sorted(u for u in used if u), "latest": latest})
        if latest:
            behind = [u for u in used if u and major_lag(u, latest) >= 1]
            if behind:
                r.notes.append(f"アクション {name}: 使用 {', '.join(sorted(behind))} / 最新 {latest}")
    if rows:
        r.data["actions"] = rows
