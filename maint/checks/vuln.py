"""既知脆弱性の照合（毎日）。

対象: 既定ブランチ（最新ソース）と最新リリースのタグ時点のロックファイル、Git サブモジュールの固定コミット。
- 照合は OSV.dev。Dependabot alerts は読み取りトークンがあるときだけ追加情報源として使う
- 取得・解析に失敗したエコシステムは「検証済み」にしない（＝その範囲の Issue は閉じない）
- C/C++ の同梱ライブラリ・vcpkg・配布バイナリは自動照合できないので UNSUPPORTED/PARTIAL として残す
"""

from __future__ import annotations

import posixpath
from collections import defaultdict

from ..context import Context
from ..http import HttpError
from ..inventory import Inventory, read_blob
from ..lockfiles import PARSERS, Package, ParseError, vcpkg_list_from_json
from ..model import (
    COV_PARTIAL,
    INFO,
    NOT_APPLICABLE,
    SEVERITY_JA,
    SEVERITY_RANK,
    SEVERITIES,
    SUPPORTED,
    UNKNOWN,
    UNSUPPORTED,
    CheckResult,
    Finding,
    Repo,
    severity_at_least,
)
from ..osv import Vuln
from ..versions import compare

MANIFEST_ONLY = {"npm-manifest": "npm", "cargo-manifest": "crates.io", "py-manifest": "PyPI", "nuget-manifest": "NuGet", "maven-manifest": "Maven"}
_ID_RANK = (("GHSA-", 0), ("RUSTSEC-", 1), ("PYSEC-", 2), ("GO-", 3), ("CVE-", 9))


def _id_rank(vid: str) -> tuple[int, str]:
    for prefix, rank in _ID_RANK:
        if vid.startswith(prefix):
            return rank, vid
    return 5, vid


def collect_packages(ctx: Context, inv: Inventory) -> tuple[list[Package], dict[str, dict]]:
    """ロックファイルを読む。戻り値: (packages, eco_status)。eco_status[eco] = {parsed, failed, unsupported, unlocked, notes}"""
    pkgs: list[Package] = []
    status: dict[str, dict] = {}

    def st(eco: str) -> dict:
        return status.setdefault(eco, {"parsed": [], "failed": [], "unsupported": [], "unlocked": [], "notes": []})

    lock_dirs: dict[str, set[str]] = defaultdict(set)
    for m in inv.manifests:
        if not m.is_lock:
            continue
        lock_dirs[m.ecosystem].add(posixpath.dirname(m.path))
        s = st(m.ecosystem)
        if not m.parser:
            s["unsupported"].append(m.path)
            continue
        try:
            raw = read_blob(ctx.reader, inv, m.path)
            got, notes = PARSERS[m.kind](raw, m.path)
        except HttpError as e:
            s["failed"].append(f"{m.path}（取得失敗: {e.kind}）")
            continue
        except ParseError as e:
            s["failed"].append(f"{m.path}（解析失敗: {e}）")
            continue
        s["parsed"].append(m.path)
        s["notes"].extend(notes[:5])
        pkgs.extend(got)
    for m in inv.manifests:
        eco = MANIFEST_ONLY.get(m.kind)
        if not eco:
            continue
        d = posixpath.dirname(m.path)
        ancestors = {d}
        while d:
            d = posixpath.dirname(d)
            ancestors.add(d)
        if not (lock_dirs.get(eco, set()) & ancestors):
            st(eco)["unlocked"].append(m.path)
    return pkgs, status


def _eco_coverage(s: dict) -> tuple[str, str, bool]:
    """(level, note, fully_verified)"""
    parts = []
    if s["parsed"]:
        parts.append("照合: " + ", ".join(s["parsed"]))
    if s["failed"]:
        parts.append("失敗: " + ", ".join(s["failed"]))
    if s["unsupported"]:
        parts.append("解析器なし: " + ", ".join(s["unsupported"]))
    if s["unlocked"]:
        parts.append("ロックファイルなし（版が確定しない）: " + ", ".join(s["unlocked"]))
    partial_notes = [n for n in s["notes"] if "照合できない" in n or "照合対象外" in n]
    if partial_notes:
        parts.append("一部対象外: " + "; ".join(partial_notes[:3]))
    note = " / ".join(parts)
    if not s["parsed"]:
        return (UNKNOWN if s["failed"] else UNSUPPORTED), note, False
    if s["failed"]:
        return COV_PARTIAL, note, False
    if s["unsupported"] or s["unlocked"] or partial_notes:
        # 解析できたファイルは検証済み。解析できない形式があるので PARTIAL
        return COV_PARTIAL, note, True
    return SUPPORTED, note, True


def check_vuln(ctx: Context, repo: Repo, inv: Inventory, release_res: CheckResult | None, rel_inv: Inventory | None) -> CheckResult:
    r = CheckResult("vuln")
    if inv.empty:
        r.cover("vuln", NOT_APPLICABLE, "コード未登録（空リポジトリ）")
        r.verified_scopes += [f"vuln:{repo.id}:*", f"vuln-release:{repo.id}"]
        return r
    if inv.truncated:
        r.fail("ツリーが大きすぎて一部しか取得できていない（未取得部分の依存定義は未検査）")

    scopes: list[tuple[str, Inventory]] = [("default", inv)]
    tag = (release_res.data or {}).get("latest_tag") if release_res else None
    if rel_inv is not None and rel_inv is not inv:
        scopes.append(("release", rel_inv))

    all_pkgs: list[tuple[str, Package]] = []
    release_ok = True
    for scope, sinv in scopes:
        pkgs, status = collect_packages(ctx, sinv)
        all_pkgs += [(scope, p) for p in pkgs]
        for eco, s in sorted(status.items()):
            level, note, verified = _eco_coverage(s)
            if scope == "default":
                r.cover(f"vuln.{eco}", level, note)
                if verified:
                    r.verified_scopes.append(f"vuln:{repo.id}:{eco}")
                elif s["failed"]:
                    r.fail(f"{eco}: " + "; ".join(s["failed"]))
            elif not verified and (s["failed"] or not s["parsed"]):
                release_ok = False
                if s["failed"]:
                    r.fail(f"{tag} 時点の {eco}: " + "; ".join(s["failed"]))
    if rel_inv is inv:
        all_pkgs += [("release", p) for s, p in all_pkgs if s == "default"]

    _native_coverage(ctx, repo, inv, r)
    if not inv.has_source:
        if release_res and (release_res.data or {}).get("releases"):
            r.cover("vuln.source", UNSUPPORTED, "ソース・依存定義が非公開。配布バイナリの中身は検査できない")
        else:
            r.cover("vuln.source", NOT_APPLICABLE, "ソースコードなし")

    # OSV 照合
    hits: dict[str, list[tuple[str, Package]]] = defaultdict(list)
    if all_pkgs:
        try:
            res = ctx.osv.query_packages([p for _, p in all_pkgs])
        except HttpError as e:
            r.fail(f"OSV 照合に失敗: {e.kind} ({e.status})", fatal=True)
            r.verified_scopes = [t for t in r.verified_scopes if not t.startswith("vuln:")]
            for area, item in r.coverage.items():
                if area.startswith("vuln.") and item.level in (SUPPORTED, COV_PARTIAL) and area not in ("vuln.submodule",):
                    r.cover(area, UNKNOWN, "OSV 照合に失敗（今回は未検査）")
            return r
        for scope, p in all_pkgs:
            for vid in res.get((p.ecosystem, p.name, p.version), []):
                hits[vid].append((scope, p))

    # サブモジュール（固定コミット）を OSV のコミット照合にかける
    sub_hits = _submodule_commits(ctx, repo, inv, r)
    for vid, entries in sub_hits.items():
        hits[vid].extend(entries)

    details: dict[str, Vuln] = {}
    for vid in sorted(hits):
        try:
            details[vid] = ctx.osv.get(vid)
        except HttpError as e:
            r.fail(f"OSV 詳細の取得に失敗: {vid} ({e.kind})")
            r.verified_scopes = [t for t in r.verified_scopes if not t.startswith("vuln:")]

    _dependabot(ctx, repo, r, details, hits)

    if release_res is None or release_res.status == "ERROR":
        release_ok = False
    elif rel_inv is None and (release_res.data or {}).get("releases") and inv.has_source:
        release_ok = False  # リリースはあるがタグ時点を検査できなかった
    if release_ok and r.status != "ERROR":
        r.verified_scopes.append(f"vuln-release:{repo.id}")

    r.findings += bucket_findings(ctx, repo, details, hits, tag, rel_inv is not None)
    r.data["packages_checked"] = len({(p.ecosystem, p.name, p.version) for _, p in all_pkgs})
    r.data["scopes"] = [{"scope": s, "ref": i.ref, "commit": i.commit_sha[:12]} for s, i in scopes]
    return r


def _native_coverage(ctx: Context, repo: Repo, inv: Inventory, r: CheckResult) -> None:
    vcpkg_pkgs: list[dict] = []
    for path in inv.custom_locks:
        try:
            got = vcpkg_list_from_json(read_blob(ctx.reader, inv, path))
        except HttpError:
            got = None
            r.fail(f"{path} を取得できません")
        if got:
            vcpkg_pkgs += got
    native_manifests = [m.path for m in inv.manifests if m.ecosystem in ("vcpkg", "conan")]
    if vcpkg_pkgs or native_manifests:
        names = ", ".join(sorted({p["name"] for p in vcpkg_pkgs})[:12])
        note = "vcpkg/Conan は OSV のエコシステムに無く、自動照合できない（月次の定期点検で手動確認）"
        if vcpkg_pkgs:
            note += f"。一覧 {len(vcpkg_pkgs)} 件: {names}…"
        r.cover("vuln.native-packages", UNSUPPORTED, note)
        r.data["native_packages"] = vcpkg_pkgs
    if inv.native_sources:
        r.cover("vuln.native", UNSUPPORTED, f"C/C++ ソース {inv.native_sources} 件。同梱・システム依存ライブラリの既知脆弱性は自動照合できない")


def _submodule_commits(ctx: Context, repo: Repo, inv: Inventory, r: CheckResult) -> dict[str, list[tuple[str, Package]]]:
    out: dict[str, list[tuple[str, Package]]] = defaultdict(list)
    if not inv.submodules:
        return out
    ok = True
    notes = []
    for sm in inv.submodules:
        try:
            ids = ctx.osv.query_commit(sm["sha"])
        except HttpError as e:
            ok = False
            r.fail(f"サブモジュール {sm['path']} のコミット照合に失敗: {e.kind}")
            continue
        pkg = Package("GIT", sm.get("url") or sm["path"], sm["sha"][:12], sm["path"])
        for vid in ids:
            out[vid].append(("default", pkg))
        notes.append(f"{sm['path']}@{sm['sha'][:10]}: OSV {len(ids)} 件")
        adv = _upstream_advisories(ctx, repo, sm, r)
        if adv:
            notes.append(adv)
    level = COV_PARTIAL if ok else UNKNOWN
    r.cover(
        "vuln.submodule",
        level,
        "; ".join(notes) + "。OSV のコミット照合は OSV が索引した上流でのみ有効で、0 件は安全の根拠にならない",
    )
    if ok:
        r.verified_scopes.append(f"vuln:{repo.id}:GIT")
    return out


def _upstream_advisories(ctx: Context, repo: Repo, sm: dict, r: CheckResult) -> str:
    url = sm.get("url") or ""
    if "github.com/" not in url:
        return ""
    full = url.split("github.com/", 1)[1].removesuffix(".git").strip("/")
    try:
        advs = ctx.reader.security_advisories(full)
    except HttpError as e:
        return f"上流 {full} の公開勧告を取得できない（{e.kind}）"
    if not advs:
        return f"上流 {full} の公開セキュリティ勧告 0 件"
    r.findings.append(
        Finding(
            key=f"vuln-upstream:{repo.id}:{sm['path']}",
            kind="vuln",
            repo_id=repo.id,
            repo_name=repo.name,
            title=f"[脆弱性] {repo.name}: 上流 {full} に公開セキュリティ勧告 {len(advs)} 件",
            severity="medium",
            summary="サブモジュールの上流に公開済みの勧告がある。固定コミットへの影響は未検証",
            evidence=[a.get("html_url", "") for a in advs[:5]],
            recommendation="勧告の影響版を確認し、固定コミット（サブモジュール）を更新するか判断する",
            unverified=["固定コミットが勧告の影響範囲に入るか"],
            scope=[f"サブモジュール {sm['path']}@{sm['sha'][:10]}"],
            material={"ids": sorted(a.get("ghsa_id", "") for a in advs)},
            verify=[f"vuln:{repo.id}:GIT"],
        )
    )
    return f"上流 {full} の公開勧告 {len(advs)} 件（要確認）"


DEPENDABOT_ECO = {"npm": "npm", "rust": "crates.io", "pip": "PyPI", "go": "Go", "nuget": "NuGet", "composer": "Packagist", "maven": "Maven", "rubygems": "RubyGems"}


def _dependabot(ctx: Context, repo: Repo, r: CheckResult, details: dict[str, Vuln], hits) -> None:
    if ctx.dependabot is None:
        return  # 全リポジトリ共通の設定なので、レポート冒頭に 1 回だけ表示する（runner）
    try:
        alerts = ctx.dependabot.dependabot_alerts(repo.full_name)
    except HttpError as e:
        if e.kind == "forbidden" and "disabled" in e.message.lower():
            r.cover("vuln.dependabot", UNSUPPORTED, "このリポジトリで Dependabot alerts が無効")
        else:
            r.cover("vuln.dependabot", UNKNOWN, f"取得失敗: {e.kind} ({e.status})")
            r.fail(f"Dependabot alerts の取得に失敗: {e.kind}（今回は脆弱性 Issue を閉じない）")
            r.verified_scopes = [t for t in r.verified_scopes if not t.startswith("vuln")]
        return
    known = set(details)
    for v in details.values():
        known |= set(v.aliases)
    extra = 0
    for a in alerts:
        adv = a.get("security_advisory") or {}
        ghsa = adv.get("ghsa_id")
        if not ghsa or ghsa in known:
            continue
        extra += 1
        dep = (a.get("dependency") or {})
        pkg = dep.get("package") or {}
        sev = str((a.get("security_vulnerability") or {}).get("severity") or adv.get("severity") or "medium").lower()
        sev = {"moderate": "medium"}.get(sev, sev)
        if sev not in SEVERITIES:
            sev = "medium"
        details[ghsa] = Vuln(
            id=ghsa,
            aliases=[adv.get("cve_id")] if adv.get("cve_id") else [],
            summary=str(adv.get("summary", ""))[:300],
            severity=sev,
            severity_source="dependabot",
            cvss_vector=None,
            published=adv.get("published_at"),
            modified=adv.get("updated_at"),
            references=[a.get("html_url", "")] if a.get("html_url") else [],
            informational=None,
        )
        eco = DEPENDABOT_ECO.get(str(pkg.get("ecosystem")), str(pkg.get("ecosystem")))
        hits[ghsa].append(("default", Package(eco, str(pkg.get("name")), "?", str(dep.get("manifest_path")), dev=(dep.get("scope") == "development"))))
    r.cover("vuln.dependabot", SUPPORTED, f"open {len(alerts)} 件（OSV に無いもの {extra} 件）")


def _group(details: dict[str, Vuln]) -> list[list[str]]:
    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for vid, v in details.items():
        for a in v.aliases:
            parent[find(a)] = find(vid)
        find(vid)
    groups: dict[str, list[str]] = defaultdict(list)
    for vid in details:
        groups[find(vid)].append(vid)
    return [sorted(g, key=_id_rank) for g in groups.values()]


ECO_JA = {"npm": "npm", "crates.io": "Cargo", "PyPI": "Python", "GIT": "サブモジュール", "Go": "Go", "NuGet": "NuGet", "Packagist": "Composer"}


def _advisory_view(group: list[str], details: dict[str, Vuln]) -> dict:
    vulns = [details[i] for i in group]
    return {
        "id": group[0],
        "ids": group,
        "aliases": sorted({a for v in vulns for a in v.aliases} | set(group)),
        "severity": max((v.severity for v in vulns), key=lambda s: SEVERITY_RANK[s]),
        "unknown_severity": all(v.severity_source == "unknown" for v in vulns),
        "informational": all(v.informational for v in vulns),
        "summary": vulns[0].summary,
        "vulns": vulns,
    }


def _min_fix(installed: str, fixed: list[str]) -> str | None:
    """installed より新しい修正版のうち最小のもの。"""
    best = None
    for f in fixed:
        if (compare(f, installed) or 0) > 0 and (best is None or (compare(f, best) or 0) < 0):
            best = f
    return best


def bucket_findings(ctx: Context, repo: Repo, details: dict[str, Vuln], hits, tag: str | None, release_scanned: bool) -> list[Finding]:
    """勧告ごとではなく「リポジトリ × エコシステム × 本番/開発用」に束ねて 1 件にする。

    利用者が取る行動（その依存一式を更新する）の単位に合わせ、初回から Issue が大量に作られないようにする。
    個々の勧告 ID は本文の表と material に残るので、増減は「内容の変化」として 1 コメントで知らせる。
    """
    min_sev = ctx.policy("issue_policy", "vuln_min_severity", "low", repo.id, repo.name)
    downgrade = ctx.policy("issue_policy", "dev_only_downgrade", True, repo.id, repo.name)
    buckets: dict[tuple[str, str], dict] = {}
    info_pkgs: list[str] = []
    suppressed_adv: list[str] = []
    for group in _group(details):
        adv = _advisory_view(group, details)
        sup = ctx.cfg.suppression_for(f"vuln:{repo.id}:{adv['id']}", adv["aliases"])
        if sup and sup.active(ctx.today):
            suppressed_adv.append(f"{adv['id']}（{sup.status}、{sup.until or '期限なし'}まで: {sup.reason}）")
            continue
        entries = sorted({(s, p) for i in group for s, p in hits[i]}, key=lambda x: (x[1].ecosystem, x[1].name, x[1].version, x[1].path, x[0]))
        for scope, p in entries:
            if adv["informational"] and adv["severity"] == INFO:
                kinds = ", ".join(sorted({v.informational for v in adv["vulns"] if v.informational}))
                info_pkgs.append(f"{p.name} {p.version}（{adv['id']}: {kinds}）")
                continue
            eco = p.ecosystem
            same = [q for s2, q in entries if s2 == "default" and q.name == p.name]
            kind = "dev" if same and all(q.dev for q in same) else "prod"
            b = buckets.setdefault((eco, kind), {"pkgs": {}, "advs": {}})
            pk = b["pkgs"].setdefault((p.name, p.version), {"name": p.name, "version": p.version, "paths": set(), "scopes": set(), "advs": set()})
            pk["paths"].add(p.path)
            pk["scopes"].add("main" if scope == "default" else (tag or "release"))
            pk["advs"].add(adv["id"])
            b["advs"][adv["id"]] = adv
    out: list[Finding] = []
    for (eco, kind), b in sorted(buckets.items()):
        advs = b["advs"]
        sev = max((a["severity"] for a in advs.values()), key=lambda s: SEVERITY_RANK[s])
        orig_sev = sev
        unverified = ["アプリから脆弱なコードが実際に呼ばれるか（到達可能性）"]
        if kind == "dev" and downgrade and sev != INFO:
            sev = SEVERITIES[min(SEVERITIES.index(sev) + 1, len(SEVERITIES) - 2)]
            unverified.append(f"開発用依存のみで検出（重要度を {SEVERITY_JA[orig_sev]} → {SEVERITY_JA[sev]} に 1 段階下げた。設定 issue_policy.dev_only_downgrade）。ビルド成果物に入らないかは未検証")
        if any(a["unknown_severity"] for a in advs.values()):
            unverified.append("深刻度（GHSA 区分・CVSS v3）が提供されていない勧告は Medium と仮定")
        if eco == "crates.io":
            oss = sorted({o for a in advs.values() for v in a["vulns"] for o in v.affected_os()})
            unverified.append("Cargo.lock は全プラットフォーム向けの依存を含む。Windows 向けビルドに含まれるかは未検証" + (f"（勧告上の影響 OS: {', '.join(oss)}）" if oss else ""))
        if eco == "GIT":
            unverified.append("サブモジュールのコミット照合は OSV が索引した上流でのみ有効")
        pkgs = sorted(b["pkgs"].values(), key=lambda x: (-max(SEVERITY_RANK[advs[i]["severity"]] for i in x["advs"]), x["name"]))
        in_release = any(s != "main" for pk in pkgs for s in pk["scopes"]) if release_scanned else None
        in_main = any("main" in pk["scopes"] for pk in pkgs)
        if in_release:
            unverified.append(f"配布中の {tag} のバイナリがタグ時点のロックファイルどおりに作られたか")
        rows = ["| パッケージ | 版 | 勧告 | 最高 | 解消に要る最小版（推定） | 範囲 |", "|---|---|---|---|---|---|"]
        recs = []
        for pk in pkgs:
            top = max((advs[i]["severity"] for i in pk["advs"]), key=lambda s: SEVERITY_RANK[s])
            need, no_fix = None, 0
            for i in pk["advs"]:
                fx = _min_fix(pk["version"], [f for v in advs[i]["vulns"] for f in v.fixed_versions(eco, pk["name"])])
                if fx is None:
                    no_fix += 1
                elif need is None or (compare(fx, need) or 0) > 0:
                    need = fx
            nofix_s = f"（修正版なし {no_fix} 件）" if no_fix else ""
            rows.append(f"| `{pk['name']}` | {pk['version']} | {len(pk['advs'])} | {SEVERITY_JA[top]} | {need or '—'}{nofix_s} | {'・'.join(sorted(pk['scopes']))} |")
            if need:
                recs.append(f"`{pk['name']}` {pk['version']} → {need} 以上")
        n_adv = len(advs)
        label = ECO_JA.get(eco, eco) + ("（開発用）" if kind == "dev" else "")
        top_ids = sorted(advs.values(), key=lambda a: (-SEVERITY_RANK[a["severity"]], a["id"]))
        detail = ["", "| 勧告 | 重要度 | 概要 |", "|---|---|---|"]
        for a in top_ids[:40]:
            detail.append(f"| [{a['id']}](https://osv.dev/vulnerability/{a['id']}) | {SEVERITY_JA[a['severity']]} | {a['summary'][:90].replace('|', '/')} |")
        if n_adv > 40:
            detail.append(f"| …ほか {n_adv - 40} 件 | | 実行レポート JSON を参照 |")
        summary = f"{label} 依存 {len(pkgs)} パッケージに既知脆弱性 {n_adv} 件。\n\n" + "\n".join(rows) + "\n" + "\n".join(detail)
        if suppressed_adv:
            summary += "\n\n抑制中の勧告（suppressions.json）: " + "; ".join(suppressed_adv[:10])
        rec = ["依存を更新してロックファイルを再生成する（多くは `npm update` / `cargo update` / 版の引き上げで解消）"]
        if recs:
            rec.append("目安: " + "; ".join(recs[:12]) + (" ほか" if len(recs) > 12 else ""))
        if in_release and in_main:
            rec.append(f"配布中の {tag} にも含まれる可能性がある。修正後に新しいリリースを配布する")
        elif in_release and not in_main:
            rec.insert(0, f"最新ソースでは解消済み。配布中の {tag} には残っている可能性があるため、新しいリリースを配布する")
        rec.append("使わない・影響しないと判断した勧告は suppressions.json に理由と期限付きで記録する（キー vuln:<リポジトリID>:<勧告ID>）")
        where = "+".join(x for x in (("main" if in_main else ""), (tag if in_release else "")) if x)
        paths = sorted({path for pk in pkgs for path in pk["paths"]})
        out.append(Finding(
            key=f"vuln:{repo.id}:{eco}:{kind}",
            kind="vuln",
            repo_id=repo.id,
            repo_name=repo.name,
            title=f"[脆弱性] {repo.name}: {label} 依存に既知脆弱性 {n_adv} 件（最高 {SEVERITY_JA[sev]}）",
            severity=sev,
            summary=summary,
            evidence=[f"https://osv.dev/vulnerability/{a['id']}" for a in top_ids[:5]],
            recommendation="\n".join(f"- {x}" for x in rec),
            unverified=unverified,
            scope=[f"依存定義: {', '.join(paths[:5])}", f"範囲: {where}（main = 既定ブランチの最新、タグ = 最新リリース時点のソース）"],
            material={
                "advisories": sorted(advs),
                "packages": sorted(f"{pk['name']}@{pk['version']}" for pk in pkgs),
                "where": where,
            },
            issue=sev != INFO and severity_at_least(sev, min_sev),
            verify=[f"vuln:{repo.id}:{eco}", f"vuln-release:{repo.id}"],
        ))
    if info_pkgs:
        items = sorted(set(info_pkgs))
        out.append(Finding(
            key=f"vuln-info:{repo.id}", kind="vuln", repo_id=repo.id, repo_name=repo.name,
            title=f"[情報] {repo.name}: 保守終了などの情報提供 {len(items)} 件（RUSTSEC informational）",
            severity=INFO, summary="; ".join(items[:20]), evidence=["https://rustsec.org/"],
            recommendation="代替クレートへの移行を中長期で検討する（直接依存でなければ上流の更新待ち）",
            material={"items": items}, issue=False, verify=[f"vuln:{repo.id}:crates.io"],
        ))
    return out
