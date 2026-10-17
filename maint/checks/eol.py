"""ランタイム・フレームワークのサポート終了（月次）。

リポジトリに書かれた版（ロックファイル・CI 設定・依存一覧）だけを根拠に、endoflife.date のサイクルと突き合わせる。
版が書かれていないもの（開発者の手元の Node.js 等）は UNKNOWN とし、推測で判定しない。
endoflife.date に無いもの（Tauri・WebView2・MSVC 等）は定期点検（manual）で人が確認する。
"""

from __future__ import annotations

import datetime as dt
import json
import re

from ..context import Context
from ..eoldata import match_cycle, product_releases
from ..http import HttpError
from ..inventory import Inventory, read_blob
from ..lockfiles import PARSERS, ParseError, vcpkg_list_from_json
from ..model import COV_PARTIAL, LOW, MEDIUM, NOT_APPLICABLE, SUPPORTED, UNKNOWN, CheckResult, Finding, Repo

NODE_VER = re.compile(r"node-version:\s*['\"]?([\w.*/-]+)")
PY_VER = re.compile(r"python-version:\s*['\"]?([\d.]+)")


def detect_versions(ctx: Context, inv: Inventory, read_errors: list[str] | None = None) -> dict[str, list[tuple[str, str]]]:
    """製品 → [(版, 根拠)]。読めなかったファイルは read_errors に積む（その回は判定を確定させない）。"""
    found: dict[str, list[tuple[str, str]]] = {}
    errs = read_errors if read_errors is not None else []

    def add(product: str, version: str, source: str):
        if version and re.match(r"^\d", version):
            found.setdefault(product, [])
            if (version, source) not in found[product]:
                found[product].append((version, source))

    def text(path: str) -> str:
        try:
            return read_blob(ctx.reader, inv, path).decode("utf-8", "replace")
        except HttpError as e:
            errs.append(f"{path}（{e.kind}）")
            return ""

    for wf in inv.workflows:
        t = text(wf)
        for m in NODE_VER.finditer(t):
            add("nodejs", m.group(1), f"{wf}（setup-node）")
        for m in PY_VER.finditer(t):
            add("python", m.group(1), f"{wf}（setup-python）")
    for p in inv.files:
        base = p.rsplit("/", 1)[-1]
        if base in (".nvmrc", ".node-version"):
            add("nodejs", text(p).strip().lstrip("v"), p)
        elif base == ".python-version":
            add("python", text(p).strip(), p)
    npm_map = {"next": "nextjs", "react": "react", "electron": "electron"}
    for m in inv.manifests:
        if m.kind == "npm-lock":
            try:
                pkgs, _ = PARSERS["npm-lock"](read_blob(ctx.reader, inv, m.path), m.path)
            except (HttpError, ParseError) as e:
                errs.append(f"{m.path}（{type(e).__name__}）")
                continue
            for p in pkgs:
                if p.name in npm_map and p.direct:
                    add(npm_map[p.name], p.version, f"{m.path}（{p.name}）")
        elif m.kind == "npm-manifest":
            try:
                d = json.loads(read_blob(ctx.reader, inv, m.path).decode("utf-8-sig"))
                eng = ((d.get("engines") or {}).get("node")) if isinstance(d, dict) else None
            except (HttpError, ValueError) as e:
                errs.append(f"{m.path}（{type(e).__name__}）")
                eng = None
            if isinstance(eng, str):
                mm = re.search(r"(\d+)", eng)
                if mm and not eng.strip().startswith((">", "^", "~")):
                    add("nodejs", mm.group(1), f"{m.path}（engines.node）")
    for path in inv.custom_locks:
        try:
            raw = read_blob(ctx.reader, inv, path)
            d = json.loads(raw.decode("utf-8-sig"))
        except HttpError as e:
            errs.append(f"{path}（{e.kind}）")
            continue
        except ValueError:
            continue  # JSON でない *lock*.json は対象外
        if isinstance(d, dict) and isinstance(d.get("qt"), dict) and isinstance(d["qt"].get("version"), str):
            add("qt", d["qt"]["version"], f"{path}（qt.version）")
        for p in vcpkg_list_from_json(raw) or []:
            if p["name"] == "qtbase":
                add("qt", p["version"], f"{path}（vcpkg qtbase）")
    return found


def check_eol(ctx: Context, repo: Repo, inv: Inventory) -> CheckResult:
    r = CheckResult("eol")
    if inv.empty or not inv.has_source:
        r.cover("eol", NOT_APPLICABLE if inv.empty else UNKNOWN,
                "コード未登録" if inv.empty else "ソース非公開のため使用ランタイムの版が分からない（定期点検で確認）")
        return r
    read_errors: list[str] = []
    found = detect_versions(ctx, inv, read_errors)
    if read_errors:
        r.fail("版の記載を読めないファイル: " + ", ".join(read_errors[:5]))
    warn_days = int(ctx.policy("eol", "warn_days", 90, repo.id, repo.name))
    checked, failed = [], []
    by_cycle: dict[tuple[str, str], dict] = {}  # 同じ製品・サイクルを複数ファイルで使っていても 1 件にまとめる
    for product, versions in sorted(found.items()):
        try:
            rels = product_releases(ctx, product)
        except HttpError as e:
            failed.append(product)
            r.fail(f"endoflife.date から {product} を取得できない: {e.kind}")
            continue
        if rels is None:
            r.notes.append(f"{product}: endoflife.date に製品がない")
            continue
        checked.append(product)
        if not read_errors:
            r.verified_scopes.append(f"eol:{repo.id}:{product}")
        for version, source in versions:
            cyc = match_cycle(rels, version)
            row = {"product": product, "version": version, "source": source}
            if cyc is None:
                r.notes.append(f"{product} {version}: 対応するサイクルが見つからない（{source}）")
                r.data.setdefault("versions", []).append(row)
                continue
            eol_from = cyc.get("eolFrom")
            row.update({"cycle": cyc.get("name"), "eol": eol_from, "is_eol": cyc.get("isEol"), "latest": (cyc.get("latest") or {}).get("name")})
            r.data.setdefault("versions", []).append(row)
            days = _days_until(eol_from, ctx.today)
            if cyc.get("isEol") or (days is not None and days <= 0):
                sev, state = MEDIUM, f"サポート終了済み（{eol_from}）"
            elif days is not None and days <= warn_days:
                sev, state = LOW, f"あと {days} 日でサポート終了（{eol_from}）"
            else:
                continue
            newest = next((x for x in rels if not x.get("isEol")), None)
            e = by_cycle.setdefault((product, str(cyc.get("name"))), {"sev": sev, "state": state, "uses": [], "newest": newest})
            e["uses"].append(f"{source}: {version}")
    for (product, cycle), e in sorted(by_cycle.items()):
        rec = f"サポート中のサイクル（例: {e['newest'].get('name')}）への移行を計画する" if e["newest"] else "後継版への移行を計画する"
        r.findings.append(Finding(
            key=f"eol:{repo.id}:{product}:{cycle}",
            kind="eol", repo_id=repo.id, repo_name=repo.name,
            title=f"[EOL] {repo.name}: {product} {cycle} が{e['state'].split('（')[0]}",
            severity=e["sev"],
            summary=f"{product} {cycle} を使用（{'; '.join(e['uses'][:5])}）。{e['state']}",
            evidence=[f"https://endoflife.date/{product}"],
            recommendation=rec,
            unverified=["配布中のバイナリが同じ版でビルドされたか", "サポート終了後に公開された脆弱性の影響有無"],
            scope=e["uses"][:5],
            material={"product": product, "cycle": cycle, "state": "eol" if e["sev"] == MEDIUM else "soon"},
            verify=[f"eol:{repo.id}:{product}"],
        ))
    for product in ("nodejs",):
        if product not in found and any(m.ecosystem == "npm" for m in inv.manifests):
            r.notes.append("Node.js の版がリポジトリに書かれていない（ビルドに使う Node の EOL は判定できない）")
    if failed:
        r.cover("eol", COV_PARTIAL if checked else UNKNOWN, f"取得失敗: {', '.join(failed)}")
    elif found:
        r.cover("eol", SUPPORTED if "Node.js の版" not in " ".join(r.notes) else COV_PARTIAL,
                "判定: " + ", ".join(f"{p} {'/'.join(v for v, _ in vs)}" for p, vs in sorted(found.items())))
    else:
        r.cover("eol", UNKNOWN, "版を特定できるランタイム記述が見つからない（定期点検で確認）")
    return r


def _days_until(date_s, today: dt.date) -> int | None:
    if not date_s:
        return None
    try:
        return (dt.date.fromisoformat(str(date_s)[:10]) - today).days
    except ValueError:
        return None
