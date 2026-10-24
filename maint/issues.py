"""保守 Issue の同期。

規則（README「Issue の扱い」と同じ）:
1. 一意キー（本文の maint-key）で既存 Issue を探す。脆弱性は別 ID（CVE/GHSA）の一致でも同一とみなす
2. 内容（fingerprint）が変わったときだけ本文を更新し、変化をコメントする。変わらなければ何もしない
   （最終確認日時の更新は refresh_days ごとに本文だけ。本文の編集は通知を出さない）
3. 検出が消えた Issue は、今回その範囲の検査が成功した（verify トークンが全部揃った）ときだけ閉じる。
   取得失敗・レート制限・権限不足・スキャナ未対応・リポジトリ消失では閉じない
4. 人が閉じた Issue は再オープンしない（ツールが閉じたもの＝maint:resolved は再検出で再オープンする）
5. suppressions.json の抑制中は新規作成もコメントもしない。期限切れでラベルを外し、1 回だけ知らせる
"""

from __future__ import annotations

import datetime as dt
import json
import re
from dataclasses import dataclass, field

from .config import Config
from .github import IssueWriter
from .http import HttpError
from .model import DUE_DAYS, SEVERITY_JA, SEVERITY_RANK, Finding
from .checks.manual import checked_items

AUTO = "maint:auto"
DASHBOARD = "maint:dashboard"
RESOLVED = "maint:resolved"
SUPPRESSED = "maint:suppressed"
SUPERSEDED = "maint:superseded"
MANUAL = "maint:manual-check"
LABELS = {
    AUTO: ("5319e7", "okakanatto-maintenance が管理する Issue"),
    DASHBOARD: ("0e8a16", "監視ダッシュボード（自動更新。閉じない）"),
    RESOLVED: ("c5def5", "検証済みで自動クローズ（再検出で再オープン）"),
    SUPPRESSED: ("d4c5f9", "suppressions.json で抑制中"),
    SUPERSEDED: ("ededed", "翌月の点検 Issue に引き継ぎ"),
    MANUAL: ("fbca04", "期限付きの定期点検（人が確認）"),
    "kind:vuln": ("b60205", "既知脆弱性"),
    "kind:deps": ("1d76db", "依存関係の更新"),
    "kind:ci": ("0052cc", "CI・開発環境"),
    "kind:eol": ("e99695", "サポート終了"),
    "kind:health": ("fef2c0", "監視不能・検査失敗の継続"),
    "kind:lifecycle": ("bfdadc", "監視対象の消失・状態変化"),
    "kind:manual": ("fbca04", "定期点検"),
    "sev:critical": ("b60205", "重要度 Critical"),
    "sev:high": ("d93f0b", "重要度 High"),
    "sev:medium": ("fbca04", "重要度 Medium"),
    "sev:low": ("c2e0c6", "重要度 Low"),
    "sev:info": ("ededed", "重要度 Info"),
}
META_RE = re.compile(r"<!--\s*maint-meta:\s*(\{.*?\})\s*-->", re.S)
MAX_BODY = 60000


@dataclass
class SyncResult:
    actions: list[dict] = field(default_factory=list)  # 実行した（dry-run では予定の）操作
    observations: list[dict] = field(default_factory=list)  # 操作しなかったが報告すべきこと
    errors: list[str] = field(default_factory=list)
    issue_numbers: dict[str, int] = field(default_factory=dict)  # key -> number

    def act(self, op: str, key: str, number: int | None = None, **kw):
        self.actions.append({"op": op, "key": key, "number": number, **kw})

    def observe(self, what: str, key: str, number: int | None = None, **kw):
        self.observations.append({"what": what, "key": key, "number": number, **kw})


# --- 本文の描画 ----------------------------------------------------------

_MENTION = re.compile(r"@(?=[A-Za-z0-9-])")
_REF = re.compile(r"#(?=\d)")  # #12・owner/repo#12 の両方
_GH_REF = re.compile(r"\bGH-(?=\d)", re.I)
_GH_ISSUE_URL = re.compile(r"(?:https?://)?(?:www\.)?github\.com/[^\s)`]+/(?:issues|pull|discussions)/\d+[^\s)`]*", re.I)
SAFE_LINK_HOSTS = ("https://osv.dev/", "https://nvd.nist.gov/", "https://github.com/advisories/", "https://rustsec.org/",
                   "https://endoflife.date/", "https://docs.github.com/", "https://www.npmjs.com/", "https://crates.io/",
                   "https://pypi.org/", "https://learn.microsoft.com/", "https://www.cve.org/")


def neutralize(text: str) -> str:
    """外部由来の文字列から @メンションと #番号・Issue URL の自動リンク（相手側への通知・相互参照）を消す。"""
    text = _GH_ISSUE_URL.sub(lambda m: "`" + m.group(0) + "`", str(text))
    text = _MENTION.sub("@\u200b", text)
    text = _REF.sub("#\u200b", text)
    text = _GH_REF.sub(lambda m: m.group(0)[:2] + "\u200b-", text)
    return text


def link(url: str) -> str:
    url = str(url).strip()
    if not url:
        return ""
    if url.startswith(SAFE_LINK_HOSTS):
        return url
    if re.match(r"^https://github\.com/[\w.-]+/[\w.-]+(/(releases|actions|security)[^\s]*)?$", url):
        return url
    return "`" + url.replace("`", "") + "`"  # 自動リンクさせない（相手リポジトリへの相互参照を作らない）


def render_body(f: Finding, meta: dict, run_url: str | None) -> str:
    sev = SEVERITY_JA[f.severity]
    due = DUE_DAYS.get(f.severity)
    first = meta.get("first_seen", "")[:10]
    due_s = f"{due} 日以内（初回検出 {first} から）" if due else "期限なし（情報）"
    lines = [
        "## 概要",
        f"- 対象: {f.repo_name or '中央監視'}" + (f"（リポジトリ ID {f.repo_id}）" if f.repo_id else ""),
        *([f"- **修正先**: {neutralize(f.fix_note)}"] if f.fix_note else []),
        f"- 種別: {f.kind} ／ 重要度: **{sev}** ／ 対応目安: {due_s}",
        "",
        neutralize(f.summary),
        "",
        "## 根拠",
        *[f"- {link(e)}" for e in f.evidence],
        "",
        "## 推奨対応",
        neutralize(f.recommendation) or "- （なし）",
        "",
        "## 検査範囲",
        *[f"- {neutralize(s)}" for s in f.scope],
        "",
        "## 未検証事項",
        *([f"- {neutralize(u)}" for u in f.unverified] or ["- （なし）"]),
        "",
        "## 状態",
        f"- 初回検出: {first}",
        f"- 最終確認: {meta.get('last_refreshed', '')[:16].replace('T', ' ')} UTC" + (f"（[実行記録]({run_url})）" if run_url else ""),
        "- 誤検知・保留・リスク受容は `config/suppressions.json` に期限付きで記録する（README「誤検知の抑制」）",
        "",
        f"<!-- maint-key: {f.key} -->",
        "<!-- maint-meta: " + json.dumps(meta, ensure_ascii=True, sort_keys=True).replace("--", "-\\u002d") + " -->",
    ]
    body = "\n".join(lines)
    if len(body) > MAX_BODY:
        body = body[: MAX_BODY - 2000] + "\n\n…（長すぎるため省略。実行レポートの JSON を参照）\n\n" + "\n".join(lines[-2:])
    return body


def parse_meta(body: str | None) -> dict:
    m = META_RE.search(body or "")
    if not m:
        return {}
    try:
        d = json.loads(m.group(1))
        return d if isinstance(d, dict) else {}
    except ValueError:
        return {}


def labels_for(f: Finding, suppressed: bool) -> list[str]:
    out = [AUTO, f"kind:{f.kind}", f"sev:{f.severity}"]
    if f.kind == "manual":
        out.append(MANUAL)
    if suppressed:
        out.append(SUPPRESSED)
    return out


def _label_names(issue: dict) -> set[str]:
    return {lb["name"] if isinstance(lb, dict) else str(lb) for lb in issue.get("labels", [])}


def _is_verified(token: str, verified: set[str]) -> bool:
    if token in verified:
        return True
    prefix = token.rsplit(":", 1)[0]
    return f"{prefix}:*" in verified


_ADV_ID = re.compile(r"^(GHSA|RUSTSEC|PYSEC|GO|CVE|OSV)-[\w-]+$")
_LIST_LABELS = {"ids": "上流の勧告", "items": "項目", "files": "ファイル"}
_SCALAR_LABELS = {
    "where": "範囲", "state": "状態", "conclusion": "最新の実行結果", "lag": "メジャー版の遅れ", "version": "版",
    "deprecated": "非推奨", "cycle": "サイクル", "product": "製品", "label": "ランナー", "path": "ワークフロー",
    "from_major": "使用中のメジャー版", "check": "検査", "runtime": "実行環境",
}
_MAX_ITEMS = 10


def _adv(i: str) -> str:
    i = str(i)
    return f"[{i}](https://osv.dev/vulnerability/{i})" if _ADV_ID.match(i) else f"`{neutralize(i)}`"


def _code(x) -> str:
    return "`" + neutralize(str(x)).replace("`", "") + "`"


def _join(items: list, fmt) -> str:
    shown = "、".join(fmt(x) for x in items[:_MAX_ITEMS])
    return shown + (f" ほか {len(items) - _MAX_ITEMS} 件" if len(items) > _MAX_ITEMS else "")


def _where_ja(w) -> str:
    """'main+v1.0.0' → '最新ソース（main）と配布中の v1.0.0'"""
    if not w:
        return "（検出なし）"
    parts = str(w).split("+")
    tags = [p for p in parts if p != "main"]
    if "main" in parts and tags:
        return f"最新ソース（main）と配布中の {tags[0]}"
    if "main" in parts:
        return "最新ソース（main）のみ"
    return f"配布中の {tags[0]} のみ（最新ソースでは解消済み）"


def _split_pkg(s: str) -> tuple[str, str]:
    name, sep, ver = str(s).rpartition("@")
    return (name, ver) if sep and name else (str(s), "")


def _package_lines(old: list, new: list) -> list[str]:
    om: dict[str, list[str]] = {}
    nm: dict[str, list[str]] = {}
    for s in old or []:
        n, v = _split_pkg(s)
        om.setdefault(n, []).append(v)
    for s in new or []:
        n, v = _split_pkg(s)
        nm.setdefault(n, []).append(v)
    lines = []
    updated = [n for n in sorted(set(om) & set(nm)) if sorted(om[n]) != sorted(nm[n])]
    if updated:
        lines.append("版が変わったパッケージ: " + _join(updated, lambda n: f"{_code(n)} {'・'.join(sorted(om[n]))} → {'・'.join(sorted(nm[n]))}"))
    gone = sorted(set(om) - set(nm))
    if gone:
        lines.append(f"対象から外れたパッケージ（解消・抑制を含む）{len(gone)} 件: " + _join(gone, lambda n: f"{_code(n)} {'・'.join(sorted(om[n]))}"))
    came = sorted(set(nm) - set(om))
    if came:
        lines.append(f"新たに該当したパッケージ {len(came)} 件: " + _join(came, lambda n: f"{_code(n)} {'・'.join(sorted(nm[n]))}"))
    return lines


def _advisory_lines(om: dict, nm: dict) -> list[str]:
    oa, na = list(om.get("advisories") or []), list(nm.get("advisories") or [])
    os_, ns = list(om.get("suppressed") or []), list(nm.get("suppressed") or [])
    lines = []
    if len(oa) != len(na):
        lines.append(f"勧告の件数: {len(oa)} 件 → {len(na)} 件")
    added = [x for x in na if x not in oa and x not in os_]
    if added:
        lines.append(f"増えた勧告 {len(added)} 件: " + _join(added, _adv))
    from_sup = [x for x in na if x not in oa and x in os_]
    if from_sup:
        lines.append(f"抑制が外れて戻った勧告 {len(from_sup)} 件: " + _join(from_sup, _adv))
    to_sup = [x for x in oa if x not in na and x in ns]
    if to_sup:
        lines.append(f"抑制した勧告（suppressions.json）{len(to_sup)} 件: " + _join(to_sup, _adv))
    fixed = [x for x in oa if x not in na and x not in ns]
    if fixed:
        lines.append(f"解消した勧告 {len(fixed)} 件: " + _join(fixed, _adv))
    new_sup = [x for x in ns if x not in os_ and x not in oa]  # 前回は対象外だった勧告をいきなり抑制
    if new_sup:
        lines.append(f"抑制中の勧告が増えた {len(new_sup)} 件: " + _join(new_sup, _adv))
    return lines


def _dict_lines(label: str, old: dict, new: dict) -> list[str]:
    old, new = old or {}, new or {}
    lines = []
    came = [k for k in sorted(new) if k not in old]
    gone = [k for k in sorted(old) if k not in new]
    changed = [k for k in sorted(set(old) & set(new)) if old[k] != new[k]]
    if came:
        lines.append(f"{label}が増えた: " + _join(came, _code))
    if gone:
        lines.append(f"{label}が解消: " + _join(gone, _code))
    for k in changed[:_MAX_ITEMS]:
        ov, nv = old[k], new[k]
        if isinstance(ov, dict) and isinstance(nv, dict):
            diffs = [f"{_SCALAR_LABELS.get(x, x)} {_brief(ov.get(x))} → {_brief(nv.get(x))}" for x in sorted(set(ov) | set(nv)) if ov.get(x) != nv.get(x)]
            lines.append(f"{_code(k)}: " + "、".join(diffs))
        else:
            lines.append(f"{_code(k)}: {_brief(ov)} → {_brief(nv)}")
    return lines


def _brief(v) -> str:
    if isinstance(v, list):
        return "・".join(neutralize(str(x)) for x in v[:5]) + (" ほか" if len(v) > 5 else "") if v else "なし"
    if isinstance(v, bool):
        return "はい" if v else "いいえ"
    return neutralize(str(v)) if v not in (None, "") else "なし"


def _change_summary(old: dict, f: Finding) -> str:
    """前回と今回の material を比べ、人が読める変化の箇条書きにする（一覧を途中で切らない。長い一覧は件数＋先頭 10 件）。"""
    lines: list[str] = []
    if old.get("sev") and old["sev"] != f.severity:
        lines.append(f"重要度: {SEVERITY_JA.get(old['sev'], old['sev'])} → {SEVERITY_JA[f.severity]}")
    om, nm = old.get("material") or {}, f.material or {}
    done = {"merged"}
    if "advisories" in om or "advisories" in nm:
        lines += _advisory_lines(om, nm)
        done |= {"advisories", "suppressed"}
    if om.get("packages") != nm.get("packages") and ("packages" in om or "packages" in nm):
        lines += _package_lines(om.get("packages"), nm.get("packages"))
    done.add("packages")
    if om.get("where") != nm.get("where") and ("where" in om or "where" in nm):
        lines.append(f"範囲: {_where_ja(om.get('where'))} → {_where_ja(nm.get('where'))}")
        if nm.get("where") and "main" not in str(nm.get("where")).split("+"):
            lines.append("→ 最新ソースでは解消済み。新しい版をリリースすると、次の監視でこの Issue は自動で閉じます")
    done.add("where")
    for k in sorted((set(om) | set(nm)) - done):
        ov, nv = om.get(k), nm.get(k)
        if ov == nv:
            continue
        label = _SCALAR_LABELS.get(k) or _LIST_LABELS.get(k) or k
        if isinstance(ov, list) or isinstance(nv, list):
            ol, nl = list(ov or []), list(nv or [])
            came, gone = [x for x in nl if x not in ol], [x for x in ol if x not in nl]
            fmt = _adv if k == "ids" else _code
            if came:
                lines.append(f"{label}が増えた {len(came)} 件: " + _join(came, fmt))
            if gone:
                lines.append(f"{label}が減った {len(gone)} 件: " + _join(gone, fmt))
        elif isinstance(ov, dict) or isinstance(nv, dict):
            lines += _dict_lines({"actions": "該当アクション"}.get(k, label), ov if isinstance(ov, dict) else {}, nv if isinstance(nv, dict) else {})
        else:
            lines.append(f"{label}: {_brief(ov)} → {_brief(nv)}")
    if not lines and om.get("merged") != nm.get("merged"):
        lines.append("検出の根拠になったファイルの内訳が変わった")
    return "\n".join(f"- {x}" for x in lines[:30]) or "- 検出内容が変わった（細部のみ）"


# --- 同期 ----------------------------------------------------------------


def index_issues(issues: list[dict]) -> tuple[dict[str, dict], list[dict]]:
    """key -> issue。同じキーが複数あれば最も古い番号を正とし、残りを duplicates として返す。"""
    by_key: dict[str, dict] = {}
    dups: list[dict] = []
    for iss in sorted(issues, key=lambda i: i["number"]):
        m = re.search(r"<!--\s*maint-key:\s*(\S+)\s*-->", iss.get("body") or "")
        if not m:
            continue
        key = m.group(1)
        if key in by_key:
            dups.append(iss)
        else:
            by_key[key] = iss
    return by_key, dups


def ensure_labels(writer: IssueWriter, res: SyncResult) -> None:
    try:
        have = {lb["name"] for lb in writer.labels()}
    except HttpError as e:
        res.errors.append(f"ラベル一覧を取得できない: {e.kind}")
        return
    for name, (color, desc) in LABELS.items():
        if name not in have:
            writer.create_label(name, color, desc)
            res.act("create_label", name)


def merge_findings(findings: list[Finding]) -> list[Finding]:
    """同じキーの Finding を 1 件にまとめる（同じ製品を複数ファイルで使う等）。重要度は高い方、根拠・範囲は和集合。"""
    out: dict[str, Finding] = {}
    for f in findings:
        g = out.get(f.key)
        if g is None:
            out[f.key] = f
            continue
        if SEVERITY_RANK[f.severity] > SEVERITY_RANK[g.severity]:
            g.severity, g.title, g.summary = f.severity, f.title, f.summary
        g.evidence = list(dict.fromkeys(g.evidence + f.evidence))
        g.scope = list(dict.fromkeys(g.scope + f.scope))
        g.unverified = list(dict.fromkeys(g.unverified + f.unverified))
        g.aliases = sorted(set(g.aliases) | set(f.aliases))
        g.verify = sorted(set(g.verify) | set(f.verify))
        g.issue = g.issue or f.issue
        g.suppressed = g.suppressed and f.suppressed
        if f.material != g.material:
            g.material = {**g.material, "merged": sorted({json.dumps(g.material, sort_keys=True, ensure_ascii=False), json.dumps(f.material, sort_keys=True, ensure_ascii=False)} | set(g.material.get("merged", [])))}
    return list(out.values())


def _escalated(old: dict, f: Finding) -> list[str]:
    """人が閉じた Issue に知らせるべき悪化（重要度の上昇・新しい勧告）。"""
    out = []
    if old.get("sev") in SEVERITY_RANK and SEVERITY_RANK[f.severity] > SEVERITY_RANK[old["sev"]]:
        out.append(f"重要度 {SEVERITY_JA[old['sev']]} → {SEVERITY_JA[f.severity]}")
    new_ids = sorted(set(f.material.get("advisories", [])) - set((old.get("material") or {}).get("advisories", [])))
    if new_ids:
        out.append("新しい勧告: " + ", ".join(new_ids[:10]) + (" ほか" if len(new_ids) > 10 else ""))
    return out


def sync(writer: IssueWriter, cfg: Config, issues: list[dict], findings: list[Finding], verified: set[str],
         now: dt.datetime, run_url: str | None, refresh_days: int = 7) -> SyncResult:
    res = SyncResult()
    today = now.date()
    now_iso = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    findings = merge_findings(findings)
    managed = [i for i in issues if DASHBOARD not in _label_names(i)]
    by_key, dups = index_issues(managed)
    for d in dups:
        res.observe("duplicate_issue", "", d["number"], note="同じキーの Issue が複数ある（古い方を正として扱う）")
    alias_index: dict[tuple[str, str], str] = {}
    for key, iss in by_key.items():
        prefix = key.rsplit(":", 1)[0]
        for a in parse_meta(iss.get("body")).get("aliases", []):
            alias_index[(prefix, a)] = key

    matched: set[str] = set()
    for f in findings:
        if f.kind == "manual":
            continue  # 別処理（sync_manual）
        key = f.key
        iss = by_key.get(key)
        if iss is None:
            prefix = key.rsplit(":", 1)[0]
            for a in f.aliases:
                k2 = alias_index.get((prefix, a))
                if k2:
                    iss, key = by_key[k2], k2
                    break
        sup = cfg.suppression_for(f.key, f.aliases) or (cfg.suppression_for(key) if key != f.key else None)
        active = bool(sup and sup.active(today)) or f.suppressed
        # 今回の検査が範囲を最後まで確かめられていない Finding は、内容の変化として扱わない（一時的な失敗で通知が往復しないように）
        complete = all(_is_verified(t, verified) for t in f.verify) if f.verify else True
        if iss is None:
            if not f.issue:
                continue
            if active:
                res.observe("suppressed_not_created", f.key, status=sup.status if sup else "advisory", until=str(sup.until) if sup else "")
                continue
            meta = {"key": f.key, "fp": f.fingerprint(), "sev": f.severity, "verify": f.verify, "aliases": f.aliases,
                    "first_seen": now_iso, "last_refreshed": now_iso, "material": f.material, "fix_note": f.fix_note}
            body = render_body(f, meta, run_url)
            created = writer.create_issue(neutralize(f.title), body, labels_for(f, False))
            num = (created or {}).get("number")
            res.act("create", f.key, num, title=f.title, severity=f.severity)
            res.issue_numbers[f.key] = num
            by_key[f.key] = {"number": num, "state": "open", "title": neutralize(f.title), "body": body,
                             "labels": [{"name": x} for x in labels_for(f, False)]}
            matched.add(f.key)
            continue
        matched.add(key)
        num = iss["number"]
        res.issue_numbers[f.key] = num
        old = parse_meta(iss.get("body"))
        labels = _label_names(iss)
        fp_changed = old.get("fp") != f.fingerprint()
        meta = {**old, "key": key, "fp": f.fingerprint(), "sev": f.severity, "verify": f.verify,
                "aliases": sorted(set(old.get("aliases", [])) | set(f.aliases)), "material": f.material,
                "first_seen": old.get("first_seen") or now_iso}
        if not complete:
            if fp_changed:
                res.observe("unverified_change_skipped", key, num, note="範囲の検査が一部失敗したため、内容の変化として扱わない")
            continue
        if iss.get("state") != "open":
            if RESOLVED in labels and not active:
                meta["last_refreshed"] = now_iso
                new_labels = sorted((labels - {RESOLVED, SUPPRESSED}) | set(labels_for(f, False)))
                writer.update_issue(num, state="open", title=neutralize(f.title), body=render_body(f, meta, run_url), labels=new_labels)
                writer.comment(num, "再検出しました。前回は検証済みで閉じましたが、今回の検査で再び見つかりました。\n\n" + _change_summary(old, f))
                res.act("reopen", key, num, title=f.title)
                continue
            worse = _escalated(old, f) if fp_changed and not active else []
            if worse:
                # 人が閉じた束にも、悪化は 1 回だけ知らせる（再オープンはしない。meta を更新して二度目を出さない）
                meta["last_refreshed"] = now_iso
                writer.update_issue(num, body=render_body(f, meta, run_url))
                writer.comment(num, "閉じられた Issue ですが、新しい検出がありました（再オープンはしません。対応しないなら suppressions.json に期限付きで記録してください）。\n\n"
                               + "\n".join(f"- {neutralize(w)}" for w in worse))
                res.act("notify_closed", key, num)
            else:
                res.observe("closed_still_detected", key, num, note="人が閉じた Issue。再オープンしない（期限付き再評価は suppressions.json で）")
            continue
        want_labels = set(labels_for(f, active))
        stale = (labels - want_labels) & ({SUPPRESSED, RESOLVED} | {lb for lb in labels if lb.startswith(("sev:", "kind:"))})
        missing = want_labels - labels
        label_change = bool(stale or missing)
        refresh_due = _older_than(old.get("last_refreshed"), now, refresh_days)
        title_change = iss.get("title") != neutralize(f.title)
        note_change = old.get("fix_note", "") != f.fix_note  # 修正先の注意が増減した（本文だけ直し、通知はしない）
        meta["fix_note"] = f.fix_note
        if fp_changed or refresh_due or label_change or title_change or note_change:
            meta["last_refreshed"] = now_iso
            writer.update_issue(num, title=neutralize(f.title), body=render_body(f, meta, run_url), labels=sorted((labels - stale) | want_labels))
            res.act("update", key, num, reason=",".join(x for x, c in (("内容", fp_changed), ("定期更新", refresh_due), ("ラベル", label_change), ("題名", title_change), ("修正先", note_change)) if c))
        if SUPPRESSED in labels and not active:
            when = f"（期限 {sup.until}）" if sup and sup.until else ""
            writer.comment(num, f"抑制の再評価期限を過ぎました{when}。内容を確認し、対応するか suppressions.json を更新してください。")
            res.act("suppression_expired", key, num)
        elif fp_changed and not active:
            writer.comment(num, "検出内容が変わりました。\n\n" + _change_summary(old, f))
            res.act("comment_change", key, num)

    # 検出が消えた Issue
    for key, iss in by_key.items():
        if key in matched or iss.get("state") != "open" or key.startswith("manual:"):
            continue
        meta = parse_meta(iss.get("body"))
        tokens = meta.get("verify") or []
        missing_tokens = [t for t in tokens if not _is_verified(t, verified)]
        if tokens and not missing_tokens:
            writer.comment(iss["number"], "今回の検査で解消を確認しました（同じ範囲の検査が成功し、該当の検出がありませんでした）。再検出したら自動で再オープンします。")
            writer.update_issue(iss["number"], state="closed", state_reason="completed", labels=sorted(_label_names(iss) | {RESOLVED}))
            res.act("close", key, iss["number"])
        else:
            res.observe("absent_unverified", key, iss["number"],
                        note="検出されなかったが、範囲の検査が成功していないため閉じない: " + (", ".join(missing_tokens) or "verify 情報なし"))
    return res


def sync_manual(writer: IssueWriter, issues: list[dict], finding: Finding | None, res: SyncResult, run_url: str | None, now: dt.datetime) -> None:
    """月次点検 Issue。作成後は本文を書き換えない（人の ✓ を消さないため）。前月分が開いていれば引き継いで閉じる。"""
    manual = [i for i in issues if (i.get("body") or "").find("<!-- maint-key: manual:") >= 0]
    if finding is None:
        return
    by_key, _ = index_issues(manual)
    if finding.key in by_key:
        res.issue_numbers[finding.key] = by_key[finding.key]["number"]
        return  # 今月分は作成済み
    carried = []
    for key, iss in by_key.items():
        if iss.get("state") == "open":
            done = checked_items(iss.get("body"))
            writer.comment(iss["number"], f"翌月の点検 Issue に引き継ぎます。✓ 済み {len(done)} 項目は完了として記録しました。")
            writer.update_issue(iss["number"], state="closed", state_reason="not_planned", labels=sorted(_label_names(iss) | {SUPERSEDED}))
            res.act("supersede_manual", key, iss["number"])
            carried.append(iss["number"])
    meta = {"key": finding.key, "first_seen": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "last_refreshed": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "items": finding.material.get("items", [])}
    body = render_body(finding, meta, run_url)
    if carried:
        body = f"前月から持ち越しあり（旧 Issue 番号: {', '.join(map(str, carried))}）\n\n" + body
    created = writer.create_issue(neutralize(finding.title), body, labels_for(finding, False))
    res.act("create", finding.key, (created or {}).get("number"), title=finding.title, severity=finding.severity)
    res.issue_numbers[finding.key] = (created or {}).get("number")


def _older_than(iso: str | None, now: dt.datetime, days: int) -> bool:
    if not iso:
        return True
    try:
        t = dt.datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return True
    return (now - t).total_seconds() >= days * 86400 - 3600
