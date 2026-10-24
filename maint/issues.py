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


def _change_summary(old: dict, f: Finding) -> str:
    parts = []
    if old.get("sev") and old["sev"] != f.severity:
        parts.append(f"重要度 {SEVERITY_JA.get(old['sev'], old['sev'])} → {SEVERITY_JA[f.severity]}")
    om, nm = old.get("material") or {}, f.material
    for k in sorted(set(om) | set(nm)):
        if om.get(k) != nm.get(k):
            ov, nv = json.dumps(om.get(k), ensure_ascii=False)[:120], json.dumps(nm.get(k), ensure_ascii=False)[:120]
            parts.append(f"{k}: `{neutralize(ov)}` → `{neutralize(nv)}`")
    return "\n".join(f"- {p}" for p in parts[:10]) or "- 検出内容が変わった"


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
