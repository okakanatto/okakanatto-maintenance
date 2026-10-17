"""期限付きの定期点検（月次。リポジトリ横断）。

機械的に監視できない項目（WebView2 の互換性、vcpkg 依存の脆弱性、ソース非公開の配布物 等）を
「自動監視済み」と偽らないために、人が確認するチェックリストとして毎月 1 件の Issue にまとめる。
- 人がチェックボックスに ✓ を付けた項目は、その日を完了日として台帳に記録する
- 完了日 + interval_days を過ぎた項目だけが次の点検 Issue に載る
- この Issue が毎月届くこと自体が、監視が動いている合図になる（届かなければ停止を疑う）
"""

from __future__ import annotations

import datetime as dt
import re

from ..context import Context
from ..model import INFO, Finding

ITEM_MARK = re.compile(r"^\s*-\s*\[([ xX])\].*<!--\s*item:([\w.-]+)\s*-->", re.M)


def checked_items(body: str | None) -> set[str]:
    return {m.group(2) for m in ITEM_MARK.finditer(body or "") if m.group(1) in "xX"}


def applies(item: dict, repo_info: dict) -> bool:
    cond = item.get("applies_to") or {}
    if cond.get("all"):
        return True
    if set(cond.get("build_systems", [])) & set(repo_info.get("build_systems", [])):
        return True
    readme = (repo_info.get("readme") or "").lower()
    if any(s.lower() in readme for s in cond.get("readme_contains", [])):
        return True
    cov = repo_info.get("coverage", {})
    for area in cond.get("coverage_gap", []):
        if cov.get(area) in ("UNSUPPORTED", "UNKNOWN"):
            return True
    if cond.get("has_releases") and repo_info.get("releases"):
        return True
    return False


def due_items(ctx: Context, state: dict, repo_infos: dict[str, dict]) -> list[dict]:
    done = state.setdefault("manual_checks", {})
    out = []
    for item in ctx.cfg.raw.get("manual_checks", []):
        targets = sorted(name for name, info in repo_infos.items() if applies(item, info))
        is_global = bool((item.get("applies_to") or {}).get("global"))
        if not targets and not is_global:
            continue
        last = done.get(item["id"])
        if last:
            try:
                if ctx.today < dt.date.fromisoformat(last) + dt.timedelta(days=int(item["interval_days"])):
                    continue
            except ValueError:
                pass
        out.append({**item, "targets": targets, "last_done": last})
    return out


def record_completions(issues: list[dict], state: dict, today: dt.date) -> list[str]:
    """点検 Issue の ✓ を完了として台帳に記録する。記録した項目 ID を返す。"""
    done = state.setdefault("manual_checks", {})
    recorded = []
    for iss in issues:
        when = (iss.get("closed_at") or iss.get("updated_at") or today.isoformat())[:10]
        for item_id in checked_items(iss.get("body")):
            if done.get(item_id, "") < when:
                done[item_id] = when
                recorded.append(item_id)
    return recorded


def manual_finding(ctx: Context, items: list[dict]) -> Finding | None:
    if not items:
        return None
    period = ctx.today.strftime("%Y-%m")
    due = ctx.today + dt.timedelta(days=int(ctx.cfg.section("issue_policy").get("manual_check_due_days", 14)))
    lines = []
    for it in items:
        tgt = "、".join(it["targets"]) if it["targets"] else "中央監視"
        lines.append(f"- [ ] **{it['title']}** — 対象: {tgt} <!-- item:{it['id']} -->")
        if it.get("how"):
            lines.append(f"  - 確認方法: {it['how']}")
        for s in it.get("sources", [])[:3]:
            lines.append(f"  - 一次情報: {s}")
        lines.append(f"  - 前回完了: {it.get('last_done') or 'なし'} ／ 周期: {it['interval_days']} 日")
    return Finding(
        key=f"manual:{period}",
        kind="manual",
        repo_id=None,
        repo_name="",
        title=f"[定期点検] {period} 月次点検（{len(items)} 項目、期限 {due.isoformat()}）",
        severity=INFO,
        summary="機械的に監視できない項目の点検。確認した項目に ✓ を付け、全部終わったら Issue を閉じる（✓ を付けた日が完了日として記録される）",
        recommendation="\n".join(lines),
        unverified=["この Issue の項目は自動監視されていない"],
        scope=["config/maintenance.json の manual_checks"],
        material={"items": [it["id"] for it in items]},
    )
