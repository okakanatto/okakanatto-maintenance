"""実行レポート（機械可読 JSON と Markdown）。

Markdown は Actions の Job Summary とダッシュボード Issue の本文に使う。
失敗・未実施・未対応を成功の語や色で表さない（「対応」は SUPPORTED かつ検査成功のときだけ）。
"""

from __future__ import annotations

import datetime as dt

from .model import ERROR, PARTIAL, SEVERITY_JA, SEVERITY_RANK, SKIPPED, SUCCESS

LEVEL_JA = {"SUPPORTED": "対応", "PARTIAL": "部分", "UNSUPPORTED": "未対応", "NOT_APPLICABLE": "対象外", "UNKNOWN": "不明"}
STATUS_JA = {SUCCESS: "成功", PARTIAL: "一部失敗", ERROR: "失敗", SKIPPED: "未実施"}
AREA_COLUMNS = [("vuln", "脆弱性"), ("release", "配布版"), ("ci", "CI"), ("deps", "依存更新"), ("eol", "EOL")]
JST = dt.timezone(dt.timedelta(hours=9))


def _jst(iso: str) -> str:
    try:
        return dt.datetime.fromisoformat(iso.replace("Z", "+00:00")).astimezone(JST).strftime("%Y-%m-%d %H:%M JST")
    except (ValueError, AttributeError):
        return str(iso)


def _cell(repo: dict, check: str) -> str:
    c = repo.get("checks", {}).get(check)
    if c is None or c["status"] == SKIPPED:
        return "未実施"
    covs = c.get("coverage", {})
    if not covs:
        return STATUS_JA[c["status"]]
    parts = []
    for area, item in covs.items():
        label = area.split(".", 1)[1] if "." in area else ""
        level = LEVEL_JA.get(item["level"], item["level"])
        parts.append(f"{label}:{level}" if label else level)
    cell = " / ".join(parts)
    if c["status"] == ERROR:
        cell = "**失敗** " + cell
    elif c["status"] == PARTIAL:
        cell = "一部失敗 " + cell
    return cell


def render_markdown(rep: dict, issue_url_base: str | None = None, dashboard: bool = False) -> str:
    run = rep["run"]
    disc = rep["discovery"]
    lines = [f"# 保守監視レポート（{_jst(run['finished'])}）", ""]
    status = run["status"]
    reasons = "／".join(run.get("status_reasons", [])[:4])
    lines.append(f"**実行状態: {status}（{STATUS_JA.get(status, status)}）**" + (f" — {reasons}" if reasons else ""))
    lines.append(f"- 実行した周期: {', '.join(run['periods']) or 'なし'}" + (f" ／ 今回は未実施: {', '.join(run['skipped_periods'])}" if run.get("skipped_periods") else ""))
    if run.get("dry_run"):
        lines.append("- **dry-run**（Issue には何も書き込んでいない）")
    lines.append(
        f"- 監視対象 {len(disc.get('active', []))} 件（新規 {len(disc.get('new', []))}・名前変更 {len(disc.get('renamed', []))}・"
        f"除外 {len(disc.get('excluded', []))}・監視不能 {len(disc.get('missing', []))}）"
    )
    if run.get("run_url"):
        lines.append(f"- 実行記録: {run['run_url']}")
    lines += ["", "> 「検出なし」と言えるのは、下表で「対応」「部分」の範囲だけ。「未対応」「不明」「失敗」「未実施」は検査できていない。", ""]

    # 要対応
    numbers = rep.get("issues", {}).get("numbers", {})
    actionable = sorted((f for f in rep["findings"] if f["issue"]), key=lambda f: (-SEVERITY_RANK[f["severity"]], f["repo"], f["key"]))
    lines.append("## 要対応（Issue 化の対象）")
    if actionable:
        lines += ["| 重要度 | リポジトリ | 内容 | Issue |", "|---|---|---|---|"]
        for f in actionable:
            n = numbers.get(f["key"])
            ref = f"#{n}" if n else ("（dry-run）" if run.get("dry_run") else "（未作成）")
            lines.append(f"| {SEVERITY_JA[f['severity']]} | {f['repo'] or '中央'} | {_md(f['title'])} | {ref} |")
    else:
        lines.append("検査できた範囲では、Issue 化の基準を満たす問題は見つからなかった（未監視の範囲は下表を参照）。")
    lines.append("")

    # カバレッジ表
    lines.append("## リポジトリ別の監視範囲と実行結果")
    lines += ["| リポジトリ | " + " | ".join(n for _, n in AREA_COLUMNS) + " |", "|---|" + "---|" * len(AREA_COLUMNS)]
    for r in rep["repos"]:
        name = r["name"] + ("（新規）" if r.get("is_new") else "")
        if r.get("error"):
            lines.append(f"| {name} | " + " | ".join(["**失敗**"] * len(AREA_COLUMNS)) + " |")
            continue
        lines.append(f"| {name} | " + " | ".join(_cell(r, c) for c, _ in AREA_COLUMNS) + " |")
    lines.append("")

    gaps = []
    for r in rep["repos"]:
        for c in r.get("checks", {}).values():
            for area, item in c.get("coverage", {}).items():
                if item["level"] in ("UNSUPPORTED", "UNKNOWN"):
                    gaps.append(f"- **{r['name']}** `{area}` {LEVEL_JA[item['level']]}: {_md(item['note'])}")
    for m in disc.get("missing", []):
        gaps.append(f"- **{m['name']}**（ID {m['id']}）監視不能: {_md(m.get('label', m['state']))}")
    lines.append("## 監視できていない範囲")
    lines += gaps or ["- なし"]
    lines.append("")

    errs = list(rep.get("errors", []))
    for r in rep["repos"]:
        if r.get("error"):
            errs.append(f"{r['name']}: {r['error']}")
        for c in r.get("checks", {}).values():
            errs += [f"{r['name']} / {c['check']}: {e}" for e in c.get("errors", [])]
    lines.append("## 検査の失敗（この範囲の Issue は閉じない）")
    lines += [f"- {_md(e)}" for e in errs[:40]] or ["- なし"]
    lines.append("")

    info = []
    for r in rep["repos"]:
        for c in r.get("checks", {}).values():
            info += [f"- {r['name']} / {c['check']}: {_md(n)}" for n in c.get("notes", [])]
    info += [f"- {f['repo'] or '中央'}: {_md(f['title'])}（{SEVERITY_JA[f['severity']]}・Issue 化しない）" for f in rep["findings"] if not f["issue"]]
    for e in disc.get("new", []):
        info.append(f"- 新規発見: {e['name']}（ID {e['id']}）— 初回棚卸しを実施")
    for e in disc.get("renamed", []):
        info.append(f"- 名前変更: {e['old']} → {e['name']}（ID {e['id']} で履歴を引き継ぎ）")
    for e in disc.get("excluded", []):
        info.append(f"- 除外: {e['name']}（{e['reason']}）")
    lines.append("## 情報（Issue にしない事項）")
    lines += info[:80] or ["- なし"]
    lines.append("")

    iss = rep.get("issues", {})
    lines.append("## Issue 操作")
    if iss.get("skipped"):
        lines.append(f"- 実施せず: {iss['skipped']}")
    else:
        counts: dict[str, int] = {}
        for a in iss.get("actions", []):
            counts[a["op"]] = counts.get(a["op"], 0) + 1
        lines.append("- " + ("、".join(f"{k} {v}" for k, v in sorted(counts.items())) or "変更なし"))
        for o in iss.get("observations", [])[:20]:
            lines.append(f"- {o['what']}: {o.get('key', '')} {('#' + str(o['number'])) if o.get('number') else ''} {_md(o.get('note', ''))}".rstrip())
        for e in iss.get("errors", []):
            lines.append(f"- **失敗**: {_md(e)}")
    lines.append("")
    lines.append("## 自動化の限界（毎回表示）")
    lines += [
        "- GitHub に push 済みの内容だけが対象。未 push の変更・手元のビルド環境は監視していない",
        "- 配布バイナリがどのソースから作られたかは検証していない（タグ時点のソースで推定）",
        "- 到達可能性（脆弱なコードが実際に使われるか）は判定していない",
        "- 中央ワークフロー自体が止まると、このレポートも更新されない。最終実行日時と月次点検 Issue の到着で稼働を確認する",
    ]
    return "\n".join(lines)


def _md(s) -> str:
    from .issues import neutralize

    return neutralize(str(s)).replace("|", "\\|").replace("\n", " ")


def worst_status(statuses: list[str]) -> str:
    order = {SKIPPED: 0, SUCCESS: 1, PARTIAL: 2, ERROR: 3}
    real = [s for s in statuses if s != SKIPPED]
    if not real:
        return SKIPPED
    return max(real, key=lambda s: order[s])
