"""CI（GitHub Actions）の状態と陳腐化（毎日）。

- 既存ワークフローの状態（有効・無効化）と、既定ブランチの最新実行の結論
- 定義されているのに一度も実行されていない（Actions 自体が無効の可能性）
- 使用アクションの実行環境（action.yml の runs.using）が削除済み・非推奨の Node か
- runs-on のランナーイメージが提供終了か（endoflife.date の github-actions-runner-images）
CI が無いことは障害ではなく、カバレッジ情報として扱う。
"""

from __future__ import annotations

import datetime as dt
import re

from ..context import Context
from ..eoldata import product_releases
from ..http import HttpError
from ..inventory import Inventory, read_blob
from ..model import (
    COV_PARTIAL,
    HIGH,
    LOW,
    MEDIUM,
    NOT_APPLICABLE,
    SUPPORTED,
    UNKNOWN,
    CheckResult,
    Finding,
    Repo,
)

USES = re.compile(r"^\s*-?\s*uses:\s*['\"]?([^'\"\s#]+)['\"]?\s*(?:#\s*(\S+))?", re.M)
RUNS_ON = re.compile(r"^\s*runs-on:\s*(.+?)\s*$", re.M)
TRIGGER_KEYS = ("push", "pull_request", "schedule", "workflow_dispatch", "release", "workflow_run", "pull_request_target")
FAIL_CONCLUSIONS = ("failure", "timed_out", "startup_failure")


def parse_workflow(text: str) -> dict:
    """YAML を完全には解釈しない。uses・runs-on・トリガーの抽出に必要な範囲だけ。"""
    uses = [(m.group(1), m.group(2)) for m in USES.finditer(text)]
    runners: list[str] = []
    dynamic = False
    for m in RUNS_ON.finditer(text):
        v = m.group(1).split(" #", 1)[0].strip().strip("'\"")
        if "${{" in v:
            dynamic = True
            continue
        if v.startswith("["):
            runners += [x.strip().strip("'\"") for x in v.strip("[]").split(",") if x.strip()]
        elif v:
            runners.append(v)
    triggers = set()
    m = re.search(r"^(?:on|\"on\"|'on'|true):[ \t]*(.*)$", text, re.M)
    if m:
        inline = m.group(1).strip()
        if inline:
            triggers |= {t.strip() for t in inline.strip("[]").split(",") if t.strip()}
        else:
            block = text[m.end() :]
            for line in block.splitlines():
                if line and not line.startswith((" ", "\t", "#")):
                    break
                mm = re.match(r"^\s{1,4}([a-z_]+):", line)
                if mm and mm.group(1) in TRIGGER_KEYS:
                    triggers.add(mm.group(1))
    return {"uses": uses, "runners": sorted(set(runners)), "dynamic_runner": dynamic, "triggers": sorted(triggers),
            "push_tags_only": _push_tags_only(text)}


def _push_tags_only(text: str) -> bool:
    """push トリガーがタグだけに絞られているか（例: push: tags: ["v*"]）。タグを付けるまでは実行 0 件が正常。"""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        m = re.match(r"^([ \t]+)push:[ \t]*(#.*)?$", line)
        if not m:
            continue
        indent = len(m.group(1))
        keys = set()
        for nxt in lines[i + 1 :]:
            if not nxt.strip() or nxt.lstrip().startswith("#"):
                continue
            if len(nxt) - len(nxt.lstrip()) <= indent:
                break
            km = re.match(r"^\s+([a-z-]+):", nxt)
            if km:
                keys.add(km.group(1))
        return bool(keys & {"tags", "tags-ignore"}) and not (keys & {"branches", "branches-ignore"})
    return False


def _action_runtime(ctx: Context, ref: str) -> str | None:
    """owner/repo[/path]@ref → runs.using（node20 等）。action.yml が無ければ None、取得失敗なら "ERROR"。"""
    cache = ctx.cache.setdefault("action_runtime", {})
    if ref in cache:
        return cache[ref]
    name, _, version = ref.partition("@")
    parts = name.split("/")
    runtime = None
    if len(parts) >= 2 and version:
        repo, sub = "/".join(parts[:2]), "/".join(parts[2:])
        for fn in ("action.yml", "action.yaml"):
            path = f"{sub}/{fn}" if sub else fn
            try:
                raw = ctx.reader.file(repo, path, version)
            except HttpError:
                runtime = "ERROR"  # 一時的な失敗。この回は陳腐化を判定できない
                break
            if raw:
                m = re.search(r"^\s*using:\s*['\"]?([\w.-]+)", raw.decode("utf-8", "replace"), re.M)
                runtime = m.group(1).lower() if m else "unknown"
                break
    cache[ref] = runtime
    return runtime


def check_ci(ctx: Context, repo: Repo, inv: Inventory) -> CheckResult:
    r = CheckResult("ci")
    if inv.empty:
        r.cover("ci", NOT_APPLICABLE, "コード未登録")
        return r
    try:
        workflows = ctx.reader.workflows(repo.full_name)
    except HttpError as e:
        r.fail(f"ワークフロー一覧を取得できません: {e.kind} ({e.status})", fatal=True)
        r.cover("ci", UNKNOWN, "取得失敗")
        return r
    workflows = [w for w in workflows if str(w.get("path", "")).startswith(".github/workflows/")]
    if not workflows and not inv.workflows:
        r.cover("ci", NOT_APPLICABLE, "CI 未整備（障害ではない。CI があっても Windows 実機での動作保証にはならない）")
        r.verified_scopes.append(f"ci-static:{repo.id}")
        return r
    rows = []
    run_ok = True
    repo_total: int | None = None  # リポジトリ全体の実行回数（必要になったときだけ取る）
    for w in workflows:
        wid, path, state = w.get("id"), w.get("path"), w.get("state")
        row = {"id": wid, "name": w.get("name"), "path": path, "state": state}
        rows.append(row)
        if state == "disabled_inactivity":
            r.findings.append(_f(repo, f"ci-disabled:{repo.id}:{wid}", LOW, f"[CI] {repo.name}: {w.get('name')} が無活動で自動停止",
                                 "60 日無活動で GitHub が定期実行を停止した", [w.get("html_url", "")],
                                 "必要なら Actions 画面から再有効化する（不要ならワークフローの削除を検討）", {"path": path, "state": state},
                                 [f"ci:{repo.id}:{wid}"]))
            r.verified_scopes.append(f"ci:{repo.id}:{wid}")
            continue
        if state != "active":
            r.notes.append(f"{path}: 状態 {state}（手動で無効化）")
            r.verified_scopes.append(f"ci:{repo.id}:{wid}")
            continue
        try:
            latest_default = ctx.reader.workflow_runs(repo.full_name, wid, branch=repo.default_branch, per_page=5)
            any_branch = ctx.reader.workflow_runs(repo.full_name, wid, per_page=1)
        except HttpError as e:
            run_ok = False
            r.fail(f"{path} の実行履歴を取得できません: {e.kind}")
            continue
        r.verified_scopes.append(f"ci:{repo.id}:{wid}")
        total = int(any_branch.get("total_count") or 0)
        row["total_runs"] = total
        completed = [x for x in latest_default.get("workflow_runs", []) if x.get("status") == "completed"]
        if completed:
            last = completed[0]
            row.update({"last_conclusion": last.get("conclusion"), "last_run": last.get("created_at"), "last_url": last.get("html_url"), "event": last.get("event")})
            if last.get("conclusion") in FAIL_CONCLUSIONS:
                r.findings.append(_f(repo, f"ci-failure:{repo.id}:{wid}", MEDIUM, f"[CI] {repo.name}: {w.get('name')} が {repo.default_branch} で失敗",
                                     f"既定ブランチの最新の完了実行が {last.get('conclusion')}", [last.get("html_url", "")],
                                     "失敗ログを確認し、修正するかワークフローを見直す", {"path": path, "conclusion": last.get("conclusion")},
                                     [f"ci:{repo.id}:{wid}"]))
            elif last.get("conclusion") == "cancelled":
                r.notes.append(f"{path}: 最新実行がキャンセル")
            stale_days = int(ctx.policy("ci_policy", "stale_days", 90, repo.id, repo.name))
            when = _parse_time(last.get("created_at"))
            if when and (ctx.now - when).days > stale_days:
                r.notes.append(f"{path}: 既定ブランチで {(ctx.now - when).days} 日実行なし")
        elif total == 0:
            text = _text(ctx, inv, path)
            if text is None:
                run_ok = False
                r.fail(f"{path} の本文を取得できない（トリガーを判定できない）")
                r.verified_scopes.remove(f"ci:{repo.id}:{wid}")
                continue
            wf = parse_workflow(text)
            expected = "schedule" in wf["triggers"] or ("push" in wf["triggers"] and not wf["push_tags_only"])
            if not expected:
                r.notes.append(f"{path}: 実行履歴なし（タグ・手動・PR トリガーのみ。条件が成立するまでは正常）")
                continue
            if repo_total is None:
                try:
                    repo_total = ctx.reader.repo_runs_total(repo.full_name)
                except HttpError as e:
                    run_ok = False
                    r.fail(f"リポジトリ全体の実行履歴を取得できない: {e.kind}")
                    r.verified_scopes.remove(f"ci:{repo.id}:{wid}")
                    continue
            if repo_total > 0:
                # 他のワークフローは動いている＝Actions は有効。トリガー条件（paths・branches 等）が未成立なだけ
                r.notes.append(f"{path}: 実行履歴なし（リポジトリでは {repo_total} 回実行あり。トリガー条件が未成立の可能性）")
                continue
            r.findings.append(_f(repo, f"ci-never-run:{repo.id}:{wid}", LOW, f"[CI] {repo.name}: {w.get('name')} が一度も実行されていない",
                                 "push/schedule トリガーがあるのに、このリポジトリでは Actions の実行が 1 回も無い。Actions が無効になっている可能性がある",
                                 [f"{repo.html_url}/actions"], "Settings → Actions で有効か確認し、意図どおりなら手動実行で動作を確かめる",
                                 {"path": path}, [f"ci:{repo.id}:{wid}"],
                                 unverified=["Actions の有効設定はリポジトリ管理者しか API で読めないため、無効かどうかは推定"]))
    r.data["workflows"] = rows
    static_ok = _static(ctx, repo, inv, r)
    if run_ok and static_ok:
        r.cover("ci", SUPPORTED, f"ワークフロー {len(workflows)} 件の状態・最新実行・使用アクション・ランナーを確認")
    else:
        r.cover("ci", COV_PARTIAL, "一部のワークフロー情報を取得できない")
    return r


def _text(ctx: Context, inv: Inventory, path: str) -> str | None:
    if path not in inv.files:
        return None
    try:
        return read_blob(ctx.reader, inv, path).decode("utf-8", "replace")
    except HttpError:
        return None


def _static(ctx: Context, repo: Repo, inv: Inventory, r: CheckResult) -> bool:
    ok = True
    deprecated = ctx.cfg.section("ci_policy").get("deprecated_runtimes", {})
    retired_cfg = ctx.cfg.section("ci_policy").get("retired_runners", {})
    by_action: dict[str, dict] = {}
    by_runner: dict[str, list[str]] = {}
    uses_all = []
    unknown_runtime = []
    for path in inv.workflows:
        text = _text(ctx, inv, path)
        if text is None:
            ok = False
            r.fail(f"{path} を取得できません")
            continue
        wf = parse_workflow(text)
        if wf["dynamic_runner"]:
            r.notes.append(f"{path}: runs-on が式（matrix 等）のためランナーの陳腐化は未判定")
        for label in wf["runners"]:
            by_runner.setdefault(label, []).append(path)
        for ref, comment in wf["uses"]:
            if ref.startswith(("./", "docker://")):
                continue
            uses_all.append({"uses": ref, "comment": comment, "file": path})
            rt = _action_runtime(ctx, ref)
            if rt == "ERROR":
                ok = False
                r.fail(f"{ref} の action.yml を取得できない（実行環境を判定できない）")
                continue
            if rt is None:
                unknown_runtime.append(ref)
                continue
            if rt in deprecated:
                name = ref.split("@")[0]
                e = by_action.setdefault(name, {"refs": set(), "files": set(), "runtime": rt})
                e["refs"].add(ref.split("@")[1][:12] + (f" ({comment})" if comment else ""))
                e["files"].add(path)
    r.data["uses"] = uses_all
    r.data["runners"] = sorted(by_runner)
    if unknown_runtime:
        r.notes.append("実行環境を確認できないアクション: " + ", ".join(sorted(set(unknown_runtime))[:5]))
    if by_action:
        # 1 リポジトリ 1 件に束ねる（同じ作業＝ワークフローのアクション更新で片付くため）
        lines = [f"`{name}`（{', '.join(sorted(e['refs']))}）: {e['runtime']} — {deprecated[e['runtime']]}" for name, e in sorted(by_action.items())]
        runtimes = sorted({e["runtime"] for e in by_action.values()})
        r.findings.append(_f(repo, f"ci-action:{repo.id}", MEDIUM, f"[CI] {repo.name}: 削除・非推奨の実行環境（{', '.join(runtimes)}）のアクション {len(by_action)} 件",
                             "使用アクションの action.yml（runs.using）が、GitHub のランナーで削除済み・削除予定の Node を指定している:\n" + "\n".join(f"- {x}" for x in lines),
                             [f"https://github.com/{'/'.join(n.split('/')[:2])}/releases" for n in sorted(by_action)][:5],
                             "node24 対応の最新メジャー版へ更新する（SHA 固定なら新しいタグの SHA に差し替える）",
                             {"actions": {n: {"runtime": e["runtime"], "refs": sorted(e["refs"])} for n, e in sorted(by_action.items())}},
                             [f"ci-static:{repo.id}"]))
    images, images_ok = _runner_images(ctx, r)
    if not images_ok:
        ok = False
    for label, files in sorted(by_runner.items()):
        eol = None
        if images is not None and label in images:
            rel = images[label]
            if rel.get("isEol"):
                eol = rel.get("eolFrom") or "提供終了"
        elif label in retired_cfg:
            eol = retired_cfg[label]
        if eol:
            past = _is_past(eol, ctx.today)
            r.findings.append(_f(repo, f"ci-runner:{repo.id}:{label}", HIGH if past else MEDIUM,
                                 f"[CI] {repo.name}: ランナー {label} が{'提供終了' if past else '提供終了予定'}（{eol}）",
                                 "提供終了したランナーイメージを指定したジョブは開始できない", ["https://endoflife.date/github-actions-runner-images"],
                                 "後継のイメージ（例: windows-2025 / ubuntu-24.04）へ変更する", {"label": label, "files": sorted(set(files))},
                                 [f"ci-static:{repo.id}"]))
    if ok:
        r.verified_scopes.append(f"ci-static:{repo.id}")
    return ok


def _runner_images(ctx: Context, r: CheckResult) -> tuple[dict | None, bool]:
    """(ランナー名 → サイクル, 取得できたか)。製品が無い（404）ときは設定の retired_runners だけで判定してよい。"""
    try:
        rels = product_releases(ctx, "github-actions-runner-images")
    except HttpError as e:
        r.fail(f"ランナーイメージの提供期限を取得できない（{e.kind}）。設定の retired_runners のみで判定")
        return None, False
    if rels is None:
        return None, True
    return {x["name"]: x for x in rels if isinstance(x, dict) and x.get("name")}, True


def _f(repo, key, sev, title, summary, evidence, rec, material, verify, unverified=None) -> Finding:
    return Finding(key=key, kind="ci", repo_id=repo.id, repo_name=repo.name, title=title, severity=sev, summary=summary,
                   evidence=[e for e in evidence if e], recommendation=rec, material=material, verify=verify,
                   unverified=unverified or [], scope=["GitHub Actions のワークフロー定義と実行履歴（既定ブランチ）"])


def _parse_time(s: str | None) -> dt.datetime | None:
    if not s:
        return None
    try:
        return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def _is_past(date_or_text: str, today: dt.date) -> bool:
    try:
        return dt.date.fromisoformat(str(date_or_text)[:10]) <= today
    except ValueError:
        return True
