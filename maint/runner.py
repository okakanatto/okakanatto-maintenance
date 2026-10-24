"""1 回の監視実行。発見 → 棚卸し → 検査 → Issue 同期 → ダッシュボード・レポート。"""

from __future__ import annotations

import datetime as dt
import traceback
from dataclasses import dataclass

from . import state as state_mod
from .checks import PERIOD_CHECKS
from .checks.ci import check_ci
from .checks.deps import check_deps
from .checks.eol import check_eol
from .checks.manual import due_items, manual_finding, record_completions
from .checks.release import check_release
from .checks.vuln import check_vuln
from .context import Context
from .discovery import MISSING_LABEL, apply_to_state, discover
from .github import IssueWriter
from .http import HttpError
from .inventory import build_inventory, read_blob
from .issues import AUTO, DASHBOARD, SyncResult, ensure_labels, sync, sync_manual
from .model import ERROR, LOW, MEDIUM, PARTIAL, SKIPPED, SUCCESS, CheckResult, Finding
from .report import render_markdown, worst_status

PERIODS = ("daily", "weekly", "monthly")
# repo_policies.<名前>.distribution_snapshot が true のリポジトリの Issue に出す注意（開発用リポジトリの名前は公開しない）
SNAPSHOT_NOTE = "このリポジトリは配布用のスナップショット（開発用の非公開リポジトリから書き出している）。ここを直接直すと次の書き出しで上書きされるため、修正は開発用リポジトリで行う（AGENTS.md 6 章）"


@dataclass
class RunOptions:
    checks: str = "auto"  # auto / daily / weekly / monthly / all
    dry_run: bool = False
    only: list[str] | None = None  # 一部のリポジトリだけ（消失判定と Issue の解消はしない）
    run_url: str | None = None


def due_periods(mode: str, state: dict, now: dt.datetime) -> list[str]:
    if mode == "all":
        return list(PERIODS)
    if mode in PERIODS:
        return [mode]
    out = ["daily"]
    last = state.get("last_completed", {})
    wk = _parse(last.get("weekly"))
    if wk is None or (now - wk) >= dt.timedelta(days=6, hours=12):
        out.append("weekly")
    mo = _parse(last.get("monthly"))
    if mo is None or (mo.year, mo.month) != (now.year, now.month):
        out.append("monthly")
    return out


def _parse(s):
    if not s:
        return None
    try:
        return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def load_central(writer: IssueWriter | None) -> tuple[list[dict], dict | None, str]:
    """(管理 Issue 一覧, ダッシュボード Issue, 状態 ok/missing/none)。読み取り失敗は HttpError。"""
    if writer is None:
        return [], None, "none"
    try:
        issues = writer.list_issues(AUTO)
    except HttpError as e:
        if e.kind == "not_found":
            return [], None, "missing"
        raise
    dashboards = sorted((i for i in issues if any((lb.get("name") if isinstance(lb, dict) else lb) == DASHBOARD for lb in i.get("labels", []))),
                        key=lambda i: (i.get("state") == "open", i["number"]), reverse=True)
    return issues, (dashboards[0] if dashboards else None), "ok"


def run(ctx: Context, writer: IssueWriter | None, opts: RunOptions) -> dict:
    started = ctx.now
    now_iso = started.strftime("%Y-%m-%dT%H:%M:%SZ")
    errors: list[str] = []
    tracebacks: list[str] = []  # report.json にだけ残す（Markdown・Issue には出さない）
    reasons: list[str] = []
    notes: list[str] = []
    try:
        issues, dashboard, central = load_central(writer)
    except HttpError as e:
        issues, dashboard, central = [], None, "error"
        errors.append(f"中央リポジトリの Issue を読めない: {e.kind} ({e.status})")
    if central == "missing":
        notes.append("中央リポジトリが未作成" + ("（dry-run: 作成後に行う予定の Issue 操作を表示）" if opts.dry_run else ""))
    elif central == "none":
        notes.append("GITHUB_TOKEN が無いため中央リポジトリに接続していない")
    st = state_mod.decode(dashboard.get("body") if dashboard else None)
    if st is None:
        if dashboard is not None:
            notes.append(f"ダッシュボード #{dashboard['number']} の状態ブロックを読めない（壊れている）。台帳を初期化し、全リポジトリを新規として棚卸しする")
            reasons.append("状態ブロックを読めず初期化した")
        st = state_mod.empty()
    if dashboard is not None and dashboard.get("state") != "open":
        notes.append(f"ダッシュボード #{dashboard['number']} が閉じられていたため、状態を引き継いで新しく作る")
        dashboard = None
    if ctx.dependabot is None:
        notes.append("Dependabot alerts: 読み取りトークン未設定のため全リポジトリで未取得（脆弱性は OSV のみで照合）")
    if dashboard is None and central == "ok":
        notes.append("ダッシュボード Issue が無い（初回実行）。全周期を実行し新規作成する")
    periods = due_periods(opts.checks, st, started)
    checks_to_run = [c for p in periods for c in PERIOD_CHECKS[p]]

    disc = discover(ctx.reader, ctx.cfg, st, opts.only)
    if disc.status == ERROR:
        errors += disc.errors
    findings: list[Finding] = []
    verified: set[str] = set()
    repo_reports = []
    repo_infos: dict[str, dict] = {}
    new_ids = {r.id for r in disc.new}
    health_threshold = int(ctx.cfg.section("issue_policy").get("health_failures_for_issue", 3))
    failed_periods: set[str] = set()  # ERROR になった検査を含む周期は「完了」にしない（翌日に再実行）
    for repo in disc.active:
        rep = {"id": repo.id, "name": repo.name, "full_name": repo.full_name, "html_url": repo.html_url, "is_new": repo.id in new_ids, "checks": {}}
        repo_reports.append(rep)
        policy = ctx.cfg.repo_policy(repo.id, repo.name)
        # 新規発見したリポジトリは周期に関係なく全検査（初回棚卸し）
        to_run = [c for p in PERIODS for c in PERIOD_CHECKS[p]] if repo.id in new_ids else checks_to_run
        verified.add(f"lifecycle:{repo.id}")  # 公開一覧に出ている＝消失ではない
        try:
            inv = build_inventory(ctx.reader, repo, repo.default_branch, policy.get("ignore_paths"))
        except Exception as e:  # HttpError も想定外の例外も、他リポジトリは続ける
            if isinstance(e, HttpError):
                rep["error"] = f"ツリーを取得できない: {e.kind} ({e.status})"
            else:
                rep["error"] = f"棚卸しで想定外のエラー: {type(e).__name__}: {e}"
                errors.append(f"{repo.name}/inventory: {type(e).__name__}: {e}")
                tracebacks.append(traceback.format_exc(limit=5))
            n = _count_failure(st, repo.id, "inventory", True)
            if n >= health_threshold:
                findings.append(_health(repo, "inventory", n, opts.run_url))
            failed_periods |= set(periods)
            continue
        _count_failure(st, repo.id, "inventory", False)
        verified.add(f"health:{repo.id}:inventory")
        rep["inventory"] = inv.summary()
        results: dict[str, CheckResult] = {}
        rel_res, rel_inv = None, None
        for name in ("release", "vuln", "ci", "deps", "eol"):
            if name not in to_run:
                results[name] = CheckResult(name, status=SKIPPED)
                continue
            try:
                if name == "release":
                    rel_res, rel_inv = check_release(ctx, repo, inv)
                    results[name] = rel_res
                elif name == "vuln":
                    results[name] = check_vuln(ctx, repo, inv, rel_res, rel_inv)
                elif name == "ci":
                    results[name] = check_ci(ctx, repo, inv)
                elif name == "deps":
                    results[name] = check_deps(ctx, repo, inv)
                elif name == "eol":
                    results[name] = check_eol(ctx, repo, inv)
            except Exception as e:
                cr = CheckResult(name)
                cr.fail(f"想定外のエラー: {type(e).__name__}: {e}", fatal=True)
                errors.append(f"{repo.name}/{name}: {type(e).__name__}: {e}")
                tracebacks.append(traceback.format_exc(limit=5))
                results[name] = cr
        fix_note = SNAPSHOT_NOTE if policy.get("distribution_snapshot") else ""
        for name, cr in results.items():
            for f in cr.findings:
                f.fix_note = fix_note
            findings += cr.findings
            verified |= set(cr.verified_scopes)
            if cr.status != SKIPPED:
                n = _count_failure(st, repo.id, name, cr.status == ERROR)
                if n == 0:
                    verified.add(f"health:{repo.id}:{name}")
                elif n >= health_threshold:
                    findings.append(_health(repo, name, n, opts.run_url))
                if cr.status == ERROR:
                    failed_periods |= {p for p in periods if name in PERIOD_CHECKS[p]}
        rep["checks"] = {k: v.to_dict() for k, v in results.items()}
        rep["status"] = worst_status([v.status for v in results.values()])
        info = {"build_systems": inv.build_systems, "releases": (rel_res.data or {}).get("releases") if rel_res else None,
                "coverage": {a: i.level for v in results.values() for a, i in v.coverage.items()}}
        if "monthly" in periods and "README.md" in inv.files:
            try:
                info["readme"] = read_blob(ctx.reader, inv, "README.md").decode("utf-8", "replace")[:20000]
            except HttpError:
                pass
        repo_infos[repo.name] = info

    # 監視対象から消えたもの
    for m in disc.missing:
        m["label"] = MISSING_LABEL.get(m["state"], m["state"])
        findings.append(Finding(
            key=f"lifecycle:{m['id']}:missing", kind="lifecycle", repo_id=m["id"], repo_name=m["name"].split("/")[-1],
            title=f"[監視] {m['name']} を監視できなくなった", severity=LOW,
            summary=f"公開リポジトリ一覧から消えた。状態: {m['label']}" + (f"（{m['detail']}）" if m.get("detail") else ""),
            evidence=[], recommendation="意図した変更（非公開化・削除・移管）か確認する。関連する保守 Issue は自動では閉じない",
            unverified=["関連 Issue の問題が解消したか（監視できないため不明）"], scope=[f"リポジトリ ID {m['id']}"],
            material={"state": m["state"]}, verify=[f"lifecycle:{m['id']}"]))

    # 月次点検
    manual = None
    if "monthly" in periods and not opts.only:
        recorded = record_completions([i for i in issues if "<!-- maint-key: manual:" in (i.get("body") or "")], st, ctx.today)
        if recorded:
            notes.append("点検完了を記録: " + ", ".join(sorted(set(recorded))))
        manual = manual_finding(ctx, due_items(ctx, st, repo_infos))

    statuses = [r.get("status", ERROR) if not r.get("error") else ERROR for r in repo_reports]
    if disc.status != ERROR and not opts.only:
        apply_to_state(disc, st, now_iso)
        for rr in repo_reports:  # 棚卸し結果（初回分は残し、最新分は毎回更新）
            e = st["repos"].get(str(rr["id"]))
            if e is not None and rr.get("inventory"):
                compact = _compact_inventory(rr["inventory"])
                e.setdefault("initial_inventory", {**compact, "at": now_iso[:10]})
                e["inventory"] = compact

    # Issue 同期
    sync_res = SyncResult()
    skipped = None
    if central == "none":
        skipped = "GITHUB_TOKEN なし"
    elif central == "error":
        skipped = "中央リポジトリの Issue を読めないため"
    elif central == "missing" and not opts.dry_run:
        skipped = "中央リポジトリが未作成のため"
    elif disc.status == ERROR:
        skipped = "リポジトリ一覧の取得に失敗したため（誤った解消を避ける）"
    try:
        if skipped is None:
            if not writer.dry_run:
                ensure_labels(writer, sync_res)
            verified_eff = verified if not opts.only else set()  # 一部実行では解消しない
            r2 = sync(writer, ctx.cfg, issues, findings, verified_eff, ctx.now, opts.run_url,
                      int(ctx.cfg.section("issue_policy").get("refresh_days", 7)))
            sync_res.actions += r2.actions
            sync_res.observations += r2.observations
            sync_res.errors += r2.errors
            sync_res.issue_numbers.update(r2.issue_numbers)
            sync_manual(writer, issues, manual, sync_res, opts.run_url, ctx.now)
    except HttpError as e:
        sync_res.errors.append(f"Issue 同期の途中で失敗: {e.kind} ({e.status})。次回の実行で同じキーから再開する")
    if manual:
        findings.append(manual)

    # 周期の完了記録（発見・Issue 同期に失敗した回、ERROR の検査を含む周期は記録しない＝翌日また実行される）
    if disc.status != ERROR and not opts.only:
        for p in periods:
            if p in failed_periods:
                continue
            if sync_res.errors and p != "daily":
                continue
            st.setdefault("last_completed", {})[p] = now_iso

    if disc.status == ERROR:
        reasons.append("リポジトリ一覧の取得に失敗")
    if sync_res.errors:
        reasons.append("Issue 同期に失敗")
    if errors and disc.status != ERROR:
        reasons.append("想定外のエラーあり")
    failed_checks = sum(1 for r in repo_reports for c in r.get("checks", {}).values() if c["status"] in (ERROR, PARTIAL))
    if failed_checks or any(r.get("error") for r in repo_reports):
        reasons.append(f"失敗・一部失敗の検査 {failed_checks + sum(1 for r in repo_reports if r.get('error'))} 件")
    if skipped and central != "none":
        reasons.append(f"Issue 同期を実施せず（{skipped}）")
    if disc.status == ERROR or sync_res.errors or central == "error" or (central == "missing" and not opts.dry_run):
        status = ERROR
    elif reasons:
        status = PARTIAL
    else:
        status = SUCCESS if statuses or disc.listed_count == 0 else PARTIAL

    finished = dt.datetime.now(dt.timezone.utc) if not ctx.cache.get("_frozen_clock") else ctx.now
    report = {
        "version": 1,
        "run": {
            "started": now_iso,
            "finished": finished.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "periods": periods,
            "skipped_periods": [p for p in PERIODS if p not in periods],
            "requested": opts.checks,
            "dry_run": opts.dry_run,
            "only": opts.only,
            "status": status,
            "status_reasons": reasons,
            "run_url": opts.run_url,
            "notes": notes,
            "http_requests": ctx.http.request_count,
        },
        "discovery": disc.to_dict(),
        "repos": repo_reports,
        "findings": [f.to_dict() for f in findings],
        "verified_scopes": sorted(verified),
        "issues": {"actions": sync_res.actions, "observations": sync_res.observations, "errors": sync_res.errors,
                   "numbers": sync_res.issue_numbers, "skipped": skipped,
                   "planned_writes": writer.planned if writer is not None and writer.dry_run else []},
        "errors": errors,
        "tracebacks": tracebacks,
    }
    report["markdown"] = render_markdown(report)

    # ダッシュボード（状態の永続化を兼ねる）
    if skipped is None and not opts.only and not (central == "missing" and not opts.dry_run):
        state_block = state_mod.encode(st)
        md = render_markdown(report, dashboard=True)
        limit = 64000 - len(state_block)
        if len(md) > limit:
            md = md[: max(0, limit - 200)] + "\n\n…（長すぎるため省略。全文は実行記録の report.md）"
        body = md + "\n\n" + state_block
        try:
            if dashboard:
                writer.update_issue(dashboard["number"], body=body)
                report["issues"]["dashboard"] = dashboard["number"]
            else:
                ensure = writer.create_issue("保守ダッシュボード（自動更新）", body, [AUTO, DASHBOARD])
                report["issues"]["dashboard"] = (ensure or {}).get("number")
        except HttpError as e:
            report["issues"]["errors"].append(f"ダッシュボード更新に失敗: {e.kind}")
            report["run"]["status"] = ERROR
            report["run"]["status_reasons"].append("ダッシュボード更新に失敗（状態が保存されていない）")
            report["markdown"] = render_markdown(report)
    report["state"] = st
    return report


def _compact_inventory(inv: dict) -> dict:
    return {
        "has_source": inv.get("has_source"),
        "empty": inv.get("empty"),
        "build_systems": inv.get("build_systems", []),
        "manifests": sorted({f"{m['kind']}:{m['path']}" for m in inv.get("manifests", [])})[:30],
        "submodules": [s["path"] for s in inv.get("submodules", [])][:10],
        "workflows": len(inv.get("workflows", [])),
        "languages": inv.get("languages", [])[:3],
    }


def _health(repo, check: str, n: int, run_url: str | None) -> Finding:
    # 題名・material に回数を入れない（毎回の更新を避ける）。回数は本文の概要にだけ書く
    return Finding(
        key=f"health:{repo.id}:{check}", kind="health", repo_id=repo.id, repo_name=repo.name,
        title=f"[監視] {repo.name}: {check} の検査が連続で失敗", severity=MEDIUM,
        summary=f"同じ検査が {n} 回以上連続して失敗しており、この範囲は監視できていない", evidence=[run_url or ""],
        recommendation="実行ログのエラーを確認する（レート制限・API 障害・権限不足・形式変更）",
        unverified=["この範囲の問題の有無"], scope=[f"{repo.full_name} の {check} 検査"],
        material={"check": check}, verify=[f"health:{repo.id}:{check}"])


def _count_failure(st: dict, repo_id: int, check: str, failed: bool) -> int:
    k = f"{repo_id}:{check}"
    cf = st.setdefault("check_failures", {})
    if failed:
        cf[k] = int(cf.get(k, 0)) + 1
        return cf[k]
    cf.pop(k, None)
    return 0
