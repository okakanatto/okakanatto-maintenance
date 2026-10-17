"""コマンドライン。

  python -m maint run [--checks auto|daily|weekly|monthly|all] [--dry-run] [--repo NAME ...] [--report-dir DIR]
  python -m maint validate

トークンは環境変数から読む（ログに出さない）:
  GITHUB_TOKEN             中央リポジトリの Issue 読み書き（Actions では github.token）。監視対象の読み取りにも使う
  MAINT_READ_TOKEN         任意。監視対象の読み取りを別トークンにする（レート制限の分離）
  DEPENDABOT_ALERTS_TOKEN  任意。Dependabot alerts の読み取り専用トークン（README「Dependabot alerts」）
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
from pathlib import Path

from . import config as config_mod
from .context import Context
from .github import GitHubReader, IssueWriter
from .http import HttpClient
from .osv import OSVClient
from .runner import RunOptions, run


def _run_url() -> str | None:
    server, repo, rid = os.environ.get("GITHUB_SERVER_URL"), os.environ.get("GITHUB_REPOSITORY"), os.environ.get("GITHUB_RUN_ID")
    if server and repo and rid:
        return f"{server}/{repo}/actions/runs/{rid}"
    return None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="maint")
    sub = ap.add_subparsers(dest="cmd", required=True)
    pr = sub.add_parser("run", help="監視を 1 回実行する")
    pr.add_argument("--checks", default="auto", choices=["auto", "daily", "weekly", "monthly", "all"])
    pr.add_argument("--dry-run", action="store_true", help="Issue に書き込まない（読み取りと予定の表示だけ）")
    pr.add_argument("--repo", action="append", help="このリポジトリだけ検査（複数可。消失判定と自動クローズはしない）")
    pr.add_argument("--report-dir", default="out", help="report.json と report.md の出力先")
    sub.add_parser("validate", help="設定ファイルを検証する")
    args = ap.parse_args(argv)

    try:
        cfg = config_mod.load()
    except config_mod.ConfigError as e:
        print(f"設定エラー: {e}", file=sys.stderr)
        return 2
    if args.cmd == "validate":
        print(f"OK: owner={cfg.owner} central={cfg.central_full_name} suppressions={len(cfg.suppressions)} manual_checks={len(cfg.raw.get('manual_checks', []))}")
        return 0

    token = os.environ.get("GITHUB_TOKEN") or None
    read_token = os.environ.get("MAINT_READ_TOKEN") or token
    dep_token = os.environ.get("DEPENDABOT_ALERTS_TOKEN") or None
    if not token:
        print("注意: GITHUB_TOKEN が無い。未認証（60 回/時）で読み取り、Issue 同期はしない", file=sys.stderr)
    http = HttpClient()
    ctx = Context(
        cfg=cfg,
        reader=GitHubReader(http, read_token),
        http=http,
        osv=OSVClient(http),
        now=dt.datetime.now(dt.timezone.utc).replace(microsecond=0),
        dependabot=GitHubReader(http, dep_token) if dep_token else None,
    )
    writer = IssueWriter(http, token, cfg.central_full_name, dry_run=args.dry_run) if token else None
    report = run(ctx, writer, RunOptions(checks=args.checks, dry_run=args.dry_run, only=args.repo, run_url=_run_url()))

    out = Path(args.report_dir)
    out.mkdir(parents=True, exist_ok=True)
    md = report.pop("markdown")
    (out / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "report.md").write_text(md, encoding="utf-8")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(md + "\n")
    st = report["run"]["status"]
    print(f"status={st} periods={','.join(report['run']['periods'])} repos={len(report['repos'])} "
          f"findings={len(report['findings'])} issue_actions={len(report['issues']['actions'])} requests={report['run']['http_requests']}")
    for r in report["run"]["status_reasons"]:
        print(f"  - {r}")
    # ERROR（一覧取得・Issue 同期・状態保存の失敗）はジョブを失敗させ、GitHub の失敗通知を出す
    return 1 if st == "ERROR" else 0


if __name__ == "__main__":
    sys.exit(main())
