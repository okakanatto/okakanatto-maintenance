@AGENTS.md

## Claude Code 向けの補足（AGENTS.md の内容を繰り返さない・矛盾させない）

- 標準開発フロー: 依頼ごとに宣言する
- 実データの段の発火ファイルと手順・テストコマンド・拡張点: AGENTS.md 9 章
- UI 実測の手順: なし（画面を持たない。Markdown レポートは report.md を目視）
- 見せる地点: 実 GitHub の dry-run レポート（`out/report.md`）と、workflow_dispatch 実行後のダッシュボード Issue
- バージョン管理対象ファイル: `maint/__init__.py` の `__version__`
