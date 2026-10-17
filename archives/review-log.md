# review-log

| 日付 | 型 | ファイル | 内容 |
|---|---|---|---|
| 2026-10-17 | 同一キーの重複作成 | maint/issues.py, maint/checks/eol.py, maint/checks/deps.py | 修正・再発防止テスト（tests/test_regressions.py） |
| 2026-10-17 | 取得失敗でも解消トークンを出す | maint/checks/vuln.py, maint/checks/ci.py, maint/checks/deps.py, maint/checks/eol.py | 修正・再発防止テスト（tests/test_regressions.py） |
| 2026-10-17 | 同期失敗でも月次を完了扱い | maint/runner.py | 修正・再発防止テスト（tests/test_regressions.py） |
| 2026-10-17 | 人が閉じた束への新規勧告を黙殺 | maint/issues.py | 修正・再発防止テスト（tests/test_regressions.py） |
| 2026-10-17 | タグにだけ残る dev 依存を prod 扱い | maint/checks/vuln.py | 修正・再発防止テスト（tests/test_regressions.py） |
| 2026-10-17 | 抑制で空の束を解消扱い | maint/checks/vuln.py, maint/issues.py | 修正・再発防止テスト（tests/test_regressions.py） |
| 2026-10-17 | 無害化の漏れ（owner/repo#n・GH-n・www/http） | maint/issues.py | 修正・再発防止テスト（tests/test_regressions.py） |
| 2026-10-17 | 依存定義なしを成功表示 | maint/checks/vuln.py, maint/report.py | 修正・再発防止テスト（tests/test_regressions.py） |
| 2026-10-17 | タグの未ロック定義で全エコシステムが閉じない | maint/checks/vuln.py | 修正・再発防止テスト（tests/test_regressions.py） |
| 2026-10-17 | 一時失敗で変化コメントが往復 | maint/issues.py | 修正・再発防止テスト（tests/test_regressions.py） |
| 2026-10-17 | POST の再送で重複 | maint/http.py | 修正・再発防止テスト（tests/test_regressions.py） |
| 2026-10-17 | 状態破損を黙って初期化 | maint/runner.py | 修正・再発防止テスト（tests/test_regressions.py） |
| 2026-10-17 | 月次点検の番号がレポートに出ない | maint/issues.py | 修正・再発防止テスト（tests/test_regressions.py） |
| 2026-10-17 | SBOM なしでも配布版を PARTIAL | maint/checks/release.py | 修正・再発防止テスト（tests/test_regressions.py） |
| 2026-10-17 | 巨大ツリーでもトークンを出す | maint/checks/vuln.py, maint/checks/deps.py | 修正・再発防止テスト（tests/test_regressions.py） |
| 2026-10-17 | 本文取得失敗を『手動トリガーのみ』と表示 | maint/checks/ci.py | 修正・再発防止テスト（tests/test_regressions.py） |
| 2026-10-17 | 毎回 PARTIAL を連続失敗に数えない | maint/runner.py | 低・ISSUES.md IMP-1 に起票 |
