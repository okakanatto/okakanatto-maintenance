# 設計判断の記録（v0.1.0、2026-10-17）

| 論点 | 決めたこと | 理由 |
|---|---|---|
| 実装言語 | Python 3.11+ 標準ライブラリのみ | ubuntu ランナーに python3 が入っており依存のインストールが要らない。`tomllib` で Cargo.lock を読める |
| 脆弱性データ | OSV.dev API（querybatch → vulns/{id}）を直接呼ぶ | 無料・認証不要・npm/crates.io/PyPI/Go 等を横断。OSV-Scanner バイナリは不要（ロックファイル解析を自前で持ち、取得物を実行しない） |
| Dependabot alerts | 任意の追加情報源 | 中央の `GITHUB_TOKEN` では他リポジトリの alerts を読めない。全リポジトリで無効（2026-10-17 実測 403）でもあり、必須にしない |
| 外部コードの扱い | ファイルは API の blob としてデータで読むだけ | 中央のトークンを持つ環境で他人のビルドスクリプトを実行しない |
| 永続状態 | ダッシュボード Issue 本文末尾の隠し JSON（台帳・周期の完了日時・連続失敗回数・点検完了日） | DB・コミットを増やさない。本文の編集は通知を出さない。壊れても「全部新規」として安全側に戻る |
| 保守案件 | GitHub Issue 1 件 = 1 対応単位。一意キーは本文の `maint-key` | 検索 API は反映が遅く重複の原因になるため、ラベル `maint:auto` の全件を一覧して照合する |
| 脆弱性の束ね方 | リポジトリ × エコシステム × 本番/開発用 | 勧告単位だと初回に Yarukoto だけで 137 件になり（実測）、通知過多で埋もれる。依存更新 1 回で片付く単位に合わせた。勧告 ID は本文と material に残し、増減は 1 コメント |
| 解消の判定 | Finding ごとに verify トークン（例 `vuln:<ID>:npm`、`vuln-release:<ID>`）を持ち、今回の検査がそれを全部「成功」と確認したときだけ閉じる | 取得失敗・未対応・周期外・消失を「問題なし」と取り違えない |
| 人の判断の尊重 | 人が閉じた Issue は再オープンしない。期限付きの判断は suppressions.json | ツールが人の判断を上書きして荒らさない。期限で再評価を強制できる |
| 配布版 | 最新リリースのタグ時点のソースも同じく照合し、Issue の「範囲」に main／タグを分けて書く | main で直っても配布物に残る状態を見えるようにする。バイナリとの一致は検証できないので「推定」と明記 |
| 周期 | cron は毎日 1 本。週次・月次は前回完了からの期日で判定 | 失敗した日の分が翌日に回る。workflow を 3 本に分けるより停止箇所が少ない |
| 監視停止 | 月次点検 Issue の到着・ダッシュボードの最終実行日時・任意の外部 ping | 同じワークフローだけでは自分の停止を通知できないため、人の目と外部サービスに頼る |
| 中央リポジトリの公開範囲 | 非公開を推奨（判断はユーザー） | 公開リポジトリの定期実行だけが 60 日無活動で止まる。使用量は無料枠に十分収まる |

## 検証済みの前提（2026-10-17 時点の一次情報）

- 公開リポジトリの scheduled workflow は 60 日無活動で自動停止（docs.github.com「Disabling and enabling a workflow」）。非公開は対象外
- Actions の Node 20 は 2026-09-23 に runner から削除予定と告知、Node 16 は 2024-11-12 に削除（github.blog changelog）
- endoflife.date API v1（`/api/v1/products/{product}`）。Tauri・WebView2・MSVC・CMake は製品が無い → 定期点検で扱う
- OSV querybatch は 1 回 1,000 件まで。結果は ID のみ

## 拡張点（フェーズ 3 に向けて）

- 新しいロックファイル形式: `maint/lockfiles.py` の `PARSERS` と `maint/inventory.py` の `MANIFEST_PATTERNS`
- 新しい検査: `maint/checks/<名前>.py` を作り、`maint/checks/__init__.py` の `PERIOD_CHECKS` と `maint/runner.py` に登録
- 自動修正の入口: 保守 Issue の `maint-meta`（material に対象パッケージ・版・範囲）と `AGENTS.md` 6 章の依頼テンプレート
