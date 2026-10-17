# AGENTS.md — okakanatto-maintenance の運用ルール（Claude Code・Codex 共通の正本）

このファイルが AI 向けルールの唯一の正本。`CLAUDE.md` はこのファイルを読み込むだけの入口で、ここと矛盾するルールを書かない。

## 1. このリポジトリは何か

`okakanatto` が公開している全リポジトリを、GitHub Actions から横断監視する中央保守リポジトリ。
- 監視の正本は **GitHub に push 済みの内容**。未 push の変更・各開発 PC の状態は対象外
- 監視対象は毎回 API で自動発見する（所有・公開・非 fork・非 archive。設定で除外可）。登録作業は不要
- 監視対象のリポジトリには**書き込まない**。書き込むのはこのリポジトリの Issue だけ
- アプリの技術的事実（言語・依存・CI）は、このファイルではなく GitHub 上の最新状態とレポートから取る

## 2. 情報源（全体を知るにはこの順に見る）

| 情報源 | 中身 | 取り方 |
|---|---|---|
| ダッシュボード Issue（ラベル `maint:dashboard`） | 最終実行日時・監視範囲表・要対応・失敗・未監視 | `gh issue list -R okakanatto/okakanatto-maintenance -l maint:dashboard` → `gh issue view <番号>` |
| 保守 Issue（ラベル `maint:auto`、open） | 1 件 = 1 つの対応単位。根拠・推奨対応・未検証事項・検査範囲 | `gh issue list -R okakanatto/okakanatto-maintenance -l maint:auto -s open --limit 100` |
| 実行レポート（Actions の成果物 `maintenance-report`） | `report.json`（機械可読の全結果）・`report.md` | `gh run list -R okakanatto/okakanatto-maintenance -w maintenance -L 5` → `gh run download <run-id> -n maintenance-report` |
| `config/maintenance.json` | 判定基準・除外・定期点検項目 | ファイルを読む |
| `config/suppressions.json` | 誤検知・保留・リスク受容（期限付き） | ファイルを読む |

ラベル: `kind:vuln|deps|ci|eol|health|lifecycle|manual`、`sev:critical|high|medium|low|info`、
`maint:resolved`（ツールが検証して閉じた）、`maint:suppressed`（抑制中）、`maint:manual-check`（人が確認する定期点検）。

## 3. 「全アプリの保守状況を確認して」と言われたとき

1. ダッシュボード Issue を読む。**最終実行日時が 2 日より古ければ、まず「監視が止まっている可能性」を報告**する（README「監視停止」）
2. open の保守 Issue を一覧し、5 章の順に並べる
3. 必要なら最新の `report.json` を取り、Issue に無い情報（`info`・未監視範囲・失敗）を補う
4. 次の様式で報告する（「検出なし」と「検査できていない」を必ず分ける）

```
## 保守状況（最終実行: YYYY-MM-DD HH:MM JST、実行状態: SUCCESS/PARTIAL/ERROR）
### 要対応（優先順）
1. [Critical] Yarukoto: npm 依存に既知脆弱性 N 件 — #12（配布中 vX に含まれる可能性 / 対応目安 3 日）
### 監視できていない範囲
- MINTIA: ソース非公開のため配布物の中身は未検査（定期点検で人が確認）
### 検査の失敗・未実施
- （なければ「なし」）
### 情報（対応不要）
```

## 4. 根拠付きで報告する規則

- 主張には必ず根拠を付ける: Issue 番号、勧告 ID（GHSA/CVE/RUSTSEC）、ファイルパス、版、一次情報 URL
- Issue の「未検証事項」をそのまま併記する。**到達可能性（実際に使われているか）・配布バイナリとソースの一致は、根拠なしに断定しない**
- カバレッジが `UNSUPPORTED` / `UNKNOWN` / 検査 `ERROR` / `SKIPPED` の範囲を「問題なし」と言わない
- 実行状態が PARTIAL のときは、どの範囲が欠けたかを書く

## 5. 優先付けの規則

上から順に比較する。
1. 重要度（Critical > High > Medium > Low > Info）。対応目安は Critical 3 日・High 14 日・Medium 30 日・Low 90 日（初回検出から）
2. 配布中のリリースに含まれる（本文の「範囲」にタグが入っている）ものを先に
3. 本番依存 > 開発用依存（開発用は自動で 1 段階下げてある）
4. 修正版がある（すぐ直せる）もの
5. `kind:health`（監視不能が続いている）は重要度に関わらず早めに直す。見えていない範囲が増えるため

## 6. 個別の修正依頼を切り出すとき（各アプリのリポジトリで作業する AI 向け）

保守 Issue 1 件を、対象アプリのリポジトリでの作業指示に変換する。中央からアプリを直接変更しない。

```
対象: okakanatto/<アプリ>（既定ブランチ <branch>）
目的: 保守 Issue okakanatto/okakanatto-maintenance#<番号> の解消
内容: <推奨対応をそのまま>（例: next 16.1.6 → 16.1.7 以上、ロックファイル再生成）
確認: テスト・ビルドが通ること。配布中の版に含まれる場合は新しいリリースの要否をユーザーに確認
完了条件: 中央の次回監視で該当 Issue が「検証済みで解消」（maint:resolved）になる
```

## 7. してはいけないこと

- ユーザーの明示指示なしに、監視対象アプリのリポジトリへ書き込む（コード・設定・Issue・PR・Dependabot 設定）
- 保守 Issue を、検証なしに閉じる。閉じるのはツールの役目（検査成功＋検出なしのときだけ自動で閉じる）
- 人が閉じた Issue を開け直す
- `suppressions.json` に理由・期限（`snoozed`/`risk_accepted` は `until` 必須）なしで追加する
- トークン・Secrets の値を表示・記録する
- 監視停止を「空コミットを繰り返す」ことで回避する

## 8. 誤検知・保留・リスク受容

`config/suppressions.json` に追記してコミットする。キーは Issue 本文末尾の `maint-key`。
脆弱性は束ねた Issue 全体（`vuln:<ID>:<エコシステム>:<prod|dev>`）でも、勧告 1 件（`vuln:<リポジトリID>:<GHSA/CVE/RUSTSEC>`）でも抑制できる。

```json
{"key": "vuln:1164599744:GHSA-xxxx-xxxx-xxxx", "status": "risk_accepted", "reason": "該当 API を使っていない（src/x.js を確認）", "until": "2027-01-31", "by": "okakanatto"}
```
期限を過ぎると、ツールが Issue のラベル `maint:suppressed` を外して 1 回だけ知らせる。

## 9. このツール自体を変更するとき

- Python 3.11 以上、**標準ライブラリのみ**。外部パッケージを足さない。監視対象のコードを実行しない（API でデータとして読むだけ）
- テスト: `python -m unittest discover -s tests -t .`（偽 GitHub による統合テストを含む）。設定検証: `python -m maint validate`
- 新しい検査や規則を足したら、その規則をわざと壊してテストが落ちることを 1 回確かめる
- 実データの段の発火ファイル: `maint/issues.py` `maint/runner.py` `maint/report.py` `maint/state.py` `maint/checks/*.py` `config/*.json`
  （Issue への外部出力と判定に関わる）。変更**前**に実 GitHub の dry-run で「予定の Issue 操作」を保存し、変更後と突き合わせて差分を説明する:
  `GITHUB_TOKEN=$(gh auth token) python -m maint run --dry-run --checks all --report-dir out/before`
- 拡張点: 解析器は `maint/lockfiles.py` の `PARSERS`、検査は `maint/checks/` と `maint/checks/__init__.py` の `PERIOD_CHECKS`、
  定期点検は `config/maintenance.json` の `manual_checks`
- 開発管理ファイル: `STATUS.md`（現在の版と単位）・`ISSUES.md`（このツール自身の課題）。各アプリの保守案件は GitHub Issues で管理し、ここには書かない
