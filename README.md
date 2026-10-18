# okakanatto-maintenance

`okakanatto` が GitHub で公開しているアプリを、**この 1 つのリポジトリから横断して保守監視**する仕組みです。
GitHub Actions が毎日自動で動き、PC の電源や Claude Code の起動状況には依存しません。
普段は何もしなくてよく、対応が要る問題が見つかったときだけ、このリポジトリの Issue に集まります。

> 完全なゼロメンテナンスではありません。機械的に監視できない範囲（C/C++ の同梱ライブラリ、ソース非公開の配布物など）は、
> 毎月の「定期点検」Issue で人が確認します。何が監視できていて何ができていないかは、ダッシュボード Issue に毎回表示されます。

## 仕組み

```
毎日 06:17 JST（GitHub Actions）
  ├─ 1. 発見     okakanatto 所有の公開リポジトリを API で全件取得（数値 ID で台帳と照合）
  ├─ 2. 棚卸し   依存定義・ロックファイル・サブモジュール・CI・Releases を読む（コードは実行しない）
  ├─ 3. 検査     毎日: 脆弱性（OSV）・配布版・CI ／ 週 1: 依存更新 ／ 月 1: サポート終了＋定期点検
  ├─ 4. Issue    問題ごとに一意キーで作成・更新・解消（同じ問題を何度も起票しない）
  └─ 5. 記録     ダッシュボード Issue・Actions のサマリー・report.json（90 日保存）
```

## 最初に一度だけ行う設定

| # | 作業 | 必須か | 方法 |
|---|---|---|---|
| 1 | このリポジトリを GitHub に作成し push する | 必須 | 下の「配備」 |
| 2 | Actions を有効にする | 必須 | 新規リポジトリでは既定で有効。Settings → Actions → General で「Allow all actions」または GitHub 製のみ許可でよい |
| 3 | 手動で 1 回実行し、ダッシュボード Issue ができることを確認 | 必須 | Actions → maintenance → Run workflow |
| 4 | このリポジトリを Watch（All Activity か Issues）にする | 推奨 | 新しい保守 Issue がメールで届く |
| 5 | 外部の死活監視（Healthchecks.io 等）の ping URL を Secret `HEALTHCHECK_PING_URL` に登録 | 任意 | 「監視停止」の節 |
| 6 | Dependabot alerts も併用する場合は、各アプリで alerts を有効化し、読み取り専用トークンを `DEPENDABOT_ALERTS_TOKEN` に登録 | 任意 | 「認証・権限」の節 |

配備（ローカルから）:
```
gh repo create okakanatto/okakanatto-maintenance --private --source . --push
gh workflow run maintenance -R okakanatto/okakanatto-maintenance -f checks=all
```
公開（`--public`）でも動きますが、公開リポジトリの定期実行は 60 日無活動で止まることがあります（「監視停止」）。非公開なら対象外で、Actions の無料枠（Free プランで月 2,000 分）に対し使用量は月 100 分程度の見込みです。

## 日常の運用

- **何もしない日がふつう**です。変化がなければ通知は来ません（ダッシュボードの本文更新は通知されません）
- 新しい保守 Issue が来たら、本文の「推奨対応」「未検証事項」を読み、アプリ側で直す
- 直して push（配布版に含まれる問題なら新しいリリースも）すると、次回の監視で検証して**自動で閉じます**（ラベル `maint:resolved`）
- **直すのも任せられます**: Claude Code / Codex に「#3 を直して」と頼むと、PR の作成からテスト・ビルド確認、マージまで行います（`AGENTS.md` 6 章）。リリース（exe の作成と配布）だけは自分で判断します。各アプリを手元で開発するときは、最初に `git pull` で取り込んでください
- 毎月 1 日ごろ「定期点検」Issue が来ます。確認した項目に ✓ を付け、終わったら閉じます。**この Issue が来なければ監視が止まっています**
- Claude Code / Codex には「全アプリの保守状況を確認して」と頼めば、`AGENTS.md` の手順で Issue とレポートから報告します

## 新しいアプリを追加したとき

**何もしなくてよい**です。`okakanatto` の公開リポジトリとして push すれば、次回の監視（翌朝）で自動発見され、
周期に関係なく全検査（初回棚卸し）を受けて監視に入ります。問題がなければ通知は来ず、ダッシュボードに「新規」と表示されます。

- 監視したくないリポジトリは `config/maintenance.json` の `exclude`（名前または ID）へ
- fork・archive 済み・非公開・このリポジトリ自身は自動で除外
- 空のリポジトリは異常ではなく「コード未登録」として扱います
- リポジトリ名を変えても数値 ID で追跡するので、Issue は引き継がれます
- 一覧から消えた（削除・非公開化・権限消失・移管）場合は、`kind:lifecycle` の Issue で知らせます。**消えたことを理由に関連 Issue を閉じません**

## 定期監視の内容

| 周期 | 検査 | 情報源 | Issue にする条件 |
|---|---|---|---|
| 毎日 | 脆弱性 | ロックファイル（npm・Cargo・Python・Go・NuGet・Composer）を OSV.dev で照合。サブモジュールは固定コミットを照合し、上流の公開勧告も確認 | 既知脆弱性がある（`vuln_min_severity` 以上） |
| 毎日 | 配布版 | GitHub Releases の最新版。タグ時点のソースも同じく脆弱性照合 | 上と同じ Issue の「範囲」にタグとして表示 |
| 毎日 | CI | 既存ワークフローの状態・既定ブランチの最新実行・使用アクションの実行環境・ランナーの提供期限 | 失敗している／一度も動いていない／削除済み・削除予定の Node のアクション／提供終了ランナー |
| 毎週 | 依存更新 | 直接依存を npm・crates.io・PyPI と照合。上流（サブモジュール等）・アクションの新版 | 使用中の版が非推奨・取り下げ／本番の直接依存が 2 メジャー以上遅れ |
| 毎月 | サポート終了 | リポジトリに書かれた版（Qt・Node.js・Next.js・Python 等）を endoflife.date と照合 | サポート終了済み／90 日以内に終了 |
| 毎月 | 定期点検 | `manual_checks` の項目（WebView2・Tauri・Windows・C/C++ 依存・ソース非公開の配布物・監視の稼働） | 期日が来た項目を 1 件の Issue にまとめる |

週次・月次は「その周期の前回完了から期日が来た日」に毎日の実行へ自動で含まれるので、ある日に失敗しても翌日に回ります。

**新しい版があるだけでは Issue にしません**（パッチ・マイナー・1 メジャー差・アクションの新版・上流の新リリースはダッシュボードの「情報」に集約）。

## 監視できること・できないこと

| 範囲 | 状態 | 説明 |
|---|---|---|
| npm / Cargo / Python / Go / NuGet / Composer のロックファイル | 対応 | 間接依存を含む。`yarn.lock`・`pnpm-lock.yaml`・`bun.lock` は検出して「未対応」と表示 |
| ロックファイルの無い依存定義（`package.json` だけ等） | 未対応 | 版が確定しないため照合できない |
| Git サブモジュール | 部分 | OSV のコミット照合は OSV が索引した上流だけ有効。0 件は安全の根拠にならない |
| C/C++ のソース・vcpkg・Conan・Qt・Tesseract 等 | 未対応（Qt の EOL は対応） | OSV にエコシステムが無い。vcpkg 一覧はレポートに出し、月次点検で人が確認 |
| 配布バイナリ（exe・zip） | 不明（SBOM 添付時は部分） | 配布物の安全性は断定しない。タグ時点のソースの依存は同じく照合し、Issue の「範囲」にタグ名で出す。バイナリとソースの一致は未検証 |
| Dependabot alerts | 任意 | 読み取りトークンがあれば追加の情報源にする（無ければ OSV だけで成立） |
| 到達可能性（脆弱なコードを実際に使っているか） | 未対応 | Issue の「未検証事項」に毎回書く |
| 未 push の変更・手元のビルド環境・Windows 上の実動作 | 対象外 | 監視の正本は GitHub 上のリモート |

## Issue の扱い

- **一意キー**: `種別:リポジトリID:対象`（例 `vuln:1164599744:npm:prod`）。本文末尾の `maint-key` に書かれ、同じ問題は同じ Issue を更新します
- 脆弱性は**リポジトリ × エコシステム × 本番/開発用**に束ねます。1 回の依存更新で片付く単位で、勧告ごとに Issue を作って埋もれるのを防ぐためです。個々の勧告は本文の表にあります
- **通知を出すのは**: 新規作成・内容の変化（勧告の増減、重要度、範囲）・解消・再発・抑制期限切れ のときだけ。変化がなければ何もしません（最終確認日時は 7 日ごとに本文だけ更新）
- **自動で閉じるのは**、同じ範囲の検査が今回成功し、検出が無かったときだけ。取得失敗・レート制限・権限不足・スキャナ未対応・リポジトリ消失・その周期の検査が今回走っていない、のいずれでも閉じません
- **人が閉じた Issue は再オープンしません**（ツールが閉じた `maint:resolved` のものだけ、再発時に再オープン）。
  ただし束ねた Issue に新しい勧告が入った・重要度が上がったときは、閉じたまま 1 回だけコメントで知らせます
- 検査の一部が失敗した日は、その Issue の内容を書き換えません（一時的な失敗で「変わりました」が往復しないため）
- 同じ検査が 3 回続けて失敗すると `kind:health` の Issue で知らせます（監視できていない範囲の放置を防ぐ）

### 重要度と対応目安

| 重要度 | 根拠 | 対応目安 |
|---|---|---|
| Critical / High / Medium / Low | GHSA の区分、無ければ CVSS v3 基本値から算出。どちらも無ければ Medium と仮定し「未検証事項」に明記 | 3 / 14 / 30 / 90 日 |
| Info | RUSTSEC の unmaintained 等の情報提供 | Issue にしない |

開発用依存（npm の `dev`、`requirements-dev.txt` 等の名前）だけで見つかったものは 1 段階下げます（`issue_policy.dev_only_downgrade`）。

## 誤検知の抑制（保留・リスク受容）

`config/suppressions.json` に追記してコミットします。`snoozed`（保留）と `risk_accepted`（リスク受容）は再評価日 `until` が必須です。

```json
{
  "suppressions": [
    {"key": "vuln:1164599744:GHSA-xxxx-xxxx-xxxx", "status": "false_positive", "reason": "該当 API を使っていない", "by": "okakanatto"},
    {"key": "eol:1418215143:qt:6.9", "status": "risk_accepted", "reason": "次の版で Qt 6.12 へ移行", "until": "2027-01-31"}
  ]
}
```
- キーは Issue 本文末尾の `maint-key`。脆弱性は勧告 1 件（`vuln:<リポジトリID>:<GHSA/CVE/RUSTSEC>`）単位でも指定できます
- 抑制中は新規作成もコメントもしません。期限を過ぎるとラベル `maint:suppressed` を外して 1 回だけ知らせます
- 束ねた Issue を手で閉じるより、勧告ごとに抑制するほうが確実です（手で閉じると期限付きの再評価になりません）

## 認証・権限

| 用途 | トークン | 権限 |
|---|---|---|
| このリポジトリの Issue 読み書き | Actions の `GITHUB_TOKEN`（自動） | ワークフローで `issues: write`・`contents: read` だけを付与 |
| 監視対象（公開リポジトリ）の読み取り | 同上（公開データの読み取り） | 追加設定不要。上限 1,000 回/時（通常の 1 回の実行は数百回以内） |
| 監視対象の読み取りを分離したい場合 | 任意の Secret `MAINT_READ_TOKEN` | fine-grained PAT・Public repositories（read-only）。書き込み権限は付けない |
| Dependabot alerts | 任意の Secret `DEPENDABOT_ALERTS_TOKEN` | fine-grained PAT、対象リポジトリに「Dependabot alerts: Read-only」だけ。加えて各アプリで Dependabot alerts を有効化（アプリ側の設定変更になるため任意） |

- `GITHUB_TOKEN` は自分のリポジトリにしか書けず、他リポジトリの Dependabot alerts は読めません。トークン未設定でも OSV で脆弱性監視は成立し、ダッシュボードに「Dependabot alerts: 未取得」と出ます
- 書き込みは中央リポジトリ宛てだけに制限してあり（`IssueWriter`）、他リポジトリへの書き込みはコード上で拒否されます
- 外部由来の文字列（勧告の要約など）は `@メンション`・`#番号`・他リポジトリ Issue への自動リンクを無効化してから Issue に書きます（相手側へ通知・相互参照を出さない）

## 認証・権限が足りないとき（症状と対処）

| 症状 | 原因 | 対処 |
|---|---|---|
| ジョブが失敗し、実行状態が ERROR（「Issue 同期に失敗」「中央リポジトリの Issue を読めない」） | Issue の書き込み権限が無い | ワークフローの `permissions: issues: write` を消していないか、Settings → Actions → General → Workflow permissions を確認 |
| あるリポジトリの検査が「失敗」（403/404） | 一覧には出たが読めない（権限消失・API 障害） | その範囲の Issue は閉じない。3 回続くと `kind:health` の Issue。原因を確認する |
| 「rate_limited」で一部失敗 | 1 時間あたりの API 上限 | 待たずに失敗として記録し翌日再試行。頻発するなら `MAINT_READ_TOKEN` で読み取りを分ける |
| ダッシュボードに「Dependabot alerts: 未取得」 | トークン未設定（既定） | 任意。必要なら「認証・権限」の表のとおり設定 |
| `vuln.dependabot` が「未対応」 | そのリポジトリで alerts が無効 | 任意。アプリ側の Settings → Code security で有効化 |
| `vuln.dependabot` が「不明」 | トークンの権限不足・期限切れ（401/403） | トークンを作り直す。その回は脆弱性 Issue を閉じない |
| ローカル実行で「GITHUB_TOKEN が無い」 | 環境変数なし | `GITHUB_TOKEN=$(gh auth token)` を付ける（未認証は 60 回/時で足りない） |

## 監視停止（定期実行が止まったとき）

**止まった監視は、自分自身では知らせられません。** 次の 3 つで気づけるようにしています。

1. **月次点検 Issue が来ない** — 毎月 1 日ごろに必ず届きます。届かなければ停止を疑う（追加設定なし）
2. **ダッシュボードの最終実行日時** — 2 日より古ければ停止。AI に状況確認を頼むと最初にここを見ます
3. **外部の死活監視（推奨・無料）** — Healthchecks.io（無料で 20 件）等で「1 日 1 回 ping が来なければメール」を作り、URL を Secret `HEALTHCHECK_PING_URL` に登録。ジョブ失敗時は `/fail` を送ります

主な停止理由と対処:

| 理由 | 対処 |
|---|---|
| 公開リポジトリで 60 日間リポジトリの活動が無い（GitHub の仕様。非公開リポジトリには無い） | Actions → maintenance → 「Enable workflow」。根本対策はこのリポジトリを非公開にすること。**空コミットを繰り返す方法は採らない** |
| 自己テストの失敗・ジョブの失敗 | GitHub から失敗メールが届く（ワークフローの cron を最後に変更した人宛て）。ログを確認 |
| Actions の障害・無料枠超過 | 復旧後の実行で自動的に追いつく（週次・月次は期日方式） |

## 手動実行

```
# 期日が来た検査だけ（定期実行と同じ）
gh workflow run maintenance -R okakanatto/okakanatto-maintenance
# 全検査
gh workflow run maintenance -R okakanatto/okakanatto-maintenance -f checks=all
# Issue に書き込まず、予定の操作だけ見る
gh workflow run maintenance -R okakanatto/okakanatto-maintenance -f checks=all -f dry_run=true
```
ローカルで読み取りだけ試す（書き込みなし）:
```
GITHUB_TOKEN=$(gh auth token) python -m maint run --dry-run --checks all --report-dir out
```
`--repo <名前>` で 1 リポジトリだけ検査できます（この場合は消失判定と自動クローズをしません）。

## 設定ファイル

- `config/maintenance.json` — 所有者・除外・個別ポリシー（`repo_policies`: `ignore_paths` や `issue_policy` の上書き）・判定基準・定期点検項目
- `config/suppressions.json` — 誤検知・保留・リスク受容
- 変更したら `python -m maint validate` で検証（push 時の tests ワークフローでも検証されます）

## 開発

- Python 3.11 以上・標準ライブラリのみ。テストは `python -m unittest discover -s tests -t .`
- AI 向けの運用ルールと開発ルールは `AGENTS.md`（Claude Code は `CLAUDE.md` 経由で同じものを読む）
- 設計判断の記録は `docs/DESIGN.md`
