"""偽の GitHub に対して監視を何度も実行し、発見・Issue 同期・解消判定の規則を確かめる。"""

import unittest

from maint.http import TransportTimeout

from . import world as W
from .fakes import FakeRepo, Snapshot, resp


def keys(runner):
    import re

    out = []
    for i in runner.managed():
        m = re.search(r"<!-- maint-key: (\S+) -->", i["body"])
        out.append(m.group(1))
    return out


class DiscoveryTests(unittest.TestCase):
    def test_discovery_exclusions_and_coverage(self):
        r = W.Runner(W.build_world())
        rep = r.run()
        names = [x["name"] for x in rep["repos"]]
        self.assertEqual(sorted(names), ["AppA", "BinOnly", "EmptyRepo", "NativeApp"])
        excluded = {e["name"].split("/")[1]: e["reason"] for e in rep["discovery"]["excluded"]}
        self.assertEqual(excluded["okakanatto-maintenance"], "中央保守リポジトリ自身")
        self.assertEqual(excluded["ForkRepo"], "fork")
        self.assertEqual(excluded["OldRepo"], "archive 済み")
        empty = next(x for x in rep["repos"] if x["name"] == "EmptyRepo")
        self.assertTrue(empty["inventory"]["empty"])
        self.assertEqual(empty["checks"]["vuln"]["coverage"]["vuln"]["level"], "NOT_APPLICABLE")
        self.assertEqual(empty.get("error"), None)
        native = next(x for x in rep["repos"] if x["name"] == "NativeApp")
        cov = native["checks"]["vuln"]["coverage"]
        # C++ は「対応」にしない
        self.assertEqual(cov["vuln.native"]["level"], "UNSUPPORTED")
        self.assertEqual(cov["vuln.native-packages"]["level"], "UNSUPPORTED")
        self.assertEqual(cov["vuln.submodule"]["level"], "PARTIAL")
        binonly = next(x for x in rep["repos"] if x["name"] == "BinOnly")
        self.assertEqual(binonly["checks"]["vuln"]["coverage"]["vuln.source"]["level"], "UNSUPPORTED")
        self.assertEqual(binonly["checks"]["release"]["coverage"]["release"]["level"], "UNKNOWN")

    def test_pagination_over_100_and_new_repo_found_next_run(self):
        w = W.build_world()
        for i in range(140):
            w.add_repo(FakeRepo(2000 + i, f"bulk{i:03d}", empty=True))
        r = W.Runner(w)
        rep = r.run()
        self.assertEqual(len(rep["repos"]), 144)
        self.assertGreaterEqual(sum(1 for m, u in w.log if "/users/okakanatto/repos" in u), 2)
        w.add_repo(FakeRepo(3000, "zzz-new-app", head=Snapshot("9" * 40, {"requirements.txt": b"flask==3.0.0\n"})))
        rep2 = r.run()
        new = [e["name"] for e in rep2["discovery"]["new"]]
        self.assertEqual(new, ["okakanatto/zzz-new-app"])
        # 新規は周期に関係なく全検査（daily の実行でも deps・eol が走る）
        z = next(x for x in rep2["repos"] if x["name"] == "zzz-new-app")
        self.assertNotEqual(z["checks"]["deps"]["status"], "SKIPPED")
        self.assertNotEqual(z["checks"]["eol"]["status"], "SKIPPED")
        rep3 = r.run()
        self.assertEqual(rep3["discovery"]["new"], [])  # 再スキャンで重複登録しない
        self.assertEqual(len(rep3["state"]["repos"]), 145)

    def test_rename_keeps_issues(self):
        w = W.build_world()
        r = W.Runner(w)
        r.run()
        before = {k: r.by_key(k)["number"] for k in keys(r)}
        w.repos[101].name = "AppRenamed"
        rep = r.run()
        self.assertEqual(rep["discovery"]["renamed"], [{"id": 101, "name": "okakanatto/AppRenamed", "old": "okakanatto/AppA"}])
        after = {k: r.by_key(k)["number"] for k in keys(r)}
        self.assertEqual(before, after)  # 新しい Issue は作られない
        iss = r.by_key("vuln:101:npm:prod")
        self.assertIn("AppRenamed", iss["title"])
        self.assertNotIn(iss["number"], w.comments)  # 名前変更だけでコメントしない
        self.assertEqual(rep["state"]["repos"]["101"]["names"], ["okakanatto/AppA"])

    def test_missing_repo_is_not_resolution(self):
        w = W.build_world()
        r = W.Runner(w)
        r.run()
        n = r.by_key("vuln:101:npm:prod")["number"]
        w.hidden.add(101)
        rep = r.run()
        self.assertEqual(rep["discovery"]["missing"][0]["state"], "gone_or_private")
        self.assertEqual(w.issue(n)["state"], "open")
        self.assertIsNotNone(r.by_key("lifecycle:101:missing"))
        # API 障害の場合は別の状態として扱う
        w.repo_by_id_status[101] = 503
        rep2 = r.run()
        self.assertEqual(rep2["discovery"]["missing"][0]["state"], "api_error")
        self.assertEqual(w.issue(n)["state"], "open")
        # 戻ってきたら監視再開し、消失 Issue は解消
        w.hidden.discard(101)
        del w.repo_by_id_status[101]
        rep3 = r.run()
        self.assertEqual([x["name"] for x in rep3["discovery"]["returned"]], ["okakanatto/AppA"])
        self.assertEqual(r.by_key("lifecycle:101:missing")["state"], "closed")

    def test_transferred_and_private(self):
        w = W.build_world()
        r = W.Runner(w)
        r.run()
        w.hidden.add(102)
        w.repo_by_id_status[102] = 200
        orig = w._github

        def patched(method, path, q, body, req):
            if path == "/repositories/102":
                return resp(200, {**w.repos[102].api(), "full_name": "someone/NativeApp", "owner": {"login": "someone"}})
            return orig(method, path, q, body, req)

        w._github = patched
        rep = r.run()
        self.assertEqual(rep["discovery"]["missing"][0]["state"], "transferred")


class IssueSyncTests(unittest.TestCase):
    def test_first_run_creates_then_repeated_runs_are_silent(self):
        w = W.build_world()
        r = W.Runner(w)
        rep = r.run()
        ks = sorted(keys(r))
        self.assertIn("vuln:101:npm:prod", ks)
        self.assertIn("vuln:101:npm:dev", ks)
        self.assertIn("vuln:101:crates.io:prod", ks)
        self.assertIn("eol:102:qt:6.9", ks)
        self.assertIn("ci-action:102", ks)
        self.assertIn("ci-never-run:102:9001", ks)
        self.assertNotIn("vuln-info:101", ks)  # unmaintained 情報は Issue にしない
        self.assertEqual(len(ks), len(set(ks)))
        crit = r.by_key("vuln:101:npm:prod")
        self.assertIn("sev:critical", {lb["name"] for lb in crit["labels"]})
        self.assertNotIn("@attacker", crit["body"])  # 外部テキストのメンションを無害化
        self.assertNotIn("https://github.com/foo/bar/issues/5)", crit["body"])
        dev = r.by_key("vuln:101:npm:dev")
        self.assertIn("sev:medium", {lb["name"] for lb in dev["labels"]})  # High の dev 依存は 1 段階下げる
        # 10 回連続で実行しても Issue は増えず、ダッシュボード以外への書き込みは無い
        for _ in range(10):
            w.log.clear()
            r.run(advance_hours=1)
            non_dash = [x for x in w.writes() if not x[1].endswith(f"/issues/{_dashboard(r)}")]
            self.assertEqual(non_dash, [], non_dash)
        self.assertEqual(sorted(keys(r)), ks)
        self.assertEqual(sum(len(v) for v in w.comments.values()), 0)

    def test_weekly_refresh_updates_body_without_comment(self):
        w = W.build_world()
        r = W.Runner(w)
        r.run()
        w.log.clear()
        r.run(advance_hours=24 * 8)
        r.run()  # 8 日後の実行で本文だけ更新
        self.assertTrue(any(m == "PATCH" for m, _ in w.writes()))
        self.assertEqual(sum(len(v) for v in w.comments.values()), 0)

    def test_fix_closes_only_when_verified_and_reopens(self):
        w = W.build_world()
        r = W.Runner(w)
        r.run()
        n = r.by_key("vuln:101:npm:prod")["number"]
        fixed = Snapshot("4" * 40, W.app_files(next_ver="16.1.7"))
        # main だけ直してリリース前 → 配布版に残るので閉じない
        w.repos[101].head = fixed
        r.run()
        iss = w.issue(n)
        self.assertEqual(iss["state"], "open")
        self.assertIn("v1.0.0", iss["body"])
        self.assertTrue(any("where" in c["body"] for c in w.comments.get(n, [])))  # 範囲の変化を 1 回コメント
        # OSV が落ちている日は、検出が消えても閉じない
        w.repos[101].tags["v1.1.0"] = fixed
        w.repos[101].releases.insert(0, {"tag_name": "v1.1.0", "draft": False, "prerelease": False, "published_at": "2026-10-20T00:00:00Z", "assets": []})
        w.fault("api.osv.dev/v1/querybatch", *[resp(503, {"message": "down"})] * 10)
        rep = r.run()
        self.assertEqual(w.issue(n)["state"], "open")
        self.assertEqual(rep["repos"][0]["checks"]["vuln"]["status"], "ERROR")
        self.assertTrue(any(o["what"] == "absent_unverified" for o in rep["issues"]["observations"]))
        # 復旧した日に検証できたので閉じる
        w.faults.clear()
        r.run()
        iss = w.issue(n)
        self.assertEqual(iss["state"], "closed")
        self.assertIn("maint:resolved", {lb["name"] for lb in iss["labels"]})
        # 再発したら同じ Issue を再オープン
        w.repos[101].head = Snapshot("5" * 40, W.app_files())
        r.run()
        self.assertEqual(w.issue(n)["state"], "open")
        self.assertEqual(len([k for k in keys(r) if k == "vuln:101:npm:prod"]), 1)

    def test_human_closed_is_respected(self):
        w = W.build_world()
        r = W.Runner(w)
        r.run()
        n = r.by_key("eol:102:qt:6.9")["number"]
        w.issue(n)["state"] = "closed"  # 人が閉じた（maint:resolved なし）
        rep = r.run(checks="all")
        self.assertEqual(w.issue(n)["state"], "closed")
        self.assertTrue(any(o["what"] == "closed_still_detected" and o["number"] == n for o in rep["issues"]["observations"]))
        self.assertEqual(len([k for k in keys(r) if k == "eol:102:qt:6.9"]), 1)

    def test_suppression_hold_and_expiry(self):
        w = W.build_world()
        cfg = W.with_suppressions(W.config_mod.load(), [
            {"key": "eol:102:qt:6.9", "status": "risk_accepted", "reason": "次版で Qt 6.12 へ", "until": "2026-10-20"},
            {"key": "vuln:101:CVE-2026-1111", "status": "false_positive", "reason": "該当機能を使っていない"},
        ])
        r = W.Runner(w, cfg)
        rep = r.run()
        self.assertIsNone(r.by_key("eol:102:qt:6.9"))  # 抑制中は作らない
        self.assertTrue(any(o["what"] == "suppressed_not_created" for o in rep["issues"]["observations"]))
        npm_prod = next((f for f in rep["findings"] if f["key"] == "vuln:101:npm:prod"), None)
        self.assertIsNone(npm_prod)  # 唯一の勧告が別 ID（CVE）で誤検知登録 → 束ねた Issue も無い
        r.run(advance_hours=24 * 4)
        r.run(checks="all")  # 期限切れ後の月次検査で作成される
        self.assertIsNotNone(r.by_key("eol:102:qt:6.9"))

    def test_suppression_expiry_on_existing_issue(self):
        w = W.build_world()
        r = W.Runner(w)
        r.run()
        n = r.by_key("ci-action:102")["number"]
        r.cfg = W.with_suppressions(r.cfg, [{"key": "ci-action:102", "status": "snoozed", "reason": "来月対応", "until": "2026-10-19"}])
        r.run()
        self.assertIn("maint:suppressed", {lb["name"] for lb in w.issue(n)["labels"]})
        self.assertEqual(w.comments.get(n, []), [])
        r.run(advance_hours=24 * 3)
        r.run()
        self.assertNotIn("maint:suppressed", {lb["name"] for lb in w.issue(n)["labels"]})
        self.assertEqual(len([c for c in w.comments.get(n, []) if "再評価期限" in c["body"]]), 1)
        r.run()
        self.assertEqual(len([c for c in w.comments.get(n, []) if "再評価期限" in c["body"]]), 1)  # 1 回だけ

    def test_partial_failure_keeps_other_repos_and_issues(self):
        w = W.build_world()
        r = W.Runner(w)
        r.run()
        n = r.by_key("eol:102:qt:6.9")["number"]
        w.fault("/repos/okakanatto/NativeApp/git/trees/", *[resp(500, {"message": "boom"})] * 10)
        rep = r.run(checks="all")
        self.assertEqual(rep["run"]["status"], "PARTIAL")
        native = next(x for x in rep["repos"] if x["name"] == "NativeApp")
        self.assertIn("ツリーを取得できない", native["error"])
        self.assertEqual(w.issue(n)["state"], "open")
        app = next(x for x in rep["repos"] if x["name"] == "AppA")
        self.assertEqual(app["checks"]["vuln"]["status"], "SUCCESS")
        self.assertIn("失敗", rep["markdown"])

    def test_three_consecutive_failures_open_health_issue(self):
        w = W.build_world()
        r = W.Runner(w)
        r.run()
        w.fault("/repos/okakanatto/AppA/releases", *[TransportTimeout("t")] * 60)
        for _ in range(3):
            r.run()
        self.assertIsNotNone(r.by_key("health:101:release"))
        w.faults.clear()
        r.run()
        self.assertEqual(r.by_key("health:101:release")["state"], "closed")

    def test_inventory_failures_open_health_issue(self):
        w = W.build_world()
        r = W.Runner(w)
        r.run()
        w.fault("/repos/okakanatto/NativeApp/git/trees/", *[resp(500, {})] * 60)
        for _ in range(3):
            r.run()
        self.assertIsNotNone(r.by_key("health:102:inventory"))
        w.faults.clear()
        r.run()
        self.assertEqual(r.by_key("health:102:inventory")["state"], "closed")

    def test_failed_weekly_is_retried_next_day(self):
        w = W.build_world()
        r = W.Runner(w)
        r.run(checks="all")
        r.now = r.now.replace(day=26)  # 1 週間以上あと
        w.fault("/repos/okakanatto/AppA/git/trees/", *[resp(500, {})] * 3)
        rep = r.run(checks="auto")
        self.assertIn("weekly", rep["run"]["periods"])
        w.faults.clear()
        rep2 = r.run(checks="auto")
        self.assertIn("weekly", rep2["run"]["periods"])  # 失敗した週次は翌日に再実行
        rep3 = r.run(checks="auto")
        self.assertNotIn("weekly", rep3["run"]["periods"])

    def test_closed_dashboard_state_is_inherited(self):
        w = W.build_world()
        r = W.Runner(w)
        r.run()
        dash = next(i for i in w.issues if "maint:dashboard" in {lb["name"] for lb in i["labels"]})
        dash["state"] = "closed"
        rep = r.run()
        self.assertEqual(rep["discovery"]["new"], [])  # 台帳を引き継いだので全部「新規」にならない
        dashes = [i for i in w.issues if "maint:dashboard" in {lb["name"] for lb in i["labels"]} and i["state"] == "open"]
        self.assertEqual(len(dashes), 1)

    def test_titles_are_neutralized(self):
        from maint.issues import sync
        from maint.model import Finding

        w = W.build_world()
        r = W.Runner(w)
        http = W.HttpClient(transport=w, sleep=lambda s: None)
        writer = W.IssueWriter(http, "t", W.CENTRAL)
        f = Finding(key="deps-deprecated:101:npm:@evil/pkg", kind="deps", repo_id=101, repo_name="AppA",
                    title="[依存] AppA: @evil/pkg 1.0 が非推奨", severity="medium", summary="x")
        sync(writer, r.cfg, [], [f], set(), r.now, None)
        self.assertNotIn("@evil", w.issues[0]["title"])
        w.log.clear()
        issues = writer.list_issues("maint:auto")
        sync(writer, r.cfg, issues, [f], set(), r.now, None)
        self.assertEqual(w.writes(), [])  # 無害化した題名どうしの比較で「題名変更」と誤判定しない

    def test_listing_failure_does_nothing(self):
        w = W.build_world()
        r = W.Runner(w)
        r.run()
        w.log.clear()
        w.fault("/users/okakanatto/repos", *[resp(502, {})] * 10)
        rep = r.run()
        self.assertEqual(rep["run"]["status"], "ERROR")
        self.assertEqual(w.writes(), [])  # 一覧が取れない回は Issue もダッシュボードも触らない

    def test_dry_run_writes_nothing(self):
        w = W.build_world()
        r = W.Runner(w)
        rep = r.run(dry_run=True, checks="all")
        self.assertEqual(w.writes(), [])
        self.assertTrue(any(a["op"] == "create" for a in rep["issues"]["actions"]))
        self.assertTrue(rep["issues"]["planned_writes"])

    def test_double_run_same_moment_is_consistent(self):
        w = W.build_world()
        r = W.Runner(w)
        r.run(advance_hours=0)
        r.run(advance_hours=0)
        ks = keys(r)
        self.assertEqual(len(ks), len(set(ks)))
        dashboards = [i for i in w.issues if "maint:dashboard" in {lb["name"] for lb in i["labels"]}]
        self.assertEqual(len(dashboards), 1)

    def test_manual_check_cycle(self):
        w = W.build_world()
        r = W.Runner(w)
        r.run(checks="all")
        manual = r.by_key("manual:2026-10")
        self.assertIsNotNone(manual)
        self.assertIn("item:monitor-alive", manual["body"])
        self.assertIn("item:webview2", manual["body"])  # Tauri / README の WebView2 から
        self.assertIn("item:native-deps", manual["body"])  # C++ の未対応領域から
        self.assertIn("item:binary-only", manual["body"])
        # 人が 1 項目 ✓ を付けたまま翌月へ
        manual["body"] = manual["body"].replace("- [ ] **監視そのもの", "- [x] **監視そのもの")
        r.now = r.now.replace(month=11, day=1)
        rep = r.run(checks="auto")  # 月が変わったので monthly が走る
        self.assertIn("monthly", rep["run"]["periods"])
        nov = r.by_key("manual:2026-11")
        self.assertIsNotNone(nov)
        self.assertNotIn("item:monitor-alive", nov["body"])  # 28 日周期の項目は完了済み
        self.assertEqual(w.issue(manual["number"])["state"], "closed")
        self.assertIn("maint:superseded", {lb["name"] for lb in w.issue(manual["number"])["labels"]})

    def test_central_missing_is_error_without_dry_run(self):
        w = W.build_world()
        w.central_exists = False
        rep = W.Runner(w).run()
        self.assertEqual(rep["run"]["status"], "ERROR")
        self.assertEqual(w.writes(), [])


class VulnCheckTests(unittest.TestCase):
    def test_osv_failure_leaves_no_verified_vuln_scope(self):
        from maint.checks.release import check_release
        from maint.checks.vuln import check_vuln
        from maint.inventory import build_inventory

        w = W.build_world()
        w.fault("api.osv.dev/v1/querybatch", *[resp(500, {})] * 10)
        r = W.Runner(w)
        http = W.HttpClient(transport=w, sleep=lambda s: None, max_retries=1, backoff=0.01)
        ctx = W.Context(r.cfg, W.GitHubReader(http, "t"), http, W.OSVClient(http), r.now)
        repo = W.Repo.from_api(w.repos[101].api())
        inv = build_inventory(ctx.reader, repo, "main")
        rel, rel_inv = check_release(ctx, repo, inv)
        res = check_vuln(ctx, repo, inv, rel, rel_inv)
        self.assertEqual(res.status, "ERROR")
        self.assertEqual([t for t in res.verified_scopes if t.startswith("vuln")], [])
        self.assertEqual(res.coverage["vuln.npm"].level, "UNKNOWN")


class ReportTests(unittest.TestCase):
    def test_all_clean_report_does_not_claim_unmonitored_is_ok(self):
        w = W.build_world()
        w.osv_db = {}
        for rid in (102, 103):
            del w.repos[rid]
        w.repos[101].head = Snapshot("6" * 40, {"requirements.txt": b"flask==3.0.0\n"})
        w.repos[101].releases = []
        w.repos[101].tags = {}
        rep = W.Runner(w).run()
        md = rep["markdown"]
        self.assertEqual(rep["run"]["status"], "SUCCESS")
        self.assertIn("Issue 化の基準を満たす問題は見つからなかった", md)
        self.assertIn("PyPI:対応", md)
        self.assertIn("未実施", md)  # 今回の周期で走らない検査を成功と書かない

    def test_partial_and_unknown_are_visible(self):
        w = W.build_world()
        w.fault("api.osv.dev/v1/querybatch", *[resp(500, {})] * 20)
        rep = W.Runner(w).run()
        md = rep["markdown"]
        self.assertEqual(rep["run"]["status"], "PARTIAL")
        self.assertIn("**失敗**", md)
        self.assertIn("OSV 照合に失敗", md)


def _dashboard(r):
    d = [i for i in r.w.issues if "maint:dashboard" in {lb["name"] for lb in i["labels"]}]
    return d[0]["number"] if d else -1


if __name__ == "__main__":
    unittest.main()
