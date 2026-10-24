"""独立レビュー（2026-10-17）で見つかった欠陥の再発防止テスト。番号はレビューの指摘番号。"""

import copy
import json
import unittest

from maint.http import HttpClient, HttpError
from maint.issues import neutralize

from . import world as W
from .fakes import FakeRepo, Snapshot, npm_lock, resp
from .test_units import Seq

NODE16_WF = b"on:\n  push:\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/setup-node@v4\n        with:\n          node-version: 16\n"


def labels(i):
    return {lb["name"] for lb in i["labels"]}


class ReviewRegressionTests(unittest.TestCase):
    def test_01_same_key_findings_make_one_issue(self):
        w = W.build_world()
        w.eol["nodejs"] = [{"name": "24", "isEol": False, "eolFrom": "2028-04-30"}, {"name": "16", "isEol": True, "eolFrom": "2023-09-11"}]
        dep = {"dependencies": {"oldlib": "1.0.0"}}
        w.add_repo(FakeRepo(201, "NodeApp", head=Snapshot("7" * 40, {
            ".github/workflows/a.yml": NODE16_WF, ".github/workflows/b.yml": NODE16_WF, ".nvmrc": b"16\n",
            "package.json": json.dumps(dep).encode(), "package-lock.json": npm_lock({"oldlib": ("1.0.0", False)}, ["oldlib"]),
            "web/package.json": json.dumps(dep).encode(), "web/package-lock.json": npm_lock({"oldlib": ("1.0.0", False)}, ["oldlib"]),
        })))
        w.npm["oldlib"] = {"dist-tags": {"latest": "1.0.0"}, "versions": {"1.0.0": {"deprecated": "use newlib"}}}
        r = W.Runner(w)
        r.run(checks="all")
        keys = [i["body"].split("maint-key: ")[1].split(" ")[0] for i in r.managed()]
        self.assertEqual(keys.count("eol:201:nodejs:16"), 1)
        self.assertEqual(keys.count("deps-deprecated:201:npm:oldlib"), 1)
        r.run(checks="all")
        self.assertEqual(sum(len(v) for v in w.comments.values()), 0)  # 二重コメントも無い

    def test_02a_upstream_advisory_fetch_failure_does_not_close(self):
        w = W.build_world()
        w.repos[901].advisories = [{"ghsa_id": "GHSA-up-0001", "html_url": "https://github.com/advisories/GHSA-up-0001"}]
        r = W.Runner(w)
        r.run()
        n = r.by_key("vuln-upstream:102:vendor/lib")["number"]
        w.repos[901].advisories = []
        w.fault("/repos/upstream/lib/security-advisories", *[resp(500, {})] * 10)
        r.run()
        self.assertEqual(w.issue(n)["state"], "open")
        w.faults.clear()
        r.run()
        self.assertEqual(w.issue(n)["state"], "closed")

    def test_02b_action_yml_failure_does_not_close(self):
        w = W.build_world()
        r = W.Runner(w)
        r.run()
        n = r.by_key("ci-action:102")["number"]
        w.repos[900].head.files["action.yml"] = b"runs:\n  using: node24\n"
        w.fault("/repos/actions/checkout/contents/action.yml", *[resp(502, {})] * 10)
        r.run()
        self.assertEqual(w.issue(n)["state"], "open")
        w.faults.clear()
        r.run()
        self.assertEqual(w.issue(n)["state"], "closed")

    def test_02c_runner_image_data_failure_does_not_close(self):
        w = W.build_world()
        w.eol["github-actions-runner-images"].append({"name": "ubuntu-22.04", "isEol": True, "eolFrom": "2026-09-17"})
        w.repos[102].head.files[".github/workflows/source-checks.yml"] = W.WORKFLOW_PUSH.replace(b"ubuntu-latest", b"ubuntu-22.04")
        r = W.Runner(w)
        r.run()
        n = r.by_key("ci-runner:102:ubuntu-22.04")["number"]
        w.fault("endoflife.date/api/v1/products/github-actions-runner-images", *[resp(503, {})] * 10)
        r.run()
        self.assertEqual(w.issue(n)["state"], "open")

    def test_02d_one_lockfile_failure_keeps_deps_issue(self):
        w = W.build_world()
        dep = {"dependencies": {"oldlib": "1.0.0"}}
        w.add_repo(FakeRepo(202, "TwoLocks", head=Snapshot("8" * 40, {
            "a/package.json": json.dumps(dep).encode(), "a/package-lock.json": npm_lock({"oldlib": ("1.0.0", False)}, ["oldlib"]),
            "b/package.json": json.dumps({"dependencies": {"next": "16"}}).encode(), "b/package-lock.json": npm_lock({"next": ("16.1.6", False)}, ["next"]),
        })))
        w.npm["oldlib"] = {"dist-tags": {"latest": "1.0.0"}, "versions": {"1.0.0": {"deprecated": "use newlib"}}}
        r = W.Runner(w)
        r.run(checks="all")
        n = r.by_key("deps-deprecated:202:npm:oldlib")["number"]
        from .fakes import sha_of
        w.fault(f"/repos/okakanatto/TwoLocks/git/blobs/{sha_of(w.repos[202].head.files['a/package-lock.json'])}", *[resp(502, {})] * 30)
        r.run(checks="all")
        self.assertEqual(w.issue(n)["state"], "open")

    def test_02e_workflow_read_failure_keeps_eol_issue(self):
        w = W.build_world()
        w.eol["nodejs"] = [{"name": "16", "isEol": True, "eolFrom": "2023-09-11"}, {"name": "24", "isEol": False}]
        w.add_repo(FakeRepo(203, "NodeOnly", head=Snapshot("9" * 40, {".github/workflows/a.yml": NODE16_WF, ".nvmrc": b"24\n", "index.js": b"1"})))
        r = W.Runner(w)
        r.run(checks="all")
        n = r.by_key("eol:203:nodejs:16")["number"]
        from .fakes import sha_of
        w.fault(f"/repos/okakanatto/NodeOnly/git/blobs/{sha_of(NODE16_WF)}", *[resp(502, {})] * 30)
        r.run(checks="all")
        self.assertEqual(w.issue(n)["state"], "open")

    def test_03_sync_failure_keeps_monthly_due(self):
        w = W.build_world()
        r = W.Runner(w)
        r.run(checks="all")
        r.now = r.now.replace(month=11, day=1)
        # 同期の最初の書き込みだけ失敗させる（ダッシュボードの保存は成功する＝状態は保存される）
        w.fault("/repos/okakanatto/okakanatto-maintenance/issues/", resp(422, {"message": "x"}))
        rep = r.run(checks="auto")
        self.assertEqual(rep["run"]["status"], "ERROR")
        w.faults.clear()
        rep2 = r.run(checks="auto")
        self.assertIn("monthly", rep2["run"]["periods"])
        self.assertIsNotNone(r.by_key("manual:2026-11"))

    def test_04_human_closed_bundle_gets_one_notice_for_new_advisory(self):
        w = W.build_world()
        r = W.Runner(w)
        r.run()
        n = r.by_key("vuln:101:npm:prod")["number"]
        w.issue(n)["state"] = "closed"
        w.osv_db[("npm", "next", "16.1.6")] = ["GHSA-next-0001", "GHSA-next-0002"]
        w.vulns["GHSA-next-0002"] = W.osv_vuln("GHSA-next-0002", "npm", "next", "16.1.9", "CRITICAL")
        r.run()
        self.assertEqual(w.issue(n)["state"], "closed")
        notes = [c for c in w.comments.get(n, []) if "新しい検出" in c["body"]]
        self.assertEqual(len(notes), 1)
        self.assertIn("GHSA-next-0002", notes[0]["body"])
        r.run()
        self.assertEqual(len([c for c in w.comments.get(n, []) if "新しい検出" in c["body"]]), 1)

    def test_05_release_only_dev_dependency_stays_dev(self):
        w = W.build_world()
        r = W.Runner(w)
        r.run()
        dev_n = r.by_key("vuln:101:npm:dev")["number"]
        files = W.app_files()
        files["package-lock.json"] = npm_lock({"next": ("16.1.6", False), "leftpad": ("1.0.0", False)}, ["next"])
        w.repos[101].head = Snapshot("a1" * 20, files)  # main から vitest を外した（v1.0.0 には残る）
        rep = r.run()
        self.assertEqual(w.issue(dev_n)["state"], "open")
        prod = next(f for f in rep["findings"] if f["key"] == "vuln:101:npm:prod")
        self.assertNotIn("vitest@4.0.0", prod["material"]["packages"])

    def test_06_suppressing_whole_bundle_is_not_resolution(self):
        w = W.build_world()
        r = W.Runner(w)
        r.run()
        n = r.by_key("vuln:101:npm:prod")["number"]
        r.cfg = W.with_suppressions(r.cfg, [{"key": "vuln:101:GHSA-next-0001", "status": "snoozed", "reason": "来月更新", "until": "2026-10-20"}])
        r.run()
        iss = w.issue(n)
        self.assertEqual(iss["state"], "open")
        self.assertIn("maint:suppressed", labels(iss))
        self.assertNotIn("maint:resolved", labels(iss))
        r.run(advance_hours=24 * 3)
        r.run()
        self.assertNotIn("maint:suppressed", labels(w.issue(n)))
        self.assertEqual(len([c for c in w.comments.get(n, []) if "再評価期限" in c["body"]]), 1)
        self.assertEqual(len([c for c in w.comments.get(n, []) if "再検出" in c["body"]]), 0)

    def test_07_neutralize_more_reference_forms(self):
        s = neutralize("see owner/repo#5, GH-12, http://github.com/a/b/issues/1 and https://www.github.com/a/b/pull/2")
        self.assertNotIn("repo#5", s)
        self.assertNotIn("GH-12", s)
        self.assertIn("`http://github.com/a/b/issues/1`", s)
        self.assertIn("`https://www.github.com/a/b/pull/2`", s)

    def test_08_unrecognized_manifests_are_not_success(self):
        w = W.build_world()
        w.add_repo(FakeRepo(204, "JavaApp", head=Snapshot("b" * 40, {"build.gradle": b"dependencies {}", "src/Main.java": b"class A{}"})))
        rep = W.Runner(w).run()
        j = next(x for x in rep["repos"] if x["name"] == "JavaApp")
        self.assertEqual(j["checks"]["vuln"]["coverage"]["vuln"]["level"], "UNKNOWN")
        row = next(line for line in rep["markdown"].splitlines() if line.startswith("| JavaApp"))
        self.assertNotIn("成功", row)

    def test_09_unlocked_manifest_in_tag_does_not_block_other_ecosystem(self):
        w = W.build_world()
        r = W.Runner(w)
        r.run()
        n = r.by_key("vuln:101:npm:prod")["number"]
        fixed = W.app_files(next_ver="16.1.7")
        fixed["pyproject.toml"] = b"[project]\nname='x'\n"  # ロックファイルの無い依存定義（別エコシステム）
        w.repos[101].head = Snapshot("c1" * 20, fixed)
        w.repos[101].tags["v1.1.0"] = Snapshot("c2" * 20, dict(fixed))  # main とは別コミットのタグ（タグ時点を別に検査させる）
        w.repos[101].releases.insert(0, {"tag_name": "v1.1.0", "draft": False, "prerelease": False, "published_at": "2026-10-20T00:00:00Z", "assets": []})
        r.run()
        self.assertEqual(w.issue(n)["state"], "closed")

    def test_10_transient_release_failure_does_not_flip_flop(self):
        w = W.build_world()
        r = W.Runner(w)
        r.run()
        n = r.by_key("vuln:101:npm:prod")["number"]
        w.fault("/repos/okakanatto/AppA/releases", *[resp(500, {})] * 10)
        r.run()
        w.faults.clear()
        r.run()
        self.assertEqual(w.comments.get(n, []), [])

    def test_11_post_is_not_retried_on_5xx(self):
        t = Seq(resp(502, {}), resp(201, {"number": 1}))
        with self.assertRaises(HttpError):
            HttpClient(transport=t, sleep=lambda s: None).request("POST", "https://api.github.com/repos/x/y/issues", json_body={})
        self.assertEqual(t.calls, 1)
        t2 = Seq(resp(429, {}, {"Retry-After": "1"}), resp(201, {"number": 1}))
        data, _ = HttpClient(transport=t2, sleep=lambda s: None).request("POST", "https://api.github.com/repos/x/y/issues", json_body={})
        self.assertEqual(data["number"], 1)

    def test_12_corrupted_state_is_reported(self):
        w = W.build_world()
        r = W.Runner(w)
        r.run()
        dash = next(i for i in w.issues if "maint:dashboard" in labels(i))
        dash["body"] = dash["body"].replace('"version":1', '"version":1,,')
        rep = r.run()
        self.assertTrue(any("状態ブロックを読めない" in n for n in rep["run"]["notes"]))
        self.assertEqual(rep["run"]["status"], "PARTIAL")

    def test_14_manual_issue_number_in_report(self):
        w = W.build_world()
        rep = W.Runner(w).run(checks="all")
        self.assertIsNotNone(rep["issues"]["numbers"].get("manual:2026-10"))
        self.assertNotIn("（未作成）", rep["markdown"])

    def test_15_release_without_sbom_is_unknown(self):
        rep = W.Runner(W.build_world()).run()
        app = next(x for x in rep["repos"] if x["name"] == "AppA")
        self.assertEqual(app["checks"]["release"]["coverage"]["release"]["level"], "UNKNOWN")

    def test_18_tag_only_or_filtered_workflow_without_runs_is_not_flagged(self):
        """実運用で見つかった誤検知（csv-diff-review の release.yml、2026-10-18）。"""
        from maint.checks.ci import parse_workflow

        self.assertTrue(parse_workflow('on:\n  push:\n    tags: ["v*"]\njobs:\n')["push_tags_only"])
        self.assertFalse(parse_workflow('on:\n  push:\n    branches: [main]\n    tags: ["v*"]\n')["push_tags_only"])
        self.assertFalse(parse_workflow("on:\n  push:\n    paths: [a]\n")["push_tags_only"])
        self.assertFalse(parse_workflow("on: push\n")["push_tags_only"])
        w = W.build_world()
        release = b'on:\n  push:\n    tags: ["v*"]\njobs:\n  r:\n    runs-on: windows-latest\n    steps:\n      - run: echo\n'
        bench = b"on:\n  push:\n    branches: [main]\n    paths: [bench.ps1]\njobs:\n  b:\n    runs-on: windows-latest\n    steps:\n      - run: echo\n"
        checks = b"on:\n  push:\njobs:\n  c:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n"
        app = w.add_repo(FakeRepo(205, "CsvApp", head=Snapshot("d" * 40, {
            ".github/workflows/release.yml": release, ".github/workflows/bench.yml": bench,
            ".github/workflows/checks.yml": checks, "src/main.rs": b"fn main(){}"})))
        app.workflows = [{"id": 1, "name": "release", "path": ".github/workflows/release.yml", "state": "active"},
                         {"id": 2, "name": "bench", "path": ".github/workflows/bench.yml", "state": "active"},
                         {"id": 3, "name": "checks", "path": ".github/workflows/checks.yml", "state": "active"}]
        app.runs = {3: [{"status": "completed", "conclusion": "success", "head_branch": "main",
                         "created_at": "2026-10-17T00:00:00Z", "html_url": "x"}]}
        r = W.Runner(w)
        r.run()
        self.assertIsNone(r.by_key("ci-never-run:205:1"))  # タグ push 専用
        self.assertIsNone(r.by_key("ci-never-run:205:2"))  # 他は動いている（paths 条件が未成立なだけ）
        self.assertIsNotNone(r.by_key("ci-never-run:102:9001"))  # Actions が一度も動いていないリポジトリは引き続き指摘

    def test_19_distribution_snapshot_shows_fix_location_without_notifying(self):
        """配布用スナップショット（開発用の非公開リポジトリから書き出す公開リポジトリ）の修正先表示。2026-10-24"""
        w = W.build_world()
        r = W.Runner(w)
        r.run()
        n = r.by_key("vuln:101:npm:prod")["number"]
        self.assertNotIn("修正先", w.issue(n)["body"])
        cfg = copy.deepcopy(r.cfg)
        cfg.raw["repo_policies"] = {"AppA": {"distribution_snapshot": True}}
        r.cfg = cfg
        w.log.clear()
        r.run()
        body = w.issue(n)["body"]
        self.assertIn("**修正先**", body)
        self.assertIn("開発用の非公開リポジトリ", body)
        self.assertEqual(w.comments.get(n, []), [])  # 本文だけ直し、コメント（通知）はしない
        w.log.clear()
        r.run()
        self.assertEqual([x for x in w.writes() if f"/issues/{n}" in x[1]], [])  # 2 回目は何もしない

    def test_20_excluded_after_disappearing_is_retired_not_missing(self):
        """一覧から消えたリポジトリを設定で除外したら、監視不能として毎回出さない。2026-10-24"""
        w = W.build_world()
        r = W.Runner(w)
        r.run()
        w.hidden.add(102)
        r.run()
        n = r.by_key("lifecycle:102:missing")["number"]
        w.issue(n)["state"] = "closed"  # 人が閉じた
        cfg = copy.deepcopy(r.cfg)
        cfg.raw["exclude"] = {"names": [], "ids": [102]}
        r.cfg = cfg
        rep = r.run()
        self.assertEqual(rep["discovery"]["missing"], [])
        self.assertEqual([x["id"] for x in rep["discovery"]["retired"]], [102])
        self.assertEqual(rep["state"]["repos"]["102"]["status"], "excluded")
        self.assertFalse(any(f["key"] == "lifecycle:102:missing" for f in rep["findings"]))
        self.assertNotIn("監視不能", rep["markdown"].split("## 監視できていない範囲")[1].split("##")[0])

    def test_state_keeps_initial_inventory(self):
        w = W.build_world()
        r = W.Runner(w)
        rep = r.run()
        e = rep["state"]["repos"]["101"]
        self.assertIn("initial_inventory", e)
        self.assertIn("npm-lock:package-lock.json", e["initial_inventory"]["manifests"])


if __name__ == "__main__":
    unittest.main()
