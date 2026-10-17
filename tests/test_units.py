"""部品単位のテスト（HTTP 再試行・解析器・CVSS・版比較・状態の保存・無害化）。"""

import datetime as dt
import json
import unittest

from maint import state
from maint.checks.ci import parse_workflow
from maint.checks.manual import checked_items
from maint.github import IssueWriter, WriteScopeError
from maint.http import HttpClient, HttpError, TransportTimeout
from maint.issues import link, neutralize
from maint.lockfiles import parse_cargo_lock, parse_go_mod, parse_npm_lock, parse_requirements, vcpkg_list_from_json
from maint.osv import cvss3_base_score, cvss_rating, parse_vuln
from maint.versions import classify, compare, major_lag

from .fakes import resp


class Seq:
    """決まった順に応答を返す transport。"""

    def __init__(self, *items):
        self.items = list(items)
        self.calls = 0

    def __call__(self, req):
        self.calls += 1
        item = self.items.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class HttpTests(unittest.TestCase):
    def client(self, t, **kw):
        self.slept = []
        return HttpClient(transport=t, sleep=self.slept.append, max_retries=3, backoff=1, clock=lambda: 1000.0, **kw)

    def test_429_retry_after_then_success(self):
        t = Seq(resp(429, {"message": "slow down"}, {"Retry-After": "2"}), resp(200, {"ok": 1}))
        data, _ = self.client(t).request("GET", "https://api.github.com/x")
        self.assertEqual(data, {"ok": 1})
        self.assertEqual(self.slept, [2.0])

    def test_403_rate_limit_far_reset_fails_fast(self):
        t = Seq(resp(403, {"message": "API rate limit exceeded"}, {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "999999"}))
        with self.assertRaises(HttpError) as cm:
            self.client(t).request("GET", "https://api.github.com/x")
        self.assertEqual(cm.exception.kind, "rate_limited")
        self.assertEqual(self.slept, [])  # 解除まで待たない

    def test_403_permission_is_not_retried(self):
        t = Seq(resp(403, {"message": "Resource not accessible by integration"}))
        with self.assertRaises(HttpError) as cm:
            self.client(t).request("GET", "https://api.github.com/x")
        self.assertEqual(cm.exception.kind, "forbidden")
        self.assertEqual(t.calls, 1)

    def test_5xx_retries_then_server_error(self):
        t = Seq(*[resp(502, {"message": "bad gateway"})] * 4)
        with self.assertRaises(HttpError) as cm:
            self.client(t).request("GET", "https://api.github.com/x")
        self.assertEqual(cm.exception.kind, "server")
        self.assertEqual(t.calls, 4)

    def test_timeout_then_success(self):
        t = Seq(TransportTimeout("t"), resp(200, [1]))
        data, _ = self.client(t).request("GET", "https://api.github.com/x")
        self.assertEqual(data, [1])

    def test_bad_json(self):
        t = Seq(resp(200, b"{not json"), resp(200, b"{still not"))
        with self.assertRaises(HttpError) as cm:
            self.client(t).request("GET", "https://api.github.com/x")
        self.assertEqual(cm.exception.kind, "bad_json")

    def test_writer_refuses_other_repo(self):
        w = IssueWriter(HttpClient(transport=Seq()), "t", "okakanatto/okakanatto-maintenance")
        with self.assertRaises(WriteScopeError):
            w._w("POST", "repos/okakanatto/Yarukoto/issues", {"title": "x"})
        with self.assertRaises(WriteScopeError):
            w._w("POST", "repos/okakanatto/okakanatto-maintenance-evil/issues", {"title": "x"})


class ParserTests(unittest.TestCase):
    def test_npm_lock_v3_direct_and_dev(self):
        raw = json.dumps({"lockfileVersion": 3, "packages": {
            "": {"dependencies": {"a": "1"}, "devDependencies": {"b": "1"}},
            "node_modules/a": {"version": "1.0.0"},
            "node_modules/b": {"version": "2.0.0", "dev": True},
            "node_modules/a/node_modules/c": {"version": "3.0.0"},
            "node_modules/@s/d": {"version": "4.0.0"},
            "packages/ws": {"version": "0.0.1"},
            "node_modules/ws": {"link": True, "resolved": "packages/ws"},
            "node_modules/g": {"version": "1.0.0", "resolved": "git+https://github.com/x/g.git"},
        }}).encode()
        pkgs, notes = parse_npm_lock(raw, "package-lock.json")
        got = {(p.name, p.version, p.direct, p.dev) for p in pkgs}
        self.assertIn(("a", "1.0.0", True, False), got)
        self.assertIn(("b", "2.0.0", True, True), got)
        self.assertIn(("c", "3.0.0", False, False), got)
        self.assertIn(("@s/d", "4.0.0", False, False), got)
        self.assertNotIn("ws", {p.name for p in pkgs})
        self.assertNotIn("g", {p.name for p in pkgs})
        self.assertTrue(any("g" in n for n in notes))

    def test_npm_lock_v1(self):
        raw = json.dumps({"lockfileVersion": 1, "dependencies": {"a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0"}}}}}).encode()
        pkgs, notes = parse_npm_lock(raw, "package-lock.json")
        self.assertEqual({(p.name, p.version) for p in pkgs}, {("a", "1.0.0"), ("b", "2.0.0")})

    def test_cargo_lock_skips_workspace_and_git(self):
        raw = b'''version = 3
[[package]]
name = "app"
version = "0.1.0"
[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
[[package]]
name = "mine"
version = "0.2.0"
source = "git+https://github.com/x/mine#abc"
'''
        pkgs, notes = parse_cargo_lock(raw, "Cargo.lock")
        self.assertEqual([(p.ecosystem, p.name, p.version) for p in pkgs], [("crates.io", "serde", "1.0.0")])
        self.assertTrue(notes)

    def test_requirements_pinned_and_dev_by_name(self):
        raw = b"black==24.10.0 \\\n  --hash=sha256:abc\nrequests>=2\n# c\nPyYAML[x]==6.0 ; python_version>'3'\n-r other.txt\n"
        pkgs, notes = parse_requirements(raw, "scripts/requirements-format.txt")
        self.assertEqual({(p.name, p.version, p.dev) for p in pkgs}, {("black", "24.10.0", True), ("pyyaml", "6.0", True)})
        self.assertTrue(any("固定されていない" in n for n in notes))
        pkgs2, _ = parse_requirements(b"flask==3.0.0\n", "requirements.txt")
        self.assertFalse(pkgs2[0].dev)

    def test_go_mod(self):
        raw = b"module x\nrequire (\n\tgolang.org/x/net v0.1.0 // indirect\n\tgithub.com/a/b v1.2.3\n)\nrequire github.com/c/d v0.0.1\n"
        pkgs, _ = parse_go_mod(raw, "go.mod")
        self.assertEqual({(p.name, p.version, p.direct) for p in pkgs},
                         {("golang.org/x/net", "v0.1.0", False), ("github.com/a/b", "v1.2.3", True), ("github.com/c/d", "v0.0.1", True)})

    def test_vcpkg_list(self):
        raw = json.dumps({"vcpkg_packages": [{"Package": "zlib", "Version": "1.3"}, {"Package": "zlib", "Feature": "x"}]}).encode()
        self.assertEqual(vcpkg_list_from_json(raw), [{"name": "zlib", "version": "1.3"}])
        self.assertIsNone(vcpkg_list_from_json(b'{"a": 1}'))

    def test_workflow_triggers(self):
        self.assertEqual(parse_workflow("on:\n  push:\n  pull_request:\njobs:\n")["triggers"], ["pull_request", "push"])
        self.assertEqual(parse_workflow("on: [push, workflow_dispatch]\n")["triggers"], ["push", "workflow_dispatch"])
        self.assertEqual(parse_workflow("on: workflow_dispatch\n")["triggers"], ["workflow_dispatch"])
        wf = parse_workflow("jobs:\n  a:\n    runs-on: [windows-2019, x]\n    steps:\n      - uses: actions/checkout@v4 # v4\n  b:\n    runs-on: ${{ matrix.os }}\n")
        self.assertEqual(wf["runners"], ["windows-2019", "x"])
        self.assertTrue(wf["dynamic_runner"])
        self.assertEqual(wf["uses"], [("actions/checkout@v4", "v4")])


class ScoreAndVersionTests(unittest.TestCase):
    def test_cvss3_known_vectors(self):
        self.assertEqual(cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertEqual(cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), 6.1)
        self.assertEqual(cvss3_base_score("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"), 5.5)
        self.assertEqual(cvss3_base_score("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), 10.0)
        self.assertIsNone(cvss3_base_score("CVSS:4.0/AV:N"))
        self.assertEqual(cvss_rating(9.8), "critical")
        self.assertEqual(cvss_rating(6.1), "medium")

    def test_parse_vuln_severity_sources(self):
        self.assertEqual(parse_vuln({"id": "G", "database_specific": {"severity": "MODERATE"}}).severity, "medium")
        v = parse_vuln({"id": "R", "affected": [{"database_specific": {"informational": "unmaintained"}}]})
        self.assertEqual((v.severity, v.informational), ("info", "unmaintained"))
        u = parse_vuln({"id": "U", "severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N"}]})
        self.assertEqual((u.severity, u.severity_source), ("medium", "unknown"))

    def test_versions(self):
        self.assertEqual(classify("1.2.3", "1.2.4"), "patch")
        self.assertEqual(classify("1.2.3", "1.3.0"), "minor")
        self.assertEqual(classify("1.2.3", "3.0.0"), "major")
        self.assertEqual(classify("0.2.0", "0.3.0"), "major")
        self.assertEqual(classify("2.0.0", "1.0.0"), "newer")
        self.assertEqual(compare("2.0.0-preview.6", "2.0.0"), -1)
        self.assertEqual(major_lag("v4", "v7.0.1"), 3)


class StateAndRenderTests(unittest.TestCase):
    def test_state_roundtrip_and_corruption(self):
        st = state.empty()
        st["repos"]["1"] = {"name": "a-->b"}
        body = "表\n\n" + state.encode(st)
        self.assertNotIn("a-->b", body)
        self.assertEqual(state.decode(body)["repos"]["1"]["name"], "a-->b")
        self.assertIsNone(state.decode(body.replace('"version":1', '"version":1,,')))
        self.assertIsNone(state.decode("no state"))

    def test_neutralize_mentions_and_refs(self):
        s = neutralize("ping @someone see #12 and https://github.com/x/y/issues/3")
        self.assertNotIn("@someone", s)
        self.assertNotIn(" #12", s)
        self.assertIn("`https://github.com/x/y/issues/3`", s)
        self.assertEqual(link("https://osv.dev/vulnerability/X"), "https://osv.dev/vulnerability/X")
        self.assertTrue(link("https://evil.example/x").startswith("`"))

    def test_checked_items(self):
        body = "- [x] A <!-- item:a -->\n- [ ] B <!-- item:b -->\n  - [X] C <!-- item:c -->"
        self.assertEqual(checked_items(body), {"a", "c"})


if __name__ == "__main__":
    unittest.main()
