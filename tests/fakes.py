"""テスト用の偽 GitHub / OSV / レジストリ / endoflife.date（HTTP transport を差し替える）。"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import urllib.parse
from dataclasses import dataclass, field

from maint.http import Request, Response, TransportTimeout

OWNER = "okakanatto"
CENTRAL = f"{OWNER}/okakanatto-maintenance"


def sha_of(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


@dataclass
class Snapshot:
    """あるコミット時点のファイル一式。"""

    sha: str
    files: dict[str, bytes] = field(default_factory=dict)
    gitlinks: dict[str, str] = field(default_factory=dict)


@dataclass
class FakeRepo:
    id: int
    name: str
    owner: str = OWNER
    private: bool = False
    fork: bool = False
    archived: bool = False
    empty: bool = False
    default_branch: str = "main"
    head: Snapshot = field(default_factory=lambda: Snapshot("a" * 40))
    tags: dict[str, Snapshot] = field(default_factory=dict)
    releases: list[dict] = field(default_factory=list)
    workflows: list[dict] = field(default_factory=list)
    runs: dict[int, list[dict]] = field(default_factory=dict)
    advisories: list[dict] = field(default_factory=list)

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.name}"

    def api(self) -> dict:
        return {
            "id": self.id, "name": self.name, "full_name": self.full_name, "private": self.private, "fork": self.fork,
            "archived": self.archived, "size": 0 if self.empty else 10, "default_branch": self.default_branch,
            "html_url": f"https://github.com/{self.full_name}", "owner": {"login": self.owner}, "pushed_at": "2026-10-01T00:00:00Z",
        }


def resp(status: int, body=None, headers: dict | None = None) -> Response:
    raw = body if isinstance(body, bytes) else json.dumps(body if body is not None else {}).encode()
    return Response(status, {k.lower(): v for k, v in (headers or {}).items()}, raw)


class FakeWorld:
    def __init__(self):
        self.repos: dict[int, FakeRepo] = {}
        self.hidden: set[int] = set()  # 一覧に出さない（非公開化・削除の再現）
        self.repo_by_id_status: dict[int, int] = {}  # /repositories/{id} の応答を上書き（404 等）
        self.issues: list[dict] = []
        self.comments: dict[int, list[dict]] = {}
        self.labels: set[str] = set()
        self.central_exists = True
        self.osv_db: dict[tuple[str, str, str], list[str]] = {}
        self.osv_commit: dict[str, list[str]] = {}
        self.vulns: dict[str, dict] = {}
        self.npm: dict[str, dict] = {}
        self.crates: dict[str, list[dict]] = {}
        self.pypi: dict[str, dict] = {}
        self.eol: dict[str, list[dict]] = {}
        self.faults: list[tuple[str, list]] = []  # (URL 部分文字列, [Response | Exception ...]) を先頭から消費
        self.log: list[tuple[str, str]] = []
        self.per_page_override: int | None = None

    # --- 便利関数 ---
    def add_repo(self, repo: FakeRepo) -> FakeRepo:
        self.repos[repo.id] = repo
        return repo

    def fault(self, substr: str, *items) -> None:
        self.faults.append((substr, list(items)))

    def writes(self) -> list[tuple[str, str]]:
        return [x for x in self.log if x[0] in ("POST", "PATCH", "PUT", "DELETE") and "api.osv.dev" not in x[1]]

    def issue(self, number: int) -> dict:
        return next(i for i in self.issues if i["number"] == number)

    # --- transport ---
    def __call__(self, req: Request) -> Response:
        self.log.append((req.method, req.url))
        for substr, items in self.faults:
            if substr in req.url and items:
                item = items.pop(0)
                if isinstance(item, Exception):
                    raise item
                return item
        u = urllib.parse.urlparse(req.url)
        q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
        body = json.loads(req.body.decode()) if req.body else None
        if u.netloc == "api.github.com":
            return self._github(req.method, urllib.parse.unquote(u.path), q, body, req)
        if u.netloc == "api.osv.dev":
            return self._osv(u.path, body)
        if u.netloc == "registry.npmjs.org":
            name = urllib.parse.unquote(u.path.lstrip("/"))
            return resp(200, self.npm[name]) if name in self.npm else resp(404, {"error": "not found"})
        if u.netloc == "index.crates.io":
            name = u.path.rsplit("/", 1)[-1]
            if name not in self.crates:
                return resp(404, b"")
            return resp(200, "\n".join(json.dumps(r) for r in self.crates[name]).encode())
        if u.netloc == "pypi.org":
            name = u.path.split("/")[2]
            return resp(200, self.pypi[name]) if name in self.pypi else resp(404, {})
        if u.netloc == "endoflife.date":
            prod = u.path.rstrip("/").rsplit("/", 1)[-1]
            return resp(200, {"result": {"releases": self.eol[prod]}}) if prod in self.eol else resp(404, {})
        return resp(404, {"message": "unknown host"})

    def _osv(self, path: str, body: dict) -> Response:
        if path == "/v1/querybatch":
            res = []
            for qq in body["queries"]:
                p = qq["package"]
                ids = self.osv_db.get((p["ecosystem"], p["name"], qq["version"]), [])
                res.append({"vulns": [{"id": i, "modified": "2026-01-01T00:00:00Z"} for i in ids]} if ids else {})
            return resp(200, {"results": res})
        if path == "/v1/query":
            ids = self.osv_commit.get(body.get("commit", ""), [])
            return resp(200, {"vulns": [self.vulns[i] for i in ids]} if ids else {})
        if path.startswith("/v1/vulns/"):
            vid = path.rsplit("/", 1)[-1]
            return resp(200, self.vulns[vid]) if vid in self.vulns else resp(404, {})
        return resp(404, {})

    def _find(self, full: str) -> FakeRepo | None:
        for r in self.repos.values():
            if r.full_name.lower() == full.lower():
                return r
        return None

    def _snap(self, r: FakeRepo, ref: str) -> Snapshot | None:
        if ref in (r.default_branch, r.head.sha):
            return r.head
        if ref in r.tags:
            return r.tags[ref]
        for s in r.tags.values():
            if s.sha == ref:
                return s
        return None

    def _github(self, method: str, path: str, q: dict, body, req: Request) -> Response:
        parts = path.strip("/").split("/")
        if parts[:1] == ["users"] and parts[2:] == ["repos"]:
            listed = [r.api() for r in sorted(self.repos.values(), key=lambda r: r.name.lower())
                      if r.owner == parts[1] and not r.private and r.id not in self.hidden]
            per = self.per_page_override or int(q.get("per_page", 30))
            page = int(q.get("page", 1))
            chunk = listed[(page - 1) * per : page * per]
            headers = {}
            if page * per < len(listed):
                nq = dict(q, page=str(page + 1))
                headers["Link"] = f'<https://api.github.com{path}?{urllib.parse.urlencode(nq)}>; rel="next"'
            return resp(200, chunk, headers)
        if parts[0] == "repositories":
            rid = int(parts[1])
            if rid in self.repo_by_id_status:
                return resp(self.repo_by_id_status[rid], {"message": "x"})
            r = self.repos.get(rid)
            return resp(200, r.api()) if r and rid not in self.hidden else resp(404, {"message": "Not Found"})
        if parts[0] != "repos":
            return resp(404, {"message": "Not Found"})
        full = "/".join(parts[1:3])
        rest = parts[3:]
        if full.lower() == CENTRAL.lower():
            return self._central(method, rest, q, body)
        r = self._find(full)
        if r is None or r.id in self.hidden:
            return resp(404, {"message": "Not Found"})
        if rest[:2] == ["git", "trees"]:
            if r.empty:
                return resp(409, {"message": "Git Repository is empty."})
            snap = self._snap(r, rest[2])
            if snap is None:
                return resp(404, {"message": "Not Found"})
            tree = [{"path": p, "type": "blob", "sha": sha_of(c), "size": len(c)} for p, c in snap.files.items()]
            tree += [{"path": p, "type": "commit", "sha": s} for p, s in snap.gitlinks.items()]
            return resp(200, {"sha": snap.sha, "tree": tree, "truncated": False})
        if rest[:2] == ["git", "blobs"]:
            for snap in [r.head, *r.tags.values()]:
                for c in snap.files.values():
                    if sha_of(c) == rest[2]:
                        return resp(200, {"encoding": "base64", "content": base64.b64encode(c).decode()})
            return resp(404, {"message": "Not Found"})
        if rest[:1] == ["contents"]:
            snap = self._snap(r, q.get("ref", r.default_branch))
            p = "/".join(rest[1:])
            if snap and p in snap.files:
                return resp(200, {"type": "file", "encoding": "base64", "content": base64.b64encode(snap.files[p]).decode(), "sha": sha_of(snap.files[p])})
            return resp(404, {"message": "Not Found"})
        if rest[:1] == ["commits"]:
            snap = self._snap(r, rest[1])
            if snap is None:
                return resp(404, {"message": "No commit"})
            return resp(200, {"sha": snap.sha, "commit": {"committer": {"date": "2026-01-01T00:00:00Z"}}})
        if rest[:1] == ["compare"]:
            base, head = rest[1].split("...")
            same = (self._snap(r, base) or Snapshot("x")).sha == (self._snap(r, head) or Snapshot("y")).sha
            return resp(200, {"ahead_by": 0 if same else 3, "behind_by": 0})
        if rest == ["releases"]:
            return resp(200, r.releases)
        if rest == ["releases", "latest"]:
            pub = [x for x in r.releases if not x.get("draft") and not x.get("prerelease")]
            return resp(200, pub[0]) if pub else resp(404, {"message": "Not Found"})
        if rest == ["tags"]:
            return resp(200, [{"name": t, "commit": {"sha": s.sha}} for t, s in r.tags.items()])
        if rest == ["languages"]:
            return resp(200, {"Python": 100})
        if rest == ["actions", "workflows"]:
            return resp(200, {"total_count": len(r.workflows), "workflows": r.workflows})
        if rest[:2] == ["actions", "workflows"] and rest[3:] == ["runs"]:
            runs = r.runs.get(int(rest[2]), [])
            if "branch" in q:
                runs = [x for x in runs if x.get("head_branch") == q["branch"]]
            return resp(200, {"total_count": len(runs), "workflow_runs": runs[: int(q.get("per_page", 30))]})
        if rest == ["security-advisories"]:
            return resp(200, r.advisories)
        if rest[:2] == ["dependabot", "alerts"]:
            return resp(403, {"message": "Dependabot alerts are disabled for this repository."})
        return resp(404, {"message": "Not Found"})

    def _central(self, method: str, rest: list[str], q: dict, body) -> Response:
        if not self.central_exists:
            return resp(404, {"message": "Not Found"})
        now = "2026-10-17T00:00:00Z"
        if rest == ["labels"]:
            if method == "POST":
                self.labels.add(body["name"])
                return resp(201, {"name": body["name"]})
            return resp(200, [{"name": n} for n in sorted(self.labels)])
        if rest == ["issues"]:
            if method == "POST":
                n = len(self.issues) + 1
                iss = {"number": n, "title": body["title"], "body": body["body"], "state": "open", "state_reason": None,
                       "labels": [{"name": x} for x in body.get("labels", [])], "created_at": now, "updated_at": now, "closed_at": None}
                self.issues.append(iss)
                self.labels |= set(body.get("labels", []))
                return resp(201, iss)
            label = q.get("labels")
            items = [i for i in self.issues if not label or label in {lb["name"] for lb in i["labels"]}]
            per = int(q.get("per_page", 30))
            page = int(q.get("page", 1))
            chunk = items[(page - 1) * per : page * per]
            headers = {}
            if page * per < len(items):
                headers["Link"] = f'<https://api.github.com/repos/{CENTRAL}/issues?{urllib.parse.urlencode(dict(q, page=str(page + 1)))}>; rel="next"'
            return resp(200, json.loads(json.dumps(chunk)), headers)
        if len(rest) == 2 and rest[0] == "issues" and method == "PATCH":
            iss = self.issue(int(rest[1]))
            for k, v in body.items():
                if k == "labels":
                    iss["labels"] = [{"name": x} for x in v]
                else:
                    iss[k] = v
            if body.get("state") == "closed":
                iss["closed_at"] = now
            if body.get("state") == "open":
                iss["closed_at"] = None
            return resp(200, iss)
        if len(rest) == 3 and rest[0] == "issues" and rest[2] == "comments":
            n = int(rest[1])
            if method == "POST":
                self.comments.setdefault(n, []).append(body)
                return resp(201, {"id": 1})
            return resp(200, self.comments.get(n, []))
        return resp(404, {"message": "Not Found"})


# --- データ作成の補助 ------------------------------------------------------


def npm_lock(pkgs: dict[str, tuple[str, bool]], direct: list[str]) -> bytes:
    """pkgs: name -> (version, dev)"""
    packages = {"": {"name": "app", "dependencies": {d: "*" for d in direct}}}
    for name, (ver, dev) in pkgs.items():
        packages[f"node_modules/{name}"] = {"version": ver, "resolved": f"https://registry.npmjs.org/{name}/-/{name}-{ver}.tgz", **({"dev": True} if dev else {})}
    return json.dumps({"lockfileVersion": 3, "packages": packages}).encode()


def cargo_lock(pkgs: dict[str, str]) -> bytes:
    lines = ["version = 3", "", '[[package]]', 'name = "app"', 'version = "0.1.0"', ""]
    for n, v in pkgs.items():
        lines += ["[[package]]", f'name = "{n}"', f'version = "{v}"', 'source = "registry+https://github.com/rust-lang/crates.io-index"', ""]
    return "\n".join(lines).encode()


def osv_vuln(vid: str, eco: str, name: str, fixed: str, severity: str = "HIGH", aliases=None, informational=None) -> dict:
    d = {
        "id": vid, "summary": f"{name} の脆弱性 @attacker #12", "aliases": aliases or [],
        "affected": [{"package": {"ecosystem": eco, "name": name}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": fixed}]}]}],
        "references": [{"type": "ADVISORY", "url": f"https://github.com/advisories/{vid}"}, {"type": "WEB", "url": "https://github.com/foo/bar/issues/5"}],
    }
    if severity:
        d["database_specific"] = {"severity": severity}
    if informational:
        d["affected"][0]["database_specific"] = {"informational": informational}
    return d


def now() -> dt.datetime:
    return dt.datetime(2026, 10, 17, 21, 30, tzinfo=dt.timezone.utc)
