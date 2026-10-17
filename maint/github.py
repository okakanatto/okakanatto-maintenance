"""GitHub REST API。

読み取り（GitHubReader）と書き込み（IssueWriter）を別クラスにしている。
- Reader: 監視対象の公開リポジトリを読むだけ。書き込みメソッドを持たない
- Writer: 中央リポジトリの Issue とラベルだけを書く。他リポジトリへの書き込みは例外で止める
"""

from __future__ import annotations

import base64
import re
import urllib.parse

from .http import HttpClient, HttpError

API = "https://api.github.com"
_LINK_NEXT = re.compile(r'<([^>]+)>;\s*rel="next"')


class GitHubBase:
    def __init__(self, http: HttpClient, token: str | None, api: str = API, max_pages: int = 50):
        self.http = http
        self._token = token
        self.api = api.rstrip("/")
        self.max_pages = max_pages

    def _headers(self, accept: str = "application/vnd.github+json") -> dict[str, str]:
        h = {"Accept": accept, "X-GitHub-Api-Version": "2022-11-28"}
        if self._token:
            h["Authorization"] = f"Bearer {self._token}"
        return h

    def _url(self, path: str, params: dict | None = None) -> str:
        url = path if path.startswith("http") else f"{self.api}/{path.lstrip('/')}"
        if params:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
        return url

    def get(self, path: str, params: dict | None = None, accept: str | None = None):
        data, _ = self.http.request("GET", self._url(path, params), self._headers(accept or "application/vnd.github+json"))
        return data

    def paginate(self, path: str, params: dict | None = None, item_key: str | None = None) -> list:
        """Link ヘッダの rel=next をたどる。途中で失敗したら HttpError（部分結果は返さない）。"""
        params = dict(params or {})
        params.setdefault("per_page", 100)
        url = self._url(path, params)
        items: list = []
        for _ in range(self.max_pages):
            data, resp = self.http.request("GET", url, self._headers())
            page = data.get(item_key, []) if item_key and isinstance(data, dict) else data
            if not isinstance(page, list):
                raise HttpError("bad_json", url, resp.status, "list expected")
            items.extend(page)
            m = _LINK_NEXT.search(resp.headers.get("link", ""))
            if not m:
                return items
            url = m.group(1)
        raise HttpError("client", url, None, f"pagination exceeded {self.max_pages} pages")


class GitHubReader(GitHubBase):
    """監視対象を読むための API。書き込みはしない。"""

    def owner_repos(self, owner: str) -> list[dict]:
        return self.paginate(f"users/{owner}/repos", {"type": "owner", "sort": "full_name"})

    def repo_by_id(self, repo_id: int) -> dict:
        return self.get(f"repositories/{repo_id}")

    def tree(self, full_name: str, ref: str) -> dict:
        """409（空リポジトリ）は HttpError(kind=conflict) のまま呼び出し側で判定する。"""
        return self.get(f"repos/{full_name}/git/trees/{urllib.parse.quote(ref, safe='')}", {"recursive": "1"})

    def blob(self, full_name: str, sha: str) -> bytes:
        # 同じ blob を検査ごとに取り直さない（SHA が同じなら内容も同じ）
        cache = self.__dict__.setdefault("_blob_cache", {})
        if sha in cache:
            return cache[sha]
        d = self.get(f"repos/{full_name}/git/blobs/{sha}")
        if d.get("encoding") != "base64":
            raise HttpError("bad_json", f"blob {sha}", None, "unexpected encoding")
        raw = base64.b64decode(d.get("content", ""))
        if len(raw) < 5 * 1024 * 1024:
            cache[sha] = raw
        return raw

    def file(self, full_name: str, path: str, ref: str) -> bytes | None:
        """存在しなければ None。"""
        try:
            d = self.get(f"repos/{full_name}/contents/{urllib.parse.quote(path)}", {"ref": ref})
        except HttpError as e:
            if e.kind == "not_found":
                return None
            raise
        if isinstance(d, dict) and d.get("encoding") == "base64":
            return base64.b64decode(d.get("content", ""))
        if isinstance(d, dict) and d.get("sha") and d.get("type") == "file":
            return self.blob(full_name, d["sha"])
        return None

    def commit_sha(self, full_name: str, ref: str) -> str:
        d = self.get(f"repos/{full_name}/commits/{urllib.parse.quote(ref, safe='')}")
        return d["sha"]

    def commit(self, full_name: str, ref: str) -> dict:
        return self.get(f"repos/{full_name}/commits/{urllib.parse.quote(ref, safe='')}")

    def compare(self, full_name: str, base: str, head: str) -> dict:
        return self.get(f"repos/{full_name}/compare/{urllib.parse.quote(base, safe='')}...{urllib.parse.quote(head, safe='')}")

    def releases(self, full_name: str, limit_pages: int = 1) -> list[dict]:
        # 最新 100 件で十分（配布中の最新版を知るのが目的）
        return self.get(f"repos/{full_name}/releases", {"per_page": 100}) or []

    def tags(self, full_name: str) -> list[dict]:
        return self.get(f"repos/{full_name}/tags", {"per_page": 100}) or []

    def languages(self, full_name: str) -> dict:
        return self.get(f"repos/{full_name}/languages") or {}

    def workflows(self, full_name: str) -> list[dict]:
        return self.paginate(f"repos/{full_name}/actions/workflows", item_key="workflows")

    def workflow_runs(self, full_name: str, workflow_id: int, branch: str | None = None, per_page: int = 5) -> dict:
        params: dict = {"per_page": per_page, "exclude_pull_requests": "true"}
        if branch:
            params["branch"] = branch
        return self.get(f"repos/{full_name}/actions/workflows/{workflow_id}/runs", params)

    def latest_release(self, full_name: str) -> dict | None:
        try:
            return self.get(f"repos/{full_name}/releases/latest")
        except HttpError as e:
            if e.kind == "not_found":
                return None
            raise

    def security_advisories(self, full_name: str) -> list[dict]:
        return self.get(f"repos/{full_name}/security-advisories", {"state": "published", "per_page": 100}) or []

    def dependabot_alerts(self, full_name: str) -> list[dict]:
        return self.paginate(f"repos/{full_name}/dependabot/alerts", {"state": "open"})


class WriteScopeError(Exception):
    pass


class IssueWriter(GitHubBase):
    """中央リポジトリの Issue・ラベルだけを書く。"""

    def __init__(self, http: HttpClient, token: str | None, repo_full_name: str, api: str = API, dry_run: bool = False):
        super().__init__(http, token, api)
        self.repo = repo_full_name
        self.dry_run = dry_run  # True なら書き込みを送らず planned に記録するだけ
        self.planned: list[dict] = []

    def _w(self, method: str, path: str, body: dict | None = None):
        if not path.startswith(f"repos/{self.repo}/"):
            raise WriteScopeError(f"write outside central repo refused: {path}")
        if self.dry_run:
            self.planned.append({"method": method, "path": path, "fields": sorted((body or {}).keys())})
            return {"number": None}
        data, _ = self.http.request(method, self._url(path), self._headers(), json_body=body)
        return data

    def list_issues(self, label: str) -> list[dict]:
        items = self.paginate(f"repos/{self.repo}/issues", {"state": "all", "labels": label})
        return [i for i in items if "pull_request" not in i]

    def labels(self) -> list[dict]:
        return self.paginate(f"repos/{self.repo}/labels")

    def create_label(self, name: str, color: str, description: str) -> None:
        self._w("POST", f"repos/{self.repo}/labels", {"name": name, "color": color, "description": description[:100]})

    def create_issue(self, title: str, body: str, labels: list[str]) -> dict:
        return self._w("POST", f"repos/{self.repo}/issues", {"title": title, "body": body, "labels": labels})

    def update_issue(self, number: int, **fields) -> dict:
        return self._w("PATCH", f"repos/{self.repo}/issues/{number}", fields)

    def comment(self, number: int, body: str) -> dict:
        return self._w("POST", f"repos/{self.repo}/issues/{number}/comments", {"body": body})

    def comments(self, number: int) -> list[dict]:
        return self.paginate(f"repos/{self.repo}/issues/{number}/comments")
