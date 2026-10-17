"""検査に渡す共通の道具一式。"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field

from .config import Config
from .github import GitHubReader
from .http import HttpClient
from .osv import OSVClient


@dataclass
class Context:
    cfg: Config
    reader: GitHubReader  # 監視対象の読み取り（書き込み不可）
    http: HttpClient  # GitHub 以外の公開 API（OSV・npm・crates.io・PyPI・endoflife.date）
    osv: OSVClient
    now: dt.datetime
    dependabot: GitHubReader | None = None  # Dependabot alerts 読み取り用（任意。未設定なら未取得と表示）
    cache: dict = field(default_factory=dict)  # 実行内キャッシュ（アクションの runtime・EOL データ等）

    @property
    def today(self) -> dt.date:
        return self.now.date()

    def policy(self, section: str, key: str, default=None, repo_id: int | None = None, repo_name: str = ""):
        if repo_id is not None:
            rp = self.cfg.repo_policy(repo_id, repo_name).get(section, {})
            if key in rp:
                return rp[key]
        return self.cfg.section(section).get(key, default)
