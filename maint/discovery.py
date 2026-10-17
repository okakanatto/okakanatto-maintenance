"""監視対象の自動発見。

毎回 GitHub API でオーナー所有の公開リポジトリを全ページ取得し、数値 ID で前回の台帳と突き合わせる。
- 新規 → new（初回棚卸しの対象）
- 同じ ID で名前が変わった → renamed（Issue は ID で引き継ぐ）
- 一覧から消えた → /repositories/{id} で理由を確かめる。消えたこと自体を「解消」の根拠にしない
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .config import Config
from .github import GitHubReader
from .http import HttpError
from .model import ERROR, SUCCESS, Repo

# 一覧から消えたリポジトリの状態
GONE_OR_PRIVATE = "gone_or_private"  # 404。削除・非公開化・権限消失を区別できない
BECAME_PRIVATE = "private"  # 読めるが非公開になった（読み取りトークンが所有者権限のときだけ判別できる）
TRANSFERRED = "transferred"  # 所有者が変わった
UNREACHABLE = "api_error"  # API 障害で確認できない
MISSING_LABEL = {
    GONE_OR_PRIVATE: "削除・非公開化・権限消失のいずれか（API 上は区別不能）",
    BECAME_PRIVATE: "非公開化",
    TRANSFERRED: "所有者変更",
    UNREACHABLE: "API 障害で状態を確認できない",
}


@dataclass
class DiscoveryResult:
    status: str = SUCCESS
    active: list[Repo] = field(default_factory=list)
    excluded: list[tuple[Repo, str]] = field(default_factory=list)
    new: list[Repo] = field(default_factory=list)
    renamed: list[tuple[Repo, str]] = field(default_factory=list)  # (repo, 旧 full_name)
    missing: list[dict] = field(default_factory=list)  # {id, name, state, detail}
    returned: list[Repo] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    listed_count: int = 0

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "listed_count": self.listed_count,
            "active": [{"id": r.id, "name": r.full_name} for r in self.active],
            "excluded": [{"id": r.id, "name": r.full_name, "reason": why} for r, why in self.excluded],
            "new": [{"id": r.id, "name": r.full_name} for r in self.new],
            "renamed": [{"id": r.id, "name": r.full_name, "old": old} for r, old in self.renamed],
            "missing": self.missing,
            "returned": [{"id": r.id, "name": r.full_name} for r in self.returned],
            "errors": self.errors,
        }


def exclusion_reason(repo: Repo, cfg: Config) -> str | None:
    if repo.name.lower() == cfg.central_repo.lower():
        return "中央保守リポジトリ自身"
    if repo.owner.lower() != cfg.owner.lower():
        return "所有者が異なる"
    if repo.private:
        return "非公開"
    if repo.fork:
        return "fork"
    if repo.archived:
        return "archive 済み"
    return cfg.excluded(repo.id, repo.name)


def discover(reader: GitHubReader, cfg: Config, state: dict, only: list[str] | None = None) -> DiscoveryResult:
    res = DiscoveryResult()
    try:
        listed = reader.owner_repos(cfg.owner)
    except HttpError as e:
        res.status = ERROR
        res.errors.append(f"リポジトリ一覧を取得できませんでした: {e.kind} ({e.status})")
        return res
    res.listed_count = len(listed)
    known = state.get("repos", {})
    seen: set[str] = set()
    for d in listed:
        repo = Repo.from_api(d)
        seen.add(str(repo.id))
        why = exclusion_reason(repo, cfg)
        if why:
            res.excluded.append((repo, why))
            continue
        if only and repo.name not in only and repo.full_name not in only:
            continue
        res.active.append(repo)
        prev = known.get(str(repo.id))
        if prev is None:
            res.new.append(repo)
        else:
            if prev.get("full_name") and prev["full_name"] != repo.full_name:
                res.renamed.append((repo, prev["full_name"]))
            if prev.get("status") == "missing":
                res.returned.append(repo)

    if only:
        return res  # 一部だけの実行では消失判定をしない

    for rid, prev in known.items():
        if rid in seen or prev.get("status") not in ("active", "missing"):
            continue
        entry = {"id": int(rid), "name": prev.get("full_name", "?")}
        try:
            d = reader.repo_by_id(int(rid))
        except HttpError as e:
            if e.kind == "not_found":
                entry["state"] = GONE_OR_PRIVATE
            else:
                entry["state"] = UNREACHABLE
                entry["detail"] = f"{e.kind} ({e.status})"
            res.missing.append(entry)
            continue
        repo = Repo.from_api(d)
        if repo.owner.lower() != cfg.owner.lower():
            entry["state"] = TRANSFERRED
            entry["detail"] = repo.full_name
        elif repo.private:
            entry["state"] = BECAME_PRIVATE
        else:
            why = exclusion_reason(repo, cfg)
            if why:
                res.excluded.append((repo, why))
                continue
            # 一覧の反映遅れ等で漏れたが実在する → 監視を続ける
            res.active.append(repo)
            continue
        res.missing.append(entry)
    return res


def apply_to_state(res: DiscoveryResult, state: dict, now_iso: str) -> None:
    """発見結果を台帳へ反映する（一覧取得に失敗したときは何も変えない）。"""
    if res.status == ERROR:
        return
    repos = state.setdefault("repos", {})
    for r in res.active:
        e = repos.setdefault(str(r.id), {"first_seen": now_iso, "names": []})
        if e.get("full_name") and e["full_name"] != r.full_name and e["full_name"] not in e["names"]:
            e["names"].append(e["full_name"])
        e.update({"name": r.name, "full_name": r.full_name, "status": "active", "last_seen": now_iso})
        e.pop("status_detail", None)
    for r, why in res.excluded:
        e = repos.get(str(r.id))
        if e is not None:  # 監視していたものが除外条件に入った（archive 等）
            e.update({"name": r.name, "full_name": r.full_name, "status": "excluded", "status_detail": why})
    for m in res.missing:
        e = repos.get(str(m["id"]))
        if e is not None:
            e["status"] = "missing"
            e["status_detail"] = m["state"]
