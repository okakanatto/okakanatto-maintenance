"""設定ファイル（config/*.json）の読み込みと検証。"""

from __future__ import annotations

import datetime as dt
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .model import SEVERITIES

ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = ROOT / "config"

SUPPRESSION_STATUSES = ("false_positive", "snoozed", "risk_accepted")


class ConfigError(Exception):
    pass


@dataclass
class Suppression:
    key: str
    status: str
    reason: str
    until: dt.date | None
    by: str = ""

    def active(self, today: dt.date) -> bool:
        return self.until is None or today <= self.until


@dataclass
class Config:
    raw: dict[str, Any]
    suppressions: list[Suppression] = field(default_factory=list)

    @property
    def owner(self) -> str:
        return self.raw["owner"]

    @property
    def central_repo(self) -> str:
        return self.raw["central_repo"]

    @property
    def central_full_name(self) -> str:
        return f"{self.owner}/{self.central_repo}"

    def section(self, name: str) -> dict:
        return self.raw.get(name, {})

    def repo_policy(self, repo_id: int, name: str) -> dict:
        pols = self.raw.get("repo_policies", {})
        merged: dict = {}
        for k in (name, str(repo_id)):
            if k in pols:
                merged.update(pols[k])
        return merged

    def excluded(self, repo_id: int, name: str) -> str | None:
        ex = self.raw.get("exclude", {})
        if name in ex.get("names", []) or repo_id in ex.get("ids", []):
            return "設定で除外"
        return None

    def suppression_for(self, key: str, aliases: list[str] | None = None) -> Suppression | None:
        keys = {key}
        # 脆弱性は別 ID（CVE/GHSA）でも抑制できる: "vuln:<repo_id>:<alias>"
        if aliases and key.startswith("vuln:"):
            prefix = key.rsplit(":", 1)[0]
            keys |= {f"{prefix}:{a}" for a in aliases}
        for s in self.suppressions:
            if s.key in keys:
                return s
        return None


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ConfigError(f"{path.name} がありません")
    except json.JSONDecodeError as e:
        raise ConfigError(f"{path.name} の JSON が壊れています: {e}")


def load(config_dir: Path = CONFIG_DIR) -> Config:
    raw = _load_json(config_dir / "maintenance.json")
    sup_path = config_dir / "suppressions.json"
    sup_raw = _load_json(sup_path) if sup_path.exists() else {"suppressions": []}
    cfg = Config(raw, _parse_suppressions(sup_raw))
    validate(cfg)
    return cfg


def _parse_suppressions(d: dict) -> list[Suppression]:
    out = []
    for i, s in enumerate(d.get("suppressions", [])):
        if s.get("status") not in SUPPRESSION_STATUSES:
            raise ConfigError(f"suppressions[{i}].status は {SUPPRESSION_STATUSES} のいずれか")
        if not s.get("key") or not s.get("reason"):
            raise ConfigError(f"suppressions[{i}] には key と reason が必要")
        until = None
        if s.get("until"):
            try:
                until = dt.date.fromisoformat(s["until"])
            except ValueError:
                raise ConfigError(f"suppressions[{i}].until は YYYY-MM-DD")
        elif s["status"] != "false_positive":
            # 保留・リスク受容は期限必須（期限付き再評価のため）
            raise ConfigError(f"suppressions[{i}] ({s['status']}) には until（再評価日）が必要")
        out.append(Suppression(s["key"], s["status"], s["reason"], until, s.get("by", "")))
    return out


def validate(cfg: Config) -> None:
    r = cfg.raw
    for k in ("owner", "central_repo"):
        if not isinstance(r.get(k), str) or not r[k]:
            raise ConfigError(f"maintenance.json: {k} が必要")
    pol = r.get("issue_policy", {})
    for k in ("vuln_min_severity",):
        if k in pol and pol[k] not in SEVERITIES:
            raise ConfigError(f"issue_policy.{k} は {SEVERITIES} のいずれか")
    for i, m in enumerate(r.get("manual_checks", [])):
        for k in ("id", "title", "interval_days"):
            if k not in m:
                raise ConfigError(f"manual_checks[{i}].{k} が必要")
