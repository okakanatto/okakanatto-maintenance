"""監視結果のデータ型。

3 つの軸を混同しないために、型を分けて持つ。
- RunStatus: 検査を実行できたか（SUCCESS / PARTIAL / ERROR / SKIPPED）
- Coverage: その領域を機械的に監視できる仕組みがあるか（SUPPORTED ... UNKNOWN）
- Severity: 見つかった問題の重さ（CRITICAL ... INFO）
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

# --- 実行状態 -------------------------------------------------------------

SUCCESS = "SUCCESS"  # 対象範囲を最後まで検査できた
PARTIAL = "PARTIAL"  # 一部の対象・取得に失敗した
ERROR = "ERROR"  # 検査そのものが成立しなかった
SKIPPED = "SKIPPED"  # 今回の実行では対象外（週次・月次の対象日でない等）

RUN_STATUSES = (SUCCESS, PARTIAL, ERROR, SKIPPED)

# --- カバレッジ -----------------------------------------------------------

SUPPORTED = "SUPPORTED"  # 機械的に検査できる
COV_PARTIAL = "PARTIAL"  # 一部だけ検査できる（未検査部分は note に書く）
UNSUPPORTED = "UNSUPPORTED"  # 対象は存在するが検査手段がない
NOT_APPLICABLE = "NOT_APPLICABLE"  # 対象が存在しない
UNKNOWN = "UNKNOWN"  # 判断材料がない（取得失敗を含む）

COVERAGES = (SUPPORTED, COV_PARTIAL, UNSUPPORTED, NOT_APPLICABLE, UNKNOWN)

# --- 重要度 ---------------------------------------------------------------

CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
LOW = "low"
INFO = "info"

SEVERITIES = (CRITICAL, HIGH, MEDIUM, LOW, INFO)
SEVERITY_RANK = {s: i for i, s in enumerate(reversed(SEVERITIES))}  # info=0 ... critical=4
SEVERITY_JA = {CRITICAL: "Critical", HIGH: "High", MEDIUM: "Medium", LOW: "Low", INFO: "Info"}
# 対応目安（日）。Issue に書く。根拠は README「重要度と対応目安」
DUE_DAYS = {CRITICAL: 3, HIGH: 14, MEDIUM: 30, LOW: 90, INFO: None}


def severity_at_least(sev: str, minimum: str) -> bool:
    return SEVERITY_RANK[sev] >= SEVERITY_RANK[minimum]


def worse_run_status(a: str, b: str) -> str:
    order = {SKIPPED: 0, SUCCESS: 1, PARTIAL: 2, ERROR: 3}
    return a if order[a] >= order[b] else b


@dataclass
class Repo:
    """監視対象。id が主キー。name は表示用で、リネームで変わる。"""

    id: int
    name: str
    full_name: str
    default_branch: str
    html_url: str
    size: int = 0
    archived: bool = False
    fork: bool = False
    private: bool = False
    pushed_at: str | None = None
    owner: str = ""

    @classmethod
    def from_api(cls, d: dict) -> "Repo":
        return cls(
            id=int(d["id"]),
            name=d["name"],
            full_name=d["full_name"],
            default_branch=d.get("default_branch") or "main",
            html_url=d.get("html_url") or f"https://github.com/{d['full_name']}",
            size=int(d.get("size") or 0),
            archived=bool(d.get("archived")),
            fork=bool(d.get("fork")),
            private=bool(d.get("private")),
            pushed_at=d.get("pushed_at"),
            owner=(d.get("owner") or {}).get("login", d["full_name"].split("/")[0]),
        )


@dataclass
class Finding:
    """検出された問題 1 件。key が Issue の一意キーになる。"""

    key: str  # 例: vuln:1164599744:GHSA-xxxx
    kind: str  # vuln / deps / ci / eol / coverage / release / manual
    repo_id: int | None
    repo_name: str
    title: str
    severity: str
    summary: str
    evidence: list[str] = field(default_factory=list)  # 根拠（URL・ファイル・値）
    recommendation: str = ""
    unverified: list[str] = field(default_factory=list)  # 未検証事項
    scope: list[str] = field(default_factory=list)  # 検査範囲
    aliases: list[str] = field(default_factory=list)  # 脆弱性の別 ID
    material: dict[str, Any] = field(default_factory=dict)  # 変化検知に使う値（日時を入れない）
    issue: bool = True  # Issue 化の対象か（False はサマリーのみ）
    # 解消判定に要る検証トークン。今回の実行でこれが全部「検査成功」と確認されたときだけ、
    # 検出が消えた Issue を閉じてよい（CheckResult.verified_scopes と照合する）
    verify: list[str] = field(default_factory=list)
    # 細かい単位（勧告 1 件など）の抑制で、中身がすべて抑制中になった Finding。Issue は作らず、既存なら抑制ラベルを付ける
    suppressed: bool = False

    def fingerprint(self) -> str:
        # タイトル（リポジトリ名を含む）は入れない。リネームだけで「内容が変わった」と通知しないため
        payload = {
            "severity": self.severity,
            "material": self.material,
        }
        raw = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "kind": self.kind,
            "repo_id": self.repo_id,
            "repo": self.repo_name,
            "title": self.title,
            "severity": self.severity,
            "summary": self.summary,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "unverified": self.unverified,
            "scope": self.scope,
            "aliases": self.aliases,
            "material": self.material,
            "issue": self.issue,
            "verify": self.verify,
            "suppressed": self.suppressed,
            "fingerprint": self.fingerprint(),
        }


@dataclass
class CoverageItem:
    level: str
    note: str = ""

    def to_dict(self) -> dict:
        return {"level": self.level, "note": self.note}


@dataclass
class CheckResult:
    """1 リポジトリ × 1 検査の結果。"""

    check: str
    status: str = SUCCESS
    coverage: dict[str, CoverageItem] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)  # サマリーに出す情報
    errors: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)  # 機械可読レポート用の生データ
    # 解消判定に使う: この検査が最後まで確かめられた範囲（Finding.verify のトークン）
    verified_scopes: list[str] = field(default_factory=list)

    def cover(self, area: str, level: str, note: str = "") -> None:
        self.coverage[area] = CoverageItem(level, note)

    def fail(self, message: str, fatal: bool = False) -> None:
        self.errors.append(message)
        self.status = worse_run_status(self.status, ERROR if fatal else PARTIAL)

    def to_dict(self) -> dict:
        return {
            "check": self.check,
            "status": self.status,
            "coverage": {k: v.to_dict() for k, v in sorted(self.coverage.items())},
            "findings": [f.to_dict() for f in self.findings],
            "notes": self.notes,
            "errors": self.errors,
            "verified_scopes": self.verified_scopes,
            "data": self.data,
        }
