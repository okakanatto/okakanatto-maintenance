"""OSV.dev API（https://google.github.io/osv.dev/api/）による既知脆弱性の照合。

- querybatch はパッケージ×版ごとに脆弱性 ID だけを返す。詳細は /v1/vulns/{id} で取る
- 深刻度は GHSA の database_specific.severity を優先し、無ければ CVSS v3 ベクトルから算出する。
  どちらも無い（CVSS v4 のみ等）場合は「未算出」とし、Medium 扱い＋未検証事項に明記する
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from .http import HttpClient, HttpError
from .lockfiles import Package
from .model import CRITICAL, HIGH, INFO, LOW, MEDIUM

OSV_API = "https://api.osv.dev/v1"
BATCH_LIMIT = 1000


@dataclass
class Vuln:
    id: str
    aliases: list[str]
    summary: str
    severity: str
    severity_source: str  # ghsa / cvss_v3 / informational / unknown
    cvss_vector: str | None
    published: str | None
    modified: str | None
    references: list[str]
    informational: str | None  # RUSTSEC の unmaintained / unsound / notice
    raw_affected: list[dict] = field(default_factory=list)

    def fixed_versions(self, ecosystem: str, name: str) -> list[str]:
        out: list[str] = []
        for a in self.raw_affected:
            pkg = a.get("package") or {}
            if pkg.get("ecosystem") != ecosystem or pkg.get("name", "").lower() != name.lower():
                continue
            for r in a.get("ranges") or []:
                for ev in r.get("events") or []:
                    if "fixed" in ev and ev["fixed"] not in out:
                        out.append(ev["fixed"])
        return out

    def affected_os(self) -> list[str]:
        """RUSTSEC が影響 OS を限定している場合はその一覧。"""
        oss: list[str] = []
        for a in self.raw_affected:
            aff = (a.get("ecosystem_specific") or {}).get("affects") or {}
            for o in aff.get("os") or []:
                if o not in oss:
                    oss.append(o)
        return oss


class OSVClient:
    def __init__(self, http: HttpClient, api: str = OSV_API):
        self.http = http
        self.api = api
        self._cache: dict[str, Vuln] = {}

    def query_packages(self, packages: list[Package]) -> dict[tuple[str, str, str], list[str]]:
        """{(eco, name, version): [vuln id, ...]}。1 件でも取得に失敗したら HttpError。"""
        uniq = sorted({(p.ecosystem, p.name, p.version) for p in packages})
        result: dict[tuple[str, str, str], list[str]] = {}
        for i in range(0, len(uniq), BATCH_LIMIT):
            chunk = uniq[i : i + BATCH_LIMIT]
            queries = [{"package": {"ecosystem": e, "name": n}, "version": v} for e, n, v in chunk]
            data, _ = self.http.request("POST", f"{self.api}/querybatch", json_body={"queries": queries})
            results = (data or {}).get("results")
            if not isinstance(results, list) or len(results) != len(chunk):
                raise HttpError("bad_json", f"{self.api}/querybatch", None, "results length mismatch")
            for key, q, r in zip(chunk, queries, results):
                ids = [v["id"] for v in (r or {}).get("vulns", []) or [] if isinstance(v, dict) and "id" in v]
                token = (r or {}).get("next_page_token")
                pages = 0
                while token and pages < 20:
                    pages += 1
                    d2, _ = self.http.request("POST", f"{self.api}/query", json_body={**q, "page_token": token})
                    ids += [v["id"] for v in (d2 or {}).get("vulns", []) or []]
                    token = (d2 or {}).get("next_page_token")
                result[key] = sorted(set(ids))
        return result

    def query_commit(self, sha: str) -> list[str]:
        data, _ = self.http.request("POST", f"{self.api}/query", json_body={"commit": sha})
        return sorted({v["id"] for v in (data or {}).get("vulns", []) or []})

    def get(self, vuln_id: str) -> Vuln:
        if vuln_id in self._cache:
            return self._cache[vuln_id]
        d, _ = self.http.request("GET", f"{self.api}/vulns/{vuln_id}")
        v = parse_vuln(d)
        self._cache[vuln_id] = v
        return v


def parse_vuln(d: dict) -> Vuln:
    if not isinstance(d, dict) or "id" not in d:
        raise HttpError("bad_json", "osv vuln", None, "id missing")
    dbs = d.get("database_specific") or {}
    informational = dbs.get("informational") if isinstance(dbs, dict) else None
    if not informational:  # RUSTSEC は affected[].database_specific.informational に入れる
        for a in d.get("affected") or []:
            ads = a.get("database_specific") if isinstance(a, dict) else None
            if isinstance(ads, dict) and ads.get("informational"):
                informational = ads["informational"]
                break
    sev, src, vector = None, "unknown", None
    ghsa = str(dbs.get("severity", "")).upper() if isinstance(dbs, dict) else ""
    if ghsa in ("CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW"):
        sev = {"CRITICAL": CRITICAL, "HIGH": HIGH, "MODERATE": MEDIUM, "MEDIUM": MEDIUM, "LOW": LOW}[ghsa]
        src = "ghsa"
    for s in d.get("severity") or []:
        if isinstance(s, dict) and s.get("type") == "CVSS_V3" and isinstance(s.get("score"), str):
            vector = s["score"]
            if sev is None:
                score = cvss3_base_score(vector)
                if score is not None:
                    sev, src = cvss_rating(score), "cvss_v3"
        elif isinstance(s, dict) and s.get("type") == "CVSS_V4" and vector is None:
            vector = s.get("score")
    if sev is None and informational:
        sev = LOW if informational == "unsound" else INFO
        src = "informational"
    if sev is None:
        sev, src = MEDIUM, "unknown"
    refs = [r["url"] for r in d.get("references") or [] if isinstance(r, dict) and isinstance(r.get("url"), str)]
    summary = d.get("summary") or (d.get("details") or "").strip().split("\n")[0]
    return Vuln(
        id=d["id"],
        aliases=sorted(set(a for a in d.get("aliases") or [] if isinstance(a, str))),
        summary=str(summary)[:300],
        severity=sev,
        severity_source=src,
        cvss_vector=vector,
        published=d.get("published"),
        modified=d.get("modified"),
        references=refs[:10],
        informational=informational,
        raw_affected=[a for a in d.get("affected") or [] if isinstance(a, dict)],
    )


# --- CVSS v3.x 基本値（FIRST 仕様書 7.1 節の式） ------------------------------

_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _roundup(x: float) -> float:
    i = round(x * 100000)
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def cvss3_base_score(vector: str) -> float | None:
    try:
        parts = dict(p.split(":", 1) for p in vector.split("/")[1:])
        if not vector.startswith("CVSS:3"):
            return None
        scope_changed = parts["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}[parts["PR"]]
        iss = 1 - (1 - _W["CIA"][parts["C"]]) * (1 - _W["CIA"][parts["I"]]) * (1 - _W["CIA"][parts["A"]])
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss
        expl = 8.22 * _W["AV"][parts["AV"]] * _W["AC"][parts["AC"]] * pr * _W["UI"][parts["UI"]]
        if impact <= 0:
            return 0.0
        if scope_changed:
            return _roundup(min(1.08 * (impact + expl), 10))
        return _roundup(min(impact + expl, 10))
    except (KeyError, ValueError):
        return None


def cvss_rating(score: float) -> str:
    if score >= 9.0:
        return CRITICAL
    if score >= 7.0:
        return HIGH
    if score >= 4.0:
        return MEDIUM
    if score > 0:
        return LOW
    return INFO
