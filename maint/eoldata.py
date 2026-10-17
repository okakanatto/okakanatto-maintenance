"""endoflife.date API v1（https://endoflife.date/docs/api/v1/）の取得と版の突き合わせ。"""

from __future__ import annotations

from .http import HttpError

EOL_API = "https://endoflife.date/api/v1/products"


def product_releases(ctx, product: str) -> list[dict] | None:
    """製品のサイクル一覧。製品が無ければ None（404）。取得失敗は HttpError。"""
    cache = ctx.cache.setdefault("eol", {})
    if product in cache:
        if isinstance(cache[product], HttpError):
            raise cache[product]
        return cache[product]
    try:
        data, _ = ctx.http.request("GET", f"{EOL_API}/{product}", {"Accept": "application/json"})
    except HttpError as e:
        if e.kind == "not_found":
            cache[product] = None
            return None
        cache[product] = e
        raise
    rels = ((data or {}).get("result") or {}).get("releases")
    if not isinstance(rels, list):
        e = HttpError("bad_json", f"{EOL_API}/{product}", None, "releases missing")
        cache[product] = e
        raise e
    cache[product] = rels
    return rels


def match_cycle(releases: list[dict], version: str) -> dict | None:
    """'6.9.3' → name='6.9' のサイクル。最も長く一致する名前を選ぶ。"""
    v = version.strip().lstrip("v^~=>< ")
    best = None
    for rel in releases:
        name = str(rel.get("name", ""))
        if not name:
            continue
        if v == name or v.startswith(name + "."):
            if best is None or len(name) > len(best["name"]):
                best = rel
    return best
