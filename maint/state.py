"""永続状態。DB を置かず、ダッシュボード Issue の本文末尾に隠し JSON として持つ。

本文編集は GitHub の通知を発生させないので、毎回更新しても通知は増えない。
JSON が壊れていた・見つからない場合は空の状態から始める（全検査を実行し、新規発見扱いになる）。
"""

from __future__ import annotations

import json

BEGIN = "<!-- maint-state:BEGIN"
END = "maint-state:END -->"
VERSION = 1


def empty() -> dict:
    return {
        "version": VERSION,
        "repos": {},  # str(repo_id) -> {name, full_name, status, first_seen, last_seen, names, inventory}
        "last_completed": {},  # daily/weekly/monthly -> ISO 日時（その周期の検査が SUCCESS/PARTIAL で終わった日時）
        "check_failures": {},  # "<repo_id>:<check>" -> 連続 ERROR 回数
        "manual_checks": {},  # check_id -> 最後に完了した日（YYYY-MM-DD）
    }


def encode(state: dict) -> str:
    raw = json.dumps(state, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    raw = raw.replace("--", "-\\u002d")  # HTML コメント終端（-->）を本文に作らない
    return f"{BEGIN}\n{raw}\n{END}"


def decode(body: str | None) -> dict | None:
    if not body or BEGIN not in body:
        return None
    try:
        chunk = body.split(BEGIN, 1)[1].split(END, 1)[0].strip()
        d = json.loads(chunk)
    except (ValueError, IndexError):
        return None
    if not isinstance(d, dict) or d.get("version") != VERSION:
        return None
    base = empty()
    for k in base:
        if isinstance(d.get(k), type(base[k])):
            base[k] = d[k]
    return base
