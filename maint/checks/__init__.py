"""検査の一覧。周期ごとに何を実行するかはここで決める（拡張するときはここに足す）。

daily  : release（配布版）→ vuln（脆弱性）→ ci（CI 状態・陳腐化）
weekly : deps（依存更新）
monthly: eol（サポート終了）＋ manual（期限付き定期点検。リポジトリ横断）
"""

PERIOD_CHECKS = {
    "daily": ["release", "vuln", "ci"],
    "weekly": ["deps"],
    "monthly": ["eol"],
}
