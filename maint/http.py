"""HTTP クライアント（標準ライブラリのみ）。

- 送受信は transport 関数に切り出してあり、テストでは偽の transport を差し込む
- 429・GitHub のレート制限（403 + remaining=0 / secondary rate limit）・5xx・タイムアウトは再試行する
- 失敗は HttpError.kind で分類する。呼び出し側は「取得できなかった」を「問題なし」と扱わないこと
"""

from __future__ import annotations

import json
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable

USER_AGENT = "okakanatto-maintenance/0.1 (+https://github.com/okakanatto/okakanatto-maintenance)"
MAX_BODY = 50 * 1024 * 1024  # 50MB を超える応答は読まない


@dataclass
class Request:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes | None = None
    timeout: float = 30.0


@dataclass
class Response:
    status: int
    headers: dict[str, str]  # キーは小文字
    body: bytes

    def json(self):
        return json.loads(self.body.decode("utf-8"))


class TransportTimeout(Exception):
    pass


class TransportError(Exception):
    pass


Transport = Callable[[Request], Response]


def urllib_transport(req: Request) -> Response:
    r = urllib.request.Request(req.url, data=req.body, method=req.method, headers=req.headers)
    try:
        with urllib.request.urlopen(r, timeout=req.timeout) as resp:
            body = resp.read(MAX_BODY + 1)
            return Response(resp.status, {k.lower(): v for k, v in resp.headers.items()}, body)
    except urllib.error.HTTPError as e:
        body = e.read(MAX_BODY + 1) if e.fp else b""
        return Response(e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, body)
    except (socket.timeout, TimeoutError) as e:
        raise TransportTimeout(str(e)) from e
    except urllib.error.URLError as e:
        if isinstance(e.reason, (socket.timeout, TimeoutError)):
            raise TransportTimeout(str(e.reason)) from e
        raise TransportError(str(e.reason)) from e
    except (ConnectionError, OSError) as e:
        raise TransportError(str(e)) from e


class HttpError(Exception):
    """kind: rate_limited / forbidden / not_found / conflict / client / server / timeout / network / bad_json / too_large"""

    def __init__(self, kind: str, url: str, status: int | None = None, message: str = ""):
        self.kind = kind
        self.url = url
        self.status = status
        self.message = message
        super().__init__(f"{kind} status={status} url={redact(url)} {message}".strip())


def redact(url: str) -> str:
    # URL にトークンを載せることはないが、念のためクエリの token 系を伏せる
    if "token=" in url or "access_token=" in url:
        return url.split("?")[0] + "?<redacted>"
    return url


def _is_rate_limited(resp: Response) -> bool:
    if resp.status == 429:
        return True
    if resp.status == 403:
        if resp.headers.get("x-ratelimit-remaining") == "0":
            return True
        text = resp.body[:2000].decode("utf-8", "replace").lower()
        if "rate limit" in text:
            return True
    return False


class HttpClient:
    def __init__(
        self,
        transport: Transport | None = None,
        max_retries: int = 3,
        backoff: float = 2.0,
        max_wait: float = 90.0,
        timeout: float = 30.0,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.time,
    ):
        self.transport = transport or urllib_transport
        self.max_retries = max_retries
        self.backoff = backoff
        self.max_wait = max_wait
        self.timeout = timeout
        self.sleep = sleep
        self.clock = clock
        self.request_count = 0

    def _wait_seconds(self, resp: Response | None, attempt: int) -> float:
        if resp is not None:
            ra = resp.headers.get("retry-after")
            if ra and ra.strip().isdigit():
                return float(ra)
            reset = resp.headers.get("x-ratelimit-reset")
            if resp.headers.get("x-ratelimit-remaining") == "0" and reset and reset.isdigit():
                return max(0.0, float(reset) - self.clock()) + 1.0
        return self.backoff * (2**attempt)

    def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        json_body=None,
        raw: bool = False,
        ok_statuses: tuple[int, ...] = (200, 201, 204),
        idempotent: bool | None = None,
    ) -> tuple[object, Response]:
        """成功時は (解析済み JSON または bytes, Response)。失敗時は HttpError。

        idempotent=False（既定では GitHub への POST）は、5xx・タイムアウト・通信断で再送しない。
        サーバー側で処理済みだった場合に Issue やコメントが二重になるため。レート制限（未処理が確実）だけは再送する。
        """
        if idempotent is None:
            idempotent = not (method == "POST" and "api.github.com" in url)
        hdrs = {"User-Agent": USER_AGENT}
        hdrs.update(headers or {})
        body = None
        if json_body is not None:
            body = json.dumps(json_body).encode("utf-8")
            hdrs["Content-Type"] = "application/json"
        last_err: HttpError | None = None
        for attempt in range(self.max_retries + 1):
            resp = None
            try:
                self.request_count += 1
                resp = self.transport(Request(method, url, hdrs, body, self.timeout))
            except TransportTimeout as e:
                last_err = HttpError("timeout", url, None, str(e))
            except TransportError as e:
                last_err = HttpError("network", url, None, str(e))
            else:
                if len(resp.body) > MAX_BODY:
                    raise HttpError("too_large", url, resp.status)
                if resp.status in ok_statuses:
                    if raw:
                        return resp.body, resp
                    if not resp.body:
                        return None, resp
                    try:
                        return resp.json(), resp
                    except (ValueError, UnicodeDecodeError) as e:
                        # 不正 JSON は再試行しても直らないことが多いが、途中切れの可能性もあるので 1 回だけ再試行
                        last_err = HttpError("bad_json", url, resp.status, str(e)[:200])
                        if attempt >= 1:
                            raise last_err
                        continue
                if _is_rate_limited(resp):
                    last_err = HttpError("rate_limited", url, resp.status, _message(resp))
                elif resp.status >= 500:
                    last_err = HttpError("server", url, resp.status, _message(resp))
                elif resp.status == 404:
                    raise HttpError("not_found", url, 404, _message(resp))
                elif resp.status == 409:
                    raise HttpError("conflict", url, 409, _message(resp))
                elif resp.status in (401, 403):
                    raise HttpError("forbidden", url, resp.status, _message(resp))
                else:
                    raise HttpError("client", url, resp.status, _message(resp))
            if attempt >= self.max_retries:
                break
            if not idempotent and last_err.kind != "rate_limited":
                break
            wait = self._wait_seconds(resp, attempt)
            if wait > self.max_wait:
                # レート制限の解除が遠い場合は待たずに失敗させる（部分取得として記録される）
                break
            self.sleep(wait)
        assert last_err is not None
        raise last_err


def _message(resp: Response) -> str:
    try:
        d = json.loads(resp.body.decode("utf-8"))
        if isinstance(d, dict):
            return str(d.get("message", ""))[:200]
    except (ValueError, UnicodeDecodeError):
        pass
    return resp.body[:200].decode("utf-8", "replace")
