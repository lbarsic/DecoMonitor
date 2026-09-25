"""Local per-device bandwidth graphs for a TP-Link Deco mesh.

Polls the Deco and serves http://127.0.0.1:8787 on this PC.
The Deco password stays in secret.txt and is never sent to TP-Link's cloud.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import math
import os
import secrets
import sqlite3
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote_plus, urlparse

from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "history.sqlite"
SECRET_PATH = ROOT / "secret.txt"
CONFIG_PATH = ROOT / "config.json"
LOG_PATH = ROOT / "server.log"
HOST = "127.0.0.1"
PORT = 8787
DECO_HOST = "192.168.68.1"

RANGES = {"1h": 3600, "24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400}
BUCKETS = {"1h": 10, "24h": 300, "7d": 900, "30d": 3600}
# The Deco web UI treats down_speed / up_speed as KiB/s: under 1024 it prints
# the raw number as KB/s, otherwise raw/1024 as MB/s. On this X55 that number
# is 10x the bytes actually transferred (a 5.75 GB download was stored as
# 55.75 GB and shown around 1700 Mbps). Divide by SPEED_SCALE at ingest.
# Mbps is the corrected byte rate in decimal megabits.
KIB = 1024
SPEED_SCALE = 10
MAX_SANE_MBPS = 2500
MAX_DT = 45
POLL_FAST = 10
POLL_MID = 15
POLL_SLOW = 30

DOWN_BYTE_KEYS = (
    "rerx_byte",
    "rx_bytes",
    "rx_byte",
    "down_bytes",
    "download_bytes",
    "traffic_down",
    "bytes_down",
)
UP_BYTE_KEYS = (
    "retx_byte",
    "tx_bytes",
    "tx_byte",
    "up_bytes",
    "upload_bytes",
    "traffic_up",
    "bytes_up",
)

logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("deco-bandwidth")


class DecoError(Exception):
    def __init__(self, message: str, code: int | str | None = None) -> None:
        super().__init__(message)
        self.code = code


def _aes_encrypt(key: str, iv: str, plaintext: str) -> str:
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key.encode()), modes.CBC(iv.encode()))
    enc = cipher.encryptor()
    return base64.b64encode(enc.update(padded) + enc.finalize()).decode()


def _aes_decrypt(key: str, iv: str, ciphertext_b64: str) -> str:
    raw = base64.b64decode(ciphertext_b64)
    cipher = Cipher(algorithms.AES(key.encode()), modes.CBC(iv.encode()))
    dec = cipher.decryptor()
    padded = dec.update(raw) + dec.finalize()
    n = padded[-1]
    if n < 1 or n > 16 or padded[-n:] != bytes([n]) * n:
        raise DecoError("Could not decrypt the Deco response")
    return padded[:-n].decode()


def _rsa_encrypt(n: int, e: int, plaintext: bytes) -> str:
    block = (int(math.log2(n)) + 8) >> 3
    step = block - 11
    out = []
    for i in range(0, len(plaintext), step):
        chunk = plaintext[i : i + step]
        pad_len = block - len(chunk) - 3
        pad = bytearray()
        while len(pad) < pad_len:
            b = secrets.token_bytes(1)
            if b != b"\x00":
                pad += b
        em = b"\x00\x02" + bytes(pad) + b"\x00" + chunk
        ct = pow(int.from_bytes(em, "big"), e, n)
        out.append(format(ct, f"0{block * 2}x"))
    return "".join(out)


def _b64_name(value: str) -> str:
    if not value:
        return ""
    try:
        pad = "=" * (-len(value) % 4)
        return base64.b64decode(value + pad, validate=False).decode("utf-8")
    except Exception:
        return value


def _norm_mac(value: str) -> str:
    raw = (value or "").strip().lower().replace("-", ":")
    hexonly = raw.replace(":", "")
    if len(hexonly) == 12 and all(c in "0123456789abcdef" for c in hexonly):
        return ":".join(hexonly[i : i + 2] for i in range(0, 12, 2))
    return raw


def _short_model(model: str) -> str:
    text = model or ""
    upper = text.upper()
    for token in ("X55", "X50"):
        if token in upper:
            return token
    return text.strip() or "Deco"


def _band(connection_type: str, wire_type: str) -> str:
    kind = (connection_type or wire_type or "").lower()
    return {
        "wired": "Wired",
        "band2_4": "2.4 GHz",
        "band5": "5 GHz",
        "band5_1": "5 GHz",
        "band5_2": "5 GHz",
        "band6": "6 GHz",
    }.get(kind, connection_type or wire_type or "")


def _first_int(item: dict, keys: tuple[str, ...]) -> int | None:
    for key in keys:
        if key in item and item[key] is not None and item[key] != "":
            try:
                return int(item[key])
            except (TypeError, ValueError):
                continue
    return None


def _mbps(raw: float) -> float:
    return raw * KIB * 8 / 1_000_000


def _speed_bytes(raw: float, dt: float) -> int:
    return int(raw * KIB * dt)


def _empty_usage() -> dict:
    return {
        "today": {"down_bytes": 0, "up_bytes": 0},
        "week": {"down_bytes": 0, "up_bytes": 0},
        "month": {"down_bytes": 0, "up_bytes": 0},
        "all": {"down_bytes": 0, "up_bytes": 0},
    }


def _stuck_levels(values: list[float]) -> list[float]:
    levels: list[list[float]] = []
    for value in values:
        if value < 2048:
            continue
        for level in levels:
            if abs(value - level[0]) / level[0] < 0.02:
                level[1] += 1
                break
        else:
            levels.append([value, 1.0])
    return [level[0] for level in levels if level[1] >= 3]


def _is_stuck(value: float, levels: list[float]) -> bool:
    return any(level > 0 and abs(value - level) / level < 0.02 for level in levels)


def _judge_stuck(raw: float, window: list[float]) -> float:
    """Replace one reading from two frozen plateaus.

    Download and upload are judged on their own. A real transfer does not sit
    on two exact high speeds that are far apart, such as 60 MB/s and 208 MB/s
    down or 27 MB/s and 135 MB/s up. Varying speeds are left as reported.
    """
    if len(window) < 8 or raw < 2048:
        return raw
    levels = _stuck_levels(window)
    if not levels:
        return raw
    highs = [value for value in window if value >= 2048]
    ordered = sorted(level for level in levels if level > 0)
    pair: list[float] | None = None
    for index, low in enumerate(ordered):
        for high in ordered[index + 1 :]:
            if high >= low * 2.5:
                pair = [low, high]
    if pair and _is_stuck(raw, pair) and all(_is_stuck(value, pair) for value in highs):
        return 0.0
    # One frozen number, with idle readings beside it. Upload does this on
    # its own: the same ~145 MB/s several times while download stays at zero.
    if (
        len(ordered) == 1
        and _is_stuck(raw, ordered)
        and all(_is_stuck(value, ordered) for value in highs)
        and sum(1 for value in highs if _is_stuck(value, ordered)) >= 3
        and sum(1 for value in window if value < 2048) >= 3
    ):
        return 0.0
    return raw


def _correct_direction(values: list[float]) -> list[float]:
    corrected = []
    for index, raw in enumerate(values):
        start = max(0, index - 12)
        end = min(len(values), index + 13)
        corrected.append(_judge_stuck(raw, values[start:end]))
    return corrected


def _median(values: list[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2


def _bucket_spark(series: list[tuple[int, float]], start: int, end: int, buckets: int) -> list[list]:
    if end <= start:
        return []
    width = (end - start) / buckets
    bins: list[list[float]] = [[] for _ in range(buckets)]
    for ts, down in series:
        index = min(buckets - 1, max(0, int((ts - start) / width)))
        bins[index].append(down)
    points = []
    for index, values in enumerate(bins):
        if not values:
            continue
        points.append([int(start + index * width), round(sum(values) / len(values), 4), 0])
    return points


def _deco_rate(raw: float) -> str:
    if raw < KIB:
        return f"{raw:.0f} KB/s"
    return f"{raw / KIB:.1f} MB/s"


def _credited_gap(previous: int | None, ts: int, fallback: float = POLL_FAST) -> float:
    if previous is None:
        return float(fallback)
    gap = ts - previous
    if gap <= 0 or gap > MAX_DT:
        return float(fallback)
    return float(gap)


def _as_float(value) -> float | None:
    try:
        if value is None or value == "":
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


class DecoClient:
    def __init__(self, host: str, username: str, password: str) -> None:
        self.host = host
        self.username = username
        self.password = password
        self._ssl = ssl.create_default_context()
        self._ssl.check_hostname = False
        self._ssl.verify_mode = ssl.CERT_NONE
        self._cookie: str | None = None
        self._stok: str | None = None
        self._aes_key = ""
        self._aes_iv = ""
        self._seq = 0
        self._sign_n = 0
        self._sign_e = 0
        self._pwd_n = 0
        self._pwd_e = 0

    def login(self) -> None:
        self._cookie = None
        self._stok = None
        auth = self._post_json(self._login_url("auth"), {"operation": "read"})
        keys = self._post_json(self._login_url("keys"), {"operation": "read"})
        try:
            sign = auth["result"]["key"]
            pwd = keys["result"]["password"]
            self._sign_n = int(sign[0], 16)
            self._sign_e = int(sign[1], 16)
            self._pwd_n = int(pwd[0], 16)
            self._pwd_e = int(pwd[1], 16)
            self._seq = int(auth["result"]["seq"])
        except (KeyError, TypeError, ValueError) as exc:
            raise DecoError("The Deco login handshake did not return keys") from exc

        self._aes_key = str(secrets.randbelow(10**16 - 10**15) + 10**15)
        self._aes_iv = str(secrets.randbelow(10**16 - 10**15) + 10**15)
        encrypted = _rsa_encrypt(self._pwd_n, self._pwd_e, self.password.encode())
        body = self._envelope({"operation": "login", "params": {"password": encrypted}})
        raw = self._post_form(self._login_url("login"), body)
        result = self._unwrap(raw)
        code = result.get("error_code", 0) or 0
        if code:
            if code == -5002:
                left = (result.get("result") or {}).get("attemptsAllowed")
                extra = f" Attempts left: {left}." if left is not None else ""
                raise DecoError(
                    "The Deco rejected that password. Use the same password as the Deco app."
                    + extra,
                    code,
                )
            raise DecoError(f"Deco login failed (error {code})", code)
        stok = (result.get("result") or {}).get("stok")
        if not stok:
            raise DecoError("Deco login did not return a session")
        if not self._cookie:
            raise DecoError("Deco login did not return a session cookie")
        self._stok = stok

    def request(self, path: str, form: str, data: dict) -> dict:
        if not self._stok:
            self.login()
        url = (
            f"https://{self.host}/cgi-bin/luci/;stok={self._stok}/{path}?form={form}"
        )
        raw = self._post_form(url, self._envelope(data))
        if raw.get("data") in ("", None):
            self._stok = None
            self.login()
            url = (
                f"https://{self.host}/cgi-bin/luci/;stok={self._stok}/{path}?form={form}"
            )
            raw = self._post_form(url, self._envelope(data))
        result = self._unwrap(raw)
        code = result.get("error_code", 0) or 0
        if code:
            raise DecoError(f"Deco request {form} failed (error {code})", code)
        payload = result.get("result")
        if isinstance(payload, dict):
            return payload
        if isinstance(payload, list):
            return {"list": payload}
        return {}

    def _login_url(self, form: str) -> str:
        return f"https://{self.host}/cgi-bin/luci/;stok=/login?form={form}"

    def _envelope(self, data: dict) -> str:
        data_b64 = _aes_encrypt(
            self._aes_key,
            self._aes_iv,
            json.dumps(data, separators=(",", ":")),
        )
        session_hash = hashlib.md5(
            f"{self.username}{self.password}".encode()
        ).hexdigest()
        sig = (
            f"k={self._aes_key}&i={self._aes_iv}&h={session_hash}"
            f"&s={self._seq + len(data_b64)}"
        )
        sign = _rsa_encrypt(self._sign_n, self._sign_e, sig.encode())
        return f"sign={sign}&data={quote_plus(data_b64)}"

    def _unwrap(self, raw: dict) -> dict:
        data_b64 = raw.get("data")
        if not isinstance(data_b64, str) or not data_b64:
            code = raw.get("error_code")
            raise DecoError(f"Empty response from the Deco (error {code})", code)
        try:
            decoded = json.loads(_aes_decrypt(self._aes_key, self._aes_iv, data_b64))
        except DecoError:
            raise
        except Exception as exc:
            raise DecoError("Could not read the Deco response") from exc
        if not isinstance(decoded, dict):
            raise DecoError("Unexpected response from the Deco")
        return decoded

    def _post_json(self, url: str, body: dict) -> dict:
        return self._send(url, json.dumps(body).encode())

    def _post_form(self, url: str, body: str) -> dict:
        return self._send(url, body.encode())

    def _send(self, url: str, data: bytes) -> dict:
        headers = {"Content-Type": "application/json"}
        if self._cookie:
            headers["Cookie"] = self._cookie
        req = urllib.request.Request(url, data=data, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=12, context=self._ssl) as resp:
                self._take_cookie(resp.headers)
                payload = json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                self._stok = None
                raise DecoError(
                    "The Deco refused the connection. Close the Deco web page if it is open, then try again.",
                    exc.code,
                ) from exc
            raise DecoError(f"The Deco returned HTTP {exc.code}", exc.code) from exc
        except urllib.error.URLError as exc:
            raise DecoError(f"Cannot reach the Deco at {self.host}: {exc.reason}") from exc
        if not isinstance(payload, dict):
            raise DecoError("Unexpected response from the Deco")
        return payload

    def _take_cookie(self, headers) -> None:
        for value in headers.get_all("Set-Cookie") or []:
            for part in value.split(";"):
                part = part.strip()
                if part.lower().startswith("sysauth="):
                    self._cookie = part.split(";", 1)[0]
                    return


class Store:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS samples (
                ts INTEGER NOT NULL,
                mac TEXT NOT NULL,
                reported_down_raw REAL NOT NULL,
                reported_up_raw REAL NOT NULL,
                down_delta INTEGER NOT NULL,
                up_delta INTEGER NOT NULL,
                dt REAL NOT NULL,
                rate_ok INTEGER NOT NULL,
                PRIMARY KEY (ts, mac)
            );
            CREATE TABLE IF NOT EXISTS devices (
                mac TEXT PRIMARY KEY,
                name TEXT,
                ip TEXT,
                node TEXT,
                band TEXT,
                online INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                last_down_raw REAL NOT NULL DEFAULT 0,
                last_up_raw REAL NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS counter_state (
                mac TEXT PRIMARY KEY,
                down_bytes INTEGER,
                up_bytes INTEGER,
                ts INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS minutes (
                minute_ts INTEGER NOT NULL,
                mac TEXT NOT NULL,
                down_bytes INTEGER NOT NULL,
                up_bytes INTEGER NOT NULL,
                gap REAL NOT NULL,
                PRIMARY KEY (minute_ts, mac)
            );
            CREATE TABLE IF NOT EXISTS days (
                day TEXT NOT NULL,
                mac TEXT NOT NULL,
                down_bytes INTEGER NOT NULL,
                up_bytes INTEGER NOT NULL,
                PRIMARY KEY (day, mac)
            );
            """
        )
        self._conn.commit()
        self._backfill_rollups()
        self._hour_at = 0
        self._hour: dict[str, dict] = {}
        self._unstick_logged: set[str] = set()
        self._reported: dict[str, list[tuple[float, float]]] = {}
        self._migrate_speed_scale()
        self.repair_stuck_rates()

    def _migrate_speed_scale(self) -> None:
        """Divide speeds saved before SPEED_SCALE was applied. Once only."""
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM meta WHERE key = 'speed_scale'"
            ).fetchone()
            if row and row["value"] == str(SPEED_SCALE):
                return
            self._conn.execute(
                "UPDATE samples SET reported_down_raw = reported_down_raw / ?, "
                "reported_up_raw = reported_up_raw / ?",
                (SPEED_SCALE, SPEED_SCALE),
            )
            self._conn.execute(
                "UPDATE devices SET last_down_raw = last_down_raw / ?, "
                "last_up_raw = last_up_raw / ?",
                (SPEED_SCALE, SPEED_SCALE),
            )
            self._conn.execute(
                "UPDATE minutes SET down_bytes = down_bytes / ?, "
                "up_bytes = up_bytes / ?",
                (SPEED_SCALE, SPEED_SCALE),
            )
            self._conn.execute(
                "UPDATE days SET down_bytes = down_bytes / ?, "
                "up_bytes = up_bytes / ?",
                (SPEED_SCALE, SPEED_SCALE),
            )
            self._conn.execute(
                "INSERT INTO meta(key, value) VALUES('speed_scale', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (str(SPEED_SCALE),),
            )
            self._conn.commit()
            log.info("scaled stored speeds and usage by 1/%s", SPEED_SCALE)

    def repair_stuck_rates(self) -> None:
        """Drop frozen plateau samples and their bytes, download and upload.

        Only those samples change. Stored day and minute totals stay otherwise,
        so a restart cannot rebuild usage from the speed history and shrink it.
        """
        with self._lock:
            rows = self._conn.execute(
                "SELECT ts, mac, reported_down_raw, reported_up_raw, dt "
                "FROM samples ORDER BY mac, ts"
            ).fetchall()
            grouped: dict[str, list[sqlite3.Row]] = {}
            for row in rows:
                grouped.setdefault(row["mac"], []).append(row)
            sample_updates = []
            minute_delta: dict[tuple[int, str], list[int]] = {}
            day_delta: dict[tuple[str, str], list[int]] = {}
            down_removed = 0
            up_removed = 0
            for mac, samples in grouped.items():
                fixed_down = _correct_direction(
                    [float(sample["reported_down_raw"] or 0) for sample in samples]
                )
                fixed_up = _correct_direction(
                    [float(sample["reported_up_raw"] or 0) for sample in samples]
                )
                for sample, new_down, new_up in zip(samples, fixed_down, fixed_up):
                    old_down = float(sample["reported_down_raw"] or 0)
                    old_up = float(sample["reported_up_raw"] or 0)
                    if new_down == old_down and new_up == old_up:
                        continue
                    dt = float(sample["dt"] or 0)
                    down_diff = _speed_bytes(old_down, dt) - _speed_bytes(new_down, dt)
                    up_diff = _speed_bytes(old_up, dt) - _speed_bytes(new_up, dt)
                    down_removed += down_diff
                    up_removed += up_diff
                    ts = int(sample["ts"])
                    sample_updates.append((new_down, new_up, ts, mac))
                    minute = ts // 60 * 60
                    day = time.strftime("%Y-%m-%d", time.localtime(ts))
                    for bucket, key in (
                        (minute_delta, (minute, mac)),
                        (day_delta, (day, mac)),
                    ):
                        cell = bucket.setdefault(key, [0, 0])
                        cell[0] += down_diff
                        cell[1] += up_diff
            if not sample_updates:
                return
            self._conn.executemany(
                "UPDATE samples SET reported_down_raw = ?, reported_up_raw = ? "
                "WHERE ts = ? AND mac = ?",
                sample_updates,
            )
            for (minute, mac), (down_diff, up_diff) in minute_delta.items():
                self._conn.execute(
                    "UPDATE minutes SET down_bytes = MAX(0, down_bytes - ?), "
                    "up_bytes = MAX(0, up_bytes - ?) "
                    "WHERE minute_ts = ? AND mac = ?",
                    (down_diff, up_diff, minute, mac),
                )
            for (day, mac), (down_diff, up_diff) in day_delta.items():
                self._conn.execute(
                    "UPDATE days SET down_bytes = MAX(0, down_bytes - ?), "
                    "up_bytes = MAX(0, up_bytes - ?) WHERE day = ? AND mac = ?",
                    (down_diff, up_diff, day, mac),
                )
            self._conn.commit()
            self._hour_at = 0
            self._hour = {}
            log.info(
                "corrected %s stuck samples without rebuilding usage: "
                "download %+.0f bytes, upload %+.0f bytes",
                len(sample_updates),
                -down_removed,
                -up_removed,
            )

    def _revise_stuck_sample(
        self,
        ts: int,
        mac: str,
        dt: float,
        old_down: float,
        old_up: float,
        new_down: float,
        new_up: float,
    ) -> None:
        down_diff = _speed_bytes(old_down, dt) - _speed_bytes(new_down, dt)
        up_diff = _speed_bytes(old_up, dt) - _speed_bytes(new_up, dt)
        minute = ts // 60 * 60
        day = time.strftime("%Y-%m-%d", time.localtime(ts))
        self._conn.execute(
            "UPDATE samples SET reported_down_raw = ?, reported_up_raw = ? "
            "WHERE ts = ? AND mac = ?",
            (new_down, new_up, ts, mac),
        )
        if down_diff or up_diff:
            self._conn.execute(
                "UPDATE minutes SET down_bytes = MAX(0, down_bytes - ?), "
                "up_bytes = MAX(0, up_bytes - ?) WHERE minute_ts = ? AND mac = ?",
                (down_diff, up_diff, minute, mac),
            )
            self._conn.execute(
                "UPDATE days SET down_bytes = MAX(0, down_bytes - ?), "
                "up_bytes = MAX(0, up_bytes - ?) WHERE day = ? AND mac = ?",
                (down_diff, up_diff, day, mac),
            )
            self._hour_at = 0

    def clear(self) -> None:
        with self._lock:
            self._conn.executescript(
                """
                DELETE FROM samples;
                DELETE FROM devices;
                DELETE FROM counter_state;
                DELETE FROM minutes;
                DELETE FROM days;
                DELETE FROM meta;
                """
            )
            self._conn.execute(
                "INSERT INTO meta(key, value) VALUES('speed_scale', ?)",
                (str(SPEED_SCALE),),
            )
            self._conn.commit()
        self._hour_at = 0
        self._hour = {}
        self._reported = {}
        self._unstick_logged = set()

    def meta_interval(self) -> float:
        return float(POLL_FAST)

    def meta_get(self, key: str, default: str = "") -> str:
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM meta WHERE key = ?", (key,)
            ).fetchone()
        return row["value"] if row else default

    def meta_set(self, key: str, value: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO meta(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )
            self._conn.commit()

    def _add_rollup(self, ts: int, mac: str, down_raw: float, up_raw: float, dt: float) -> None:
        down_bytes = int(down_raw * KIB * dt)
        up_bytes = int(up_raw * KIB * dt)
        minute = ts // 60 * 60
        day = time.strftime("%Y-%m-%d", time.localtime(ts))
        self._conn.execute(
            "INSERT INTO minutes(minute_ts, mac, down_bytes, up_bytes, gap) "
            "VALUES(?, ?, ?, ?, ?) ON CONFLICT(minute_ts, mac) DO UPDATE SET "
            "down_bytes = down_bytes + excluded.down_bytes, "
            "up_bytes = up_bytes + excluded.up_bytes, "
            "gap = gap + excluded.gap",
            (minute, mac, down_bytes, up_bytes, dt),
        )
        self._conn.execute(
            "INSERT INTO days(day, mac, down_bytes, up_bytes) VALUES(?, ?, ?, ?) "
            "ON CONFLICT(day, mac) DO UPDATE SET "
            "down_bytes = down_bytes + excluded.down_bytes, "
            "up_bytes = up_bytes + excluded.up_bytes",
            (day, mac, down_bytes, up_bytes),
        )

    def _backfill_rollups(self) -> None:
        with self._lock:
            existing = self._conn.execute("SELECT COUNT(*) AS n FROM minutes").fetchone()["n"]
            if existing:
                return
            rows = self._conn.execute(
                "SELECT ts, mac, reported_down_raw, reported_up_raw FROM samples "
                "WHERE rate_ok = 1 ORDER BY mac, ts"
            ).fetchall()
            last: dict[str, int] = {}
            for row in rows:
                mac = row["mac"]
                ts = int(row["ts"])
                dt = _credited_gap(last.get(mac), ts)
                last[mac] = ts
                self._add_rollup(
                    ts,
                    mac,
                    float(row["reported_down_raw"] or 0),
                    float(row["reported_up_raw"] or 0),
                    dt,
                )
            self._conn.commit()

    def record(
        self,
        ts: int,
        clients: list[dict],
        node_map: dict[str, str],
        interval: float = POLL_FAST,
    ) -> None:
        with self._lock:
            seen = []
            for client in clients:
                mac = _norm_mac(str(client.get("mac") or ""))
                if not mac or client.get("online") is False:
                    continue
                seen.append(mac)
                name = _b64_name(str(client.get("name") or "")) or mac
                node = node_map.get(mac) or ""
                band = _band(
                    str(client.get("connection_type") or ""),
                    str(client.get("wire_type") or ""),
                )
                reported_down = (_as_float(client.get("down_speed")) or 0.0) / SPEED_SCALE
                reported_up = (_as_float(client.get("up_speed")) or 0.0) / SPEED_SCALE
                prior = self._reported.get(mac, [])
                fixed_down = _correct_direction(
                    [item[0] for item in prior] + [reported_down]
                )
                fixed_up = _correct_direction(
                    [item[1] for item in prior] + [reported_up]
                )
                for item, new_down, new_up in zip(prior, fixed_down, fixed_up):
                    old_down = float(item[3])
                    old_up = float(item[4])
                    # A later window must not put a dropped plateau back.
                    new_down = min(new_down, old_down)
                    new_up = min(new_up, old_up)
                    if new_down == old_down and new_up == old_up:
                        continue
                    self._revise_stuck_sample(
                        int(item[2]),
                        mac,
                        float(item[5]),
                        old_down,
                        old_up,
                        new_down,
                        new_up,
                    )
                    item[3] = new_down
                    item[4] = new_up
                down_raw = fixed_down[-1]
                up_raw = fixed_up[-1]
                if (down_raw != reported_down or up_raw != reported_up) and mac not in self._unstick_logged:
                    self._unstick_logged.add(mac)
                    log.info(
                        "ignoring stuck Deco speed for %s down %.0f->%.0f up %.0f->%.0f",
                        name,
                        reported_down,
                        down_raw,
                        reported_up,
                        up_raw,
                    )
                down_now = _first_int(client, DOWN_BYTE_KEYS)
                up_now = _first_int(client, UP_BYTE_KEYS)
                prev = self._conn.execute(
                    "SELECT down_bytes, up_bytes, ts FROM counter_state WHERE mac = ?",
                    (mac,),
                ).fetchone()
                down_delta = 0
                up_delta = 0
                prev_sample = self._conn.execute(
                    "SELECT ts FROM samples WHERE mac = ? ORDER BY ts DESC LIMIT 1",
                    (mac,),
                ).fetchone()
                dt = _credited_gap(
                    int(prev_sample["ts"]) if prev_sample else None,
                    ts,
                    interval,
                )
                # raw router speeds stay in the window so a frozen upload or
                # download can be taken back out of usage once both plateaus
                # have been seen. stored_* is what the database currently has.
                self._reported[mac] = (
                    prior
                    + [[reported_down, reported_up, ts, down_raw, up_raw, dt]]
                )[-20:]
                if prev is not None:
                    gap = max(1.0, ts - int(prev["ts"]))
                    if gap <= MAX_DT:
                        down_got = _delta(prev["down_bytes"], down_now, dt)
                        up_got = _delta(prev["up_bytes"], up_now, dt)
                        if down_got is not None and up_got is not None:
                            down_delta = down_got
                            up_delta = up_got
                            if down_delta > 0 or up_delta > 0:
                                self._conn.execute(
                                    "INSERT INTO meta(key, value) VALUES('counters_ok', '1') "
                                    "ON CONFLICT(key) DO UPDATE SET value = '1'"
                                )
                if down_now is not None or up_now is not None:
                    self._conn.execute(
                        "INSERT INTO counter_state(mac, down_bytes, up_bytes, ts) "
                        "VALUES(?, ?, ?, ?) ON CONFLICT(mac) DO UPDATE SET "
                        "down_bytes = excluded.down_bytes, "
                        "up_bytes = excluded.up_bytes, ts = excluded.ts",
                        (
                            mac,
                            down_now if down_now is not None else (prev["down_bytes"] if prev else 0),
                            up_now if up_now is not None else (prev["up_bytes"] if prev else 0),
                            ts,
                        ),
                    )
                self._conn.execute(
                    "INSERT OR REPLACE INTO samples("
                    "ts, mac, reported_down_raw, reported_up_raw, "
                    "down_delta, up_delta, dt, rate_ok) "
                    "VALUES(?, ?, ?, ?, ?, ?, ?, 1)",
                    (ts, mac, down_raw, up_raw, down_delta, up_delta, dt),
                )
                self._add_rollup(ts, mac, down_raw, up_raw, dt)
                self._conn.execute(
                    "INSERT INTO devices(mac, name, ip, node, band, online, last_seen, "
                    "last_down_raw, last_up_raw) VALUES(?, ?, ?, ?, ?, 1, ?, ?, ?) "
                    "ON CONFLICT(mac) DO UPDATE SET name = excluded.name, ip = excluded.ip, "
                    "node = CASE WHEN excluded.node = '' THEN devices.node ELSE excluded.node END, "
                    "band = excluded.band, online = 1, "
                    "last_seen = excluded.last_seen, "
                    "last_down_raw = excluded.last_down_raw, "
                    "last_up_raw = excluded.last_up_raw",
                    (
                        mac,
                        name,
                        str(client.get("ip") or ""),
                        node,
                        band,
                        ts,
                        down_raw,
                        up_raw,
                    ),
                )
            if seen:
                marks = ",".join("?" for _ in seen)
                self._conn.execute(
                    f"UPDATE devices SET online = 0 WHERE mac NOT IN ({marks})",
                    seen,
                )
            else:
                self._conn.execute("UPDATE devices SET online = 0")
            self._conn.execute("DELETE FROM samples WHERE ts < ?", (ts - 48 * 3600,))
            self._conn.execute(
                "DELETE FROM minutes WHERE minute_ts < ?", (ts - 90 * 86400,)
            )
            self._conn.commit()

    def _usage_map(self, now: int) -> dict[str, dict]:
        from datetime import datetime, timedelta

        moment = datetime.fromtimestamp(now)
        today = moment.date()
        week_start = (today - timedelta(days=today.weekday())).isoformat()
        month_start = today.replace(day=1).isoformat()
        today_key = today.isoformat()
        with self._lock:
            rows = self._conn.execute(
                "SELECT mac, day, down_bytes, up_bytes FROM days"
            ).fetchall()
        out: dict[str, dict] = {}
        for row in rows:
            item = out.setdefault(row["mac"], _empty_usage())
            day = row["day"]
            down = int(row["down_bytes"] or 0)
            up = int(row["up_bytes"] or 0)
            item["all"]["down_bytes"] += down
            item["all"]["up_bytes"] += up
            if day == today_key:
                item["today"]["down_bytes"] += down
                item["today"]["up_bytes"] += up
            if week_start <= day <= today_key:
                item["week"]["down_bytes"] += down
                item["week"]["up_bytes"] += up
            if month_start <= day <= today_key:
                item["month"]["down_bytes"] += down
                item["month"]["up_bytes"] += up
        return out

    def _hour_for(self, now: int) -> dict[str, dict]:
        if now - self._hour_at < 10 and self._hour:
            return self._hour
        with self._lock:
            rows = self._conn.execute(
                "SELECT ts, mac, reported_down_raw, reported_up_raw FROM samples "
                "WHERE ts >= ? AND rate_ok = 1 ORDER BY mac, ts",
                (now - 3600,),
            ).fetchall()
        grouped: dict[str, list[tuple[int, float, float]]] = {}
        for row in rows:
            grouped.setdefault(row["mac"], []).append(
                (
                    int(row["ts"]),
                    _mbps(row["reported_down_raw"] or 0),
                    _mbps(row["reported_up_raw"] or 0),
                )
            )
        start = now - 3600
        out: dict[str, dict] = {}
        for mac, samples in grouped.items():
            out[mac] = {
                "median": round(_median([down + up for _, down, up in samples]), 4),
                "spark": _bucket_spark([(ts, down) for ts, down, _ in samples], start, now, 60),
            }
        self._hour = out
        self._hour_at = now
        return out

    def live(self) -> dict:
        now = int(time.time())
        with self._lock:
            rows = self._conn.execute(
                "SELECT mac, name, ip, node, band, online, last_seen, "
                "last_down_raw, last_up_raw FROM devices WHERE online = 1 "
                "ORDER BY last_down_raw DESC, name"
            ).fetchall()
            sparks = self._conn.execute(
                "SELECT ts, mac, reported_down_raw, reported_up_raw FROM samples "
                "WHERE ts >= ? AND rate_ok = 1 ORDER BY ts",
                (now - 600,),
            ).fetchall()
        by_mac: dict[str, list] = {}
        net: dict[int, list[float]] = {}
        total_raw_down = 0.0
        total_raw_up = 0.0
        for row in sparks:
            by_mac.setdefault(row["mac"], []).append(row)
            if int(row["ts"]) >= now - 300:
                slot = net.setdefault(int(row["ts"]), [0.0, 0.0])
                slot[0] += _mbps(row["reported_down_raw"] or 0)
                slot[1] += _mbps(row["reported_up_raw"] or 0)
        hour_view = self._hour_for(now)
        usage_view = self._usage_map(now)
        devices = []
        total_down = 0.0
        total_up = 0.0
        for row in rows:
            raw_down = row["last_down_raw"] or 0
            raw_up = row["last_up_raw"] or 0
            down = _mbps(raw_down)
            up = _mbps(raw_up)
            total_down += down
            total_up += up
            total_raw_down += raw_down
            total_raw_up += raw_up
            recent = by_mac.get(row["mac"], [])
            recent_series = [
                (int(sample["ts"]), _mbps(sample["reported_down_raw"] or 0))
                for sample in recent
            ]
            recent_usage = [
                _mbps(sample["reported_down_raw"] or 0) + _mbps(sample["reported_up_raw"] or 0)
                for sample in recent
            ]
            hour = hour_view.get(row["mac"], {})
            devices.append(
                {
                    "mac": row["mac"],
                    "name": row["name"] or row["mac"],
                    "ip": row["ip"] or "",
                    "node": row["node"] or "",
                    "band": row["band"] or "",
                    "online": True,
                    "down_mbps": round(down, 4),
                    "up_mbps": round(up, 4),
                    "down_deco": _deco_rate(raw_down),
                    "up_deco": _deco_rate(raw_up),
                    "median10": round(_median(recent_usage), 4),
                    "median_hour": hour.get("median", 0),
                    "spark": _bucket_spark(recent_series, now - 600, now, 60),
                    "hour": hour.get("spark", []),
                    "usage": usage_view.get(row["mac"], _empty_usage()),
                }
            )
        network = [
            [ts, round(vals[0], 4), round(vals[1], 4)]
            for ts, vals in sorted(net.items())
        ]
        return {
            "totals": {
                "down_mbps": round(total_down, 4),
                "up_mbps": round(total_up, 4),
                "down_deco": _deco_rate(total_raw_down),
                "up_deco": _deco_rate(total_raw_up),
            },
            "network": network,
            "devices": devices,
        }

    def history(self, range_key: str, mac: str | None) -> dict:
        window = RANGES[range_key]
        bucket = BUCKETS[range_key]
        start = int(time.time()) - window
        mac_norm = _norm_mac(mac) if mac else None
        with self._lock:
            names = {
                row["mac"]: row["name"]
                for row in self._conn.execute("SELECT mac, name FROM devices")
            }
            if range_key in ("1h", "24h"):
                credits = self._credits_from_samples(start, mac_norm)
            else:
                credits = self._credits_from_minutes(start, mac_norm)
            speed = self._peak_speeds(start, bucket, mac_norm)
        devices: dict[str, dict] = {}
        for ts, item_mac, down_bytes, up_bytes, gap in credits:
            if gap <= 0:
                continue
            item = devices.setdefault(
                item_mac,
                {
                    "mac": item_mac,
                    "name": names.get(item_mac) or item_mac,
                    "points": [],
                    "down_bytes": 0,
                    "up_bytes": 0,
                },
            )
            item["down_bytes"] += int(down_bytes)
            item["up_bytes"] += int(up_bytes)
        for item_mac, points in speed.items():
            item = devices.setdefault(
                item_mac,
                {
                    "mac": item_mac,
                    "name": names.get(item_mac) or item_mac,
                    "points": [],
                    "down_bytes": 0,
                    "up_bytes": 0,
                },
            )
            item["points"] = points
        listed = sorted(devices.values(), key=lambda item: item["down_bytes"], reverse=True)
        return {
            "range": range_key,
            "mac": mac_norm,
            "mode": "reported",
            "totals": {
                "down_bytes": sum(item["down_bytes"] for item in listed),
                "up_bytes": sum(item["up_bytes"] for item in listed),
            },
            "devices": listed,
        }

    def _peak_speeds(self, start: int, bucket: int, mac: str | None) -> dict[str, list]:
        """Fastest second in each chart bucket, split by device at that second.

        Averaging a speed test across the whole bucket hid it: a 180 Mbps
        second became about 90 Mbps on the 1-hour graph and about 10 Mbps
        on the 7-day graph. The stack of these points matches that second.
        """
        now = int(time.time())
        sample_from = max(start, now - 48 * 3600)
        sql = (
            "SELECT ts, mac, reported_down_raw, reported_up_raw FROM samples "
            "WHERE rate_ok = 1 AND ts >= ?"
        )
        args: list = [sample_from]
        if mac:
            sql += " AND mac = ?"
            args.append(mac)
        sql += " ORDER BY ts"
        rows = self._conn.execute(sql, args).fetchall()
        slots: dict[int, dict[int, list]] = {}
        for row in rows:
            ts = int(row["ts"])
            if ts < start:
                continue
            item_mac = row["mac"]
            down = _mbps(row["reported_down_raw"] or 0)
            up = _mbps(row["reported_up_raw"] or 0)
            slot = ts // bucket * bucket
            by_ts = slots.setdefault(slot, {})
            cell = by_ts.get(ts)
            if cell is None:
                cell = [0.0, 0.0, {}]
                by_ts[ts] = cell
            rates = cell[2]
            previous = rates.get(item_mac)
            if previous is None:
                rates[item_mac] = [down, up]
                cell[0] += down
                cell[1] += up
            else:
                if down > previous[0]:
                    cell[0] += down - previous[0]
                    previous[0] = down
                if up > previous[1]:
                    cell[1] += up - previous[1]
                    previous[1] = up
        points: dict[str, list] = {}
        covered: set[int] = set()
        for slot, by_ts in slots.items():
            covered.add(slot)
            down_ts = max(by_ts, key=lambda item: by_ts[item][0])
            up_ts = max(by_ts, key=lambda item: by_ts[item][1])
            seen = set(by_ts[down_ts][2]) | set(by_ts[up_ts][2])
            for item_mac in seen:
                down = by_ts[down_ts][2].get(item_mac, (0.0, 0.0))[0]
                up = by_ts[up_ts][2].get(item_mac, (0.0, 0.0))[1]
                points.setdefault(item_mac, []).append(
                    [slot, round(down, 4), round(up, 4)]
                )
        if start < sample_from:
            sql = (
                "SELECT minute_ts, mac, down_bytes, up_bytes, gap FROM minutes "
                "WHERE minute_ts >= ? AND minute_ts < ?"
            )
            args = [start, sample_from]
            if mac:
                sql += " AND mac = ?"
                args.append(mac)
            best: dict[tuple[str, int], list[float]] = {}
            for row in self._conn.execute(sql, args):
                gap = float(row["gap"] or 0)
                if gap <= 0:
                    continue
                slot = int(row["minute_ts"]) // bucket * bucket
                if slot in covered:
                    continue
                down = int(row["down_bytes"] or 0) * 8 / gap / 1_000_000
                up = int(row["up_bytes"] or 0) * 8 / gap / 1_000_000
                cell = best.setdefault((row["mac"], slot), [0.0, 0.0])
                if down > cell[0]:
                    cell[0] = down
                if up > cell[1]:
                    cell[1] = up
            for (item_mac, slot), (down, up) in best.items():
                points.setdefault(item_mac, []).append(
                    [slot, round(down, 4), round(up, 4)]
                )
        for series in points.values():
            series.sort()
        return points

    def _credits_from_samples(self, start: int, mac: str | None) -> list[tuple]:
        sql = (
            "SELECT ts, mac, reported_down_raw, reported_up_raw FROM samples "
            "WHERE rate_ok = 1 AND ts >= ?"
        )
        args: list = [start - MAX_DT]
        if mac:
            sql += " AND mac = ?"
            args.append(mac)
        sql += " ORDER BY mac, ts"
        rows = self._conn.execute(sql, args).fetchall()
        credits = []
        last: dict[str, int] = {}
        for row in rows:
            item_mac = row["mac"]
            ts = int(row["ts"])
            previous = last.get(item_mac)
            last[item_mac] = ts
            if ts < start:
                continue
            gap = _credited_gap(previous, ts)
            down_raw = float(row["reported_down_raw"] or 0)
            up_raw = float(row["reported_up_raw"] or 0)
            credits.append((ts, item_mac, down_raw * KIB * gap, up_raw * KIB * gap, gap))
        return credits

    def _credits_from_minutes(self, start: int, mac: str | None) -> list[tuple]:
        sql = (
            "SELECT minute_ts, mac, down_bytes, up_bytes, gap FROM minutes "
            "WHERE minute_ts >= ?"
        )
        args: list = [start]
        if mac:
            sql += " AND mac = ?"
            args.append(mac)
        rows = self._conn.execute(sql, args).fetchall()
        return [
            (int(row["minute_ts"]), row["mac"], row["down_bytes"], row["up_bytes"], float(row["gap"] or 0))
            for row in rows
        ]


def _delta(previous, current, dt: float) -> int | None:
    if previous is None or current is None:
        return 0
    previous = int(previous)
    current = int(current)
    change = current - previous
    if change < 0:
        return None
    if dt > 0 and change * 8 / dt / 1_000_000 > MAX_SANE_MBPS:
        return None
    return change


def _stats_have_bytes(stats: dict) -> bool:
    items = []
    if isinstance(stats.get("list"), list):
        items = stats["list"]
    else:
        for key in ("traffic_list", "client_list", "client_list_speed", "stat_list"):
            if isinstance(stats.get(key), list):
                items = stats[key]
                break
    if not items or not isinstance(items[0], dict):
        return False
    keys = DOWN_BYTE_KEYS + UP_BYTE_KEYS
    return any(key in items[0] for key in keys)


def _clients_by_node(client: DecoClient, nodes: list[dict]) -> dict[str, str]:
    found: dict[str, tuple[float, str]] = {}
    for node in nodes:
        label = _short_model(str(node.get("device_model") or ""))
        node_mac = str(node.get("mac") or "")
        if not node_mac:
            continue
        try:
            listed = client.request(
                "admin/client",
                "client_list",
                {"operation": "read", "params": {"device_mac": node_mac}},
            ).get("client_list", [])
        except DecoError as exc:
            log.info("client list for %s failed: %s", label, exc)
            continue
        if not isinstance(listed, list):
            continue
        for item in listed:
            if item.get("online") is False:
                continue
            mac = _norm_mac(str(item.get("mac") or ""))
            if not mac:
                continue
            speed = (_as_float(item.get("down_speed")) or 0) + (_as_float(item.get("up_speed")) or 0)
            previous = found.get(mac)
            if previous is None or speed >= previous[0]:
                found[mac] = (speed, label)
    return {mac: label for mac, (_, label) in found.items()}


def _pct(value) -> int | None:
    number = _as_float(value)
    if number is None:
        return None
    if number > 1:
        number = number / 100
    return int(number * 100)


def _mesh_nodes(nodes: list[dict]) -> list[dict]:
    mesh = []
    for node in nodes:
        mac = str(node.get("mac") or "")
        if not mac:
            continue
        mesh.append(
            {
                "mac": mac,
                "label": _short_model(str(node.get("device_model") or "")),
                "master": str(node.get("role") or "").lower() == "master",
            }
        )
    mesh.sort(key=lambda item: 0 if item["master"] else 1)
    return mesh


def _router_performance(client: DecoClient, nodes: list[dict]) -> list[dict]:
    targets = nodes or [{"mac": "", "label": "Deco", "master": True}]
    readings = []
    for node in targets:
        body: dict = {"operation": "read"}
        if node.get("mac"):
            body["params"] = {"device_mac": node["mac"]}
        try:
            perf = client.request("admin/network", "performance", body)
        except DecoError as exc:
            log.info("performance for %s unavailable: %s", node.get("label"), exc)
            continue
        readings.append(
            {
                "label": node.get("label") or "Deco",
                "cpu": _pct(perf.get("cpu_usage")),
                "mem": _pct(perf.get("mem_usage")),
            }
        )
    return readings


def _node_map(nodes: list[dict]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for index, node in enumerate(nodes, start=1):
        model = _short_model(
            str(node.get("device_model") or node.get("hardware_ver") or "")
        )
        nickname = _b64_name(str(node.get("custom_nickname") or node.get("nickname") or ""))
        label = model if model != "Deco" else (nickname or f"Node {index}")
        mac = _norm_mac(str(node.get("mac") or ""))
        if mac:
            mapping[mac] = label
        mapping[str(index)] = label
        for key in ("device_id", "deco_index", "index", "idx"):
            if node.get(key) is not None:
                mapping[str(node.get(key))] = label
    return mapping


def _merge_counters(clients: list[dict], stats: dict) -> None:
    items = []
    if isinstance(stats.get("list"), list):
        items = stats["list"]
    else:
        for key in ("traffic_list", "client_list", "stat_list"):
            if isinstance(stats.get(key), list):
                items = stats[key]
                break
    by_mac = {}
    for item in items:
        if isinstance(item, dict) and item.get("mac"):
            by_mac[_norm_mac(str(item["mac"]))] = item
    if not by_mac:
        return
    for client in clients:
        extra = by_mac.get(_norm_mac(str(client.get("mac") or "")))
        if not extra:
            continue
        for key, value in extra.items():
            if key == "mac":
                continue
            if key not in client or client.get(key) in (None, ""):
                client[key] = value


class Service:
    def __init__(self) -> None:
        self.store = Store(DB_PATH)
        self._lock = threading.Lock()
        self._client: DecoClient | None = None
        self._wake = threading.Event()
        self.interval = 1
        self.last_error = ""
        self.last_ok = 0
        self.cpu: float | None = None
        self.mem: float | None = None
        self.zero_streak = 0
        self._node_map: dict[str, str] = {}
        self._node_label = ""
        self._logged_shape = False
        self._stats_op = ""
        self._calm = 0
        self._last_perf = 0
        self._last_nodes = 0
        self._mesh_nodes: list[dict] = []
        self.routers: list[dict] = []
        self.auth_blocked = False
        self._load_config()
        _lock_secret()
        saved = SECRET_PATH.read_text(encoding="utf-8") if SECRET_PATH.exists() else ""
        self.password = saved

    def _load_config(self) -> None:
        self.speed_unit = "KiB/s"
        self.username = "admin"
        self.host = DECO_HOST
        if CONFIG_PATH.exists():
            try:
                data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                data = {}
            if data.get("username"):
                self.username = str(data["username"])
            host = str(data.get("host") or "").strip()
            if host:
                self.host = host
        else:
            CONFIG_PATH.write_text(
                json.dumps({"host": DECO_HOST, "username": "admin"}, indent=2),
                encoding="utf-8",
            )

    def scale(self) -> float:
        return KIB * 8 / 1_000_000

    def needs_password(self) -> bool:
        return not self.password

    def set_password(self, password: str) -> None:
        password = password
        if not password:
            raise DecoError("Enter the Deco app password")
        client = DecoClient(self.host, self.username, password)
        with self._lock:
            client.login()
            self._client = client
            self.password = password
            self.last_error = ""
            self.auth_blocked = False
        SECRET_PATH.write_text(password, encoding="utf-8")
        _lock_secret()
        self._wake.set()

    def status(self) -> dict:
        live = self.store.live() if not self.needs_password() else {
            "totals": {"down_mbps": 0, "up_mbps": 0, "down_deco": "0 KB/s", "up_deco": "0 KB/s"},
            "network": [],
            "devices": [],
        }
        return {
            "needs_password": self.needs_password(),
            "ok": not self.last_error,
            "error": self.last_error,
            "updated": self.last_ok,
            "cpu": self.cpu,
            "mem": self.mem,
            "routers": self.routers,
            "interval": self.interval,
            "device_count": len(live["devices"]),
            "counters": self.store.meta_get("counters_ok") == "1",
            "speed_unit": self.speed_unit,
            "zero_streak": self.zero_streak,
            **live,
        }

    def _read_traffic(self, client: DecoClient) -> dict:
        if self._stats_op == "off":
            return {}
        operations = (self._stats_op,) if self._stats_op else ("read", "list")
        for operation in operations:
            try:
                stats = client.request(
                    "admin/client",
                    "traffic_stat",
                    {"operation": operation},
                )
                if not _stats_have_bytes(stats):
                    self._stats_op = "off"
                    log.info("traffic_stat has rates only; history uses those rates")
                    return {}
                self._stats_op = operation
                return stats
            except DecoError as exc:
                if not self._stats_op:
                    log.info("traffic_stat %s unavailable: %s", operation, exc)
        if not self._stats_op:
            self._stats_op = "off"
            log.info("byte counters are not on this firmware; graphs use reported speeds")
        return {}

    def _client_session(self) -> DecoClient:
        if self._client is None or self._client.password != self.password:
            client = DecoClient(self.host, self.username, self.password)
            client.login()
            self._client = client
        return self._client

    def poll_speeds(self) -> None:
        if not self.password or self.auth_blocked:
            return
        started = time.time()
        with self._lock:
            client = self._client_session()
        clients = client.request(
            "admin/client",
            "client_list",
            {"operation": "read", "params": {"device_mac": "default"}},
        ).get("client_list", [])
        if not isinstance(clients, list):
            clients = []
        if not self._logged_shape and clients:
            log.info("client fields: %s", ", ".join(sorted(clients[0].keys())))
            self._logged_shape = True
        ts = int(time.time())
        self.store.record(ts, clients, self._node_map, self.interval)
        self.last_ok = ts
        self.last_error = ""
        busy = any(
            (_as_float(row.get("down_speed")) or 0) > 0
            or (_as_float(row.get("up_speed")) or 0) > 0
            for row in clients
            if row.get("online") is not False
        )
        online = any(row.get("online") is not False for row in clients)
        self.zero_streak = self.zero_streak + 1 if online and not busy else 0
        elapsed = time.time() - started
        if elapsed > self.interval + 0.4:
            log.info("speed poll took %.2fs with interval %ss", elapsed, self.interval)

    def poll_slow(self) -> None:
        if not self.password or self.auth_blocked:
            return
        with self._lock:
            client = self._client_session()
            refresh_nodes = int(time.time()) - self._last_nodes >= 30 or not self._node_map
            if refresh_nodes:
                self._last_nodes = int(time.time())
            mesh = list(self._mesh_nodes)
        if refresh_nodes:
            try:
                nodes = client.request(
                    "admin/device", "device_list", {"operation": "read"}
                ).get("device_list", [])
                if isinstance(nodes, list) and nodes:
                    mesh = _mesh_nodes(nodes)
                    mapping = _clients_by_node(client, nodes)
                    counts: dict[str, int] = {}
                    for label in mapping.values():
                        counts[label] = counts.get(label, 0) + 1
                    label = ", ".join(
                        f"{name} {count}" for name, count in sorted(counts.items())
                    )
                    with self._lock:
                        self._mesh_nodes = mesh
                        self._node_map = mapping
                    if label != self._node_label:
                        self._node_label = label
                        log.info("clients by node: %s", label or "none")
            except DecoError as exc:
                log.info("device list unavailable: %s", exc)
        routers = _router_performance(client, mesh)
        if routers:
            self.routers = routers
            self.cpu = None if routers[0]["cpu"] is None else routers[0]["cpu"] / 100
            self.mem = None if routers[0]["mem"] is None else routers[0]["mem"] / 100

    def _slow_loop(self) -> None:
        while True:
            time.sleep(5)
            try:
                self.poll_slow()
            except DecoError as exc:
                log.info("background refresh failed: %s", exc)
                self._client = None
            except Exception:
                log.exception("background refresh failed")

    def loop(self) -> None:
        threading.Thread(target=self._slow_loop, name="deco-slow", daemon=True).start()
        while True:
            started = time.time()
            try:
                self.poll_speeds()
            except DecoError as exc:
                self.last_error = str(exc)
                self._client = None
                if exc.code == -5002:
                    self.auth_blocked = True
                log.warning("%s", exc)
            except Exception:
                self.last_error = "The collector hit an unexpected error. See server.log."
                self._client = None
                log.exception("poll failed")
            wait = self.interval - (time.time() - started)
            if wait > 0:
                self._wake.wait(wait)
            self._wake.clear()


def _secret_principals() -> set[str]:
    """Users who may read the password file: this user, SYSTEM, and whoever already can."""
    principals = {"NT AUTHORITY\\SYSTEM"}
    user = os.environ.get("USERNAME") or ""
    domain = os.environ.get("USERDOMAIN") or ""
    service_names = {"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"}
    if user and user.upper() not in service_names and not user.endswith("$"):
        principals.add(f"{domain}\\{user}" if domain and "\\" not in user else user)
    listed = subprocess.run(
        ["icacls", str(SECRET_PATH)],
        check=False,
        capture_output=True,
        text=True,
    )
    path_text = str(SECRET_PATH)
    for raw in (listed.stdout or "").splitlines():
        line = raw.strip()
        lowered = line.lower()
        if not line or lowered.startswith("successfully processed") or lowered.startswith("failed processing"):
            continue
        if lowered.startswith(path_text.lower()):
            line = line[len(path_text):].strip()
        if ":(" not in line:
            continue
        principal = line.split(":(")[0].strip()
        if not principal or principal.upper().startswith("BUILTIN\\") or principal.endswith("$"):
            continue
        principals.add(principal)
    return principals


def _lock_secret() -> None:
    if not SECRET_PATH.exists():
        return
    try:
        if os.name != "nt":
            os.chmod(SECRET_PATH, 0o600)
            return
        command = ["icacls", str(SECRET_PATH), "/inheritance:r"]
        for principal in sorted(_secret_principals()):
            command.extend(["/grant:r", f"{principal}:(R,W)"])
        subprocess.run(command, check=False, capture_output=True, text=True)
    except Exception:
        log.exception("could not lock secret.txt")


SERVICE = Service()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:
        return

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/":
            body = (ROOT / "index.html").read_bytes()
            self._send(200, "text/html; charset=utf-8", body)
            return
        if parsed.path == "/api/live":
            self._send_json(SERVICE.status())
            return
        if parsed.path == "/api/history":
            query = parse_qs(parsed.query)
            range_key = (query.get("range") or ["1h"])[0]
            mac = (query.get("mac") or [""])[0].strip() or None
            if range_key not in RANGES:
                self._send_json({"error": "Unknown range"}, 400)
                return
            if SERVICE.needs_password():
                self._send_json(
                    {
                        "range": range_key,
                        "mac": mac,
                        "mode": "reported",
                        "totals": {"down_bytes": 0, "up_bytes": 0},
                        "devices": [],
                    }
                )
                return
            self._send_json(SERVICE.store.history(range_key, mac))
            return
        if parsed.path == "/favicon.ico":
            self._send(204, "image/x-icon", b"")
            return
        self._send(404, "text/plain", b"Not found")

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length") or "0")
        if length > 10_000:
            self._send_json({"ok": False, "error": "Request too large"}, 400)
            return
        try:
            payload = json.loads(self.rfile.read(length).decode() or "{}")
        except json.JSONDecodeError:
            self._send_json({"ok": False, "error": "Expected JSON"}, 400)
            return
        try:
            if parsed.path == "/api/login":
                SERVICE.set_password(str(payload.get("password") or ""))
                self._send_json({"ok": True})
                return
            if parsed.path == "/api/clear":
                SERVICE.store.clear()
                self._send_json({"ok": True})
                return
        except DecoError as exc:
            self._send_json({"ok": False, "error": str(exc)})
            return
        self._send(404, "text/plain", b"Not found")

    def _send_json(self, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload).encode()
        self._send(status, "application/json", body)

    def _send(self, status: int, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    threading.Thread(target=SERVICE.loop, name="poller", daemon=True).start()
    try:
        server = ThreadingHTTPServer((HOST, PORT), Handler)
    except OSError as exc:
        log.error("port %s is already in use (%s); leaving the existing collector running", PORT, exc)
        return
    log.info("listening on http://%s:%s", HOST, PORT)
    server.serve_forever()


if __name__ == "__main__":
    main()
