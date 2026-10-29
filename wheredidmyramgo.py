#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WhereDidMyRAMGo - a premium Windows system monitor with memory-leak hints.

Single-file edition: Python logic, HTML/CSS/JS front-end, Qt shell and unit tests
all live in this one file.

QUICK START (Windows 10 / 11, Python 3.11)
------------------------------------------
    py -3.11 -m venv .venv
    .venv\\Scripts\\activate
    python -m pip install --upgrade pip
    pip install PySide6 psutil
    python wheredidmyramgo.py

OPTIONS
-------
    python wheredidmyramgo.py --test              run the unit tests
    python wheredidmyramgo.py --export-icon a.ico write the app icon (.ico)
    python wheredidmyramgo.py --minimized         start minimised
    python wheredidmyramgo.py --disable-gpu       software rendering (troubleshooting)

BUILD AN EXECUTABLE
-------------------
    pip install pyinstaller
    python wheredidmyramgo.py --export-icon app.ico
    pyinstaller --noconfirm --windowed --name WhereDidMyRAMGo --icon app.ico wheredidmyramgo.py
    (result: dist\\WhereDidMyRAMGo\\WhereDidMyRAMGo.exe)

TROUBLESHOOTING
---------------
* Blank / black window  -> run with --disable-gpu, update your graphics driver.
* "Access denied" rows  -> normal without administrator rights; basic monitoring
                           never needs elevation.
* Logs and data live in %APPDATA%\\WhereDidMyRAMGo (app.log, history.db, settings.json).
* Memory numbers are each process's *working set* (RSS), so shared pages are
  counted once per process and totals can exceed physical RAM; Task Manager's
  default column shows "private working set", which is smaller.
"""
from __future__ import annotations

import argparse
import base64
import ctypes
import json
import logging
import logging.handlers
import math
import os
import re
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from collections import deque
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Deque, Dict, Iterable, List, Optional, Sequence, Tuple

import psutil
from PySide6.QtCore import (QBuffer, QByteArray, QFile, QFileInfo, QIODevice, QObject,
                            QRectF, QThread, QUrl, Qt, Signal, Slot)
from PySide6.QtGui import QAction, QColor, QIcon, QLinearGradient, QPainter, QPixmap
from PySide6.QtWebChannel import QWebChannel
from PySide6.QtWebEngineCore import QWebEnginePage
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtWidgets import (QApplication, QFileIconProvider, QMainWindow, QMenu,
                               QMessageBox, QSystemTrayIcon)

APP_NAME = "WhereDidMyRAMGo"
APP_VERSION = "1.0.0"
MB = 1024 ** 2
GB = 1024 ** 3
IS_WINDOWS = sys.platform == "win32"

log = logging.getLogger("wdmrg")


# ============================================================================
# Utilities
# ============================================================================
def data_dir() -> Path:
    """Return (and create) the per-user data directory."""
    override = os.environ.get("WDMRG_DATA_DIR")
    if override:
        base = Path(override)
    else:
        root = os.environ.get("APPDATA") or str(Path.home() / ".config")
        base = Path(root) / APP_NAME
    base.mkdir(parents=True, exist_ok=True)
    return base


def setup_logging(directory: Path) -> None:
    """Log to a rotating file (and to the console when one exists)."""
    root = logging.getLogger("wdmrg")
    root.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        fh = logging.handlers.RotatingFileHandler(
            directory / "app.log", maxBytes=512 * 1024, backupCount=2, encoding="utf-8")
        fh.setFormatter(fmt)
        root.addHandler(fh)
    except OSError:
        pass
    if sys.stderr is not None:
        sh = logging.StreamHandler(sys.stderr)
        sh.setFormatter(fmt)
        root.addHandler(sh)


def format_bytes(n: Optional[float]) -> str:
    """Human readable size, e.g. 1536 -> '1.5 KB'."""
    if n is None:
        return "-"
    value = float(abs(n))
    units = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while value >= 1024 and i < len(units) - 1:
        value /= 1024
        i += 1
    if i <= 1:
        text = f"{value:.0f}"
    elif i == 2:
        text = f"{value:.0f}" if value >= 100 else f"{value:.1f}"
    else:
        text = f"{value:.2f}"
    return f"{'-' if n < 0 else ''}{text} {units[i]}"


def format_duration(seconds: float) -> str:
    """Human readable duration, e.g. 3725 -> '1h 2m'."""
    s = max(0, int(seconds))
    d, rem = divmod(s, 86400)
    h, rem = divmod(rem, 3600)
    m, sec = divmod(rem, 60)
    if d:
        return f"{d}d {h}h {m}m"
    if h:
        return f"{h}h {m}m"
    if m:
        return f"{m}m {sec}s"
    return f"{sec}s"


def percent(part: float, whole: float, digits: int = 1) -> float:
    """Safe percentage."""
    if not whole:
        return 0.0
    return round(part / whole * 100.0, digits)


def compute_memory_stats(total: int, available: int) -> Dict[str, Any]:
    """Derive used/available/percent from psutil's total and available values."""
    total = max(int(total), 0)
    available = min(max(int(available), 0), total)
    used = total - available
    return {"total": total, "used": used, "available": available,
            "percent": percent(used, total)}


def make_key(pid: int, create_time: float) -> str:
    """Stable process identity: PID + creation time (survives PID reuse)."""
    return f"{int(pid)}:{int(round(float(create_time) * 100))}"


_KEY_RE = re.compile(r"^(\d{1,10}):(\d{1,20})$")


def parse_key(key: Any) -> Optional[Tuple[int, int]]:
    """Validate and split a process key coming from the front-end."""
    if not isinstance(key, str):
        return None
    m = _KEY_RE.match(key)
    return (int(m.group(1)), int(m.group(2))) if m else None


def display_name(name: str) -> str:
    """'chrome.exe' -> 'Chrome'."""
    base = name[:-4] if name.lower().endswith(".exe") else name
    return base[:1].upper() + base[1:] if base.islower() else base


PROTECTED_NAMES = {
    "system", "system idle process", "registry", "memory compression", "memcompression",
    "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe",
    "lsm.exe", "svchost.exe", "dwm.exe", "fontdrvhost.exe", "explorer.exe", "audiodg.exe",
    "sihost.exe", "ctfmon.exe", "securityhealthservice.exe", "msmpeng.exe", "spoolsv.exe",
    "wudfhost.exe", "taskhostw.exe", "startmenuexperiencehost.exe", "shellexperiencehost.exe",
}


def protection_reason(name: str, pid: int) -> Optional[str]:
    """Return a reason string if the process must never be terminated from here."""
    if pid <= 4:
        return "This is a core operating-system process."
    if name.lower() in PROTECTED_NAMES:
        return f"{name} is a critical Windows component. Ending it can crash or log you out of Windows."
    try:
        me = psutil.Process()
        if pid == me.pid:
            return "This is WhereDidMyRAMGo itself."
        if pid in {c.pid for c in me.children(recursive=True)}:
            return "This process belongs to WhereDidMyRAMGo's own interface."
    except psutil.Error:
        pass
    return None


def is_admin() -> bool:
    """True when running with administrator rights on Windows."""
    if not IS_WINDOWS:
        return hasattr(os, "geteuid") and os.geteuid() == 0
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def set_startup(enabled: bool) -> Tuple[bool, str]:
    """Add/remove the per-user Run key. Only ever called after an explicit user toggle."""
    if not IS_WINDOWS:
        return False, "Start with Windows is only available on Windows."
    try:
        import winreg  # type: ignore
        path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_SET_VALUE) as key:
            if enabled:
                if getattr(sys, "frozen", False):
                    cmd = f'"{sys.executable}"'
                else:
                    exe = Path(sys.executable)
                    pyw = exe.with_name("pythonw.exe")
                    runner = pyw if pyw.exists() else exe
                    cmd = f'"{runner}" "{Path(sys.argv[0]).resolve()}"'
                winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, cmd)
            else:
                try:
                    winreg.DeleteValue(key, APP_NAME)
                except FileNotFoundError:
                    pass
        return True, "ok"
    except OSError as exc:
        return False, f"Could not update the startup entry: {exc}"


# ============================================================================
# Settings
# ============================================================================
SETTING_SPECS: Dict[str, tuple] = {
    "theme": ("choice", ("dark", "light"), "dark"),
    "refresh_interval": ("int", 1, 10, 2),
    "history_interval": ("int", 5, 300, 30),
    "retention_days": ("int", 1, 90, 7),
    "leak_window_min": ("int", 5, 240, 30),
    "leak_min_growth_mb": ("int", 10, 4096, 50),
    "ram_warn_pct": ("int", 50, 99, 85),
    "ram_crit_pct": ("int", 51, 100, 95),
    "cpu_warn_pct": ("int", 30, 100, 90),
    "sustained_seconds": ("int", 10, 900, 60),
    "start_with_windows": ("bool", False),
    "notifications": ("bool", False),
    "launch_minimized": ("bool", False),
    "tray_enabled": ("bool", False),
    "close_to_tray": ("bool", False),
    "chart_smooth": ("bool", True),
    "chart_grid": ("bool", True),
    "chart_fill": ("bool", True),
    "perf_range_s": ("choice", (60, 300, 900, 1800, 3600), 300),
}


def _coerce(spec: tuple, value: Any) -> Any:
    kind, default = spec[0], spec[-1]
    try:
        if kind == "bool":
            if isinstance(value, bool):
                return value
            if isinstance(value, (int, float)):
                return bool(value)
            return default
        if kind == "int":
            if isinstance(value, bool):
                return default
            v = int(round(float(value)))
            return max(spec[1], min(spec[2], v))
        if kind == "choice":
            opts = spec[1]
            v = type(opts[0])(value)
            return v if v in opts else default
    except (TypeError, ValueError, OverflowError):
        return default
    return default


def validate_settings(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Return a complete, clamped settings dict. Unknown keys are dropped."""
    out = {k: _coerce(spec, raw.get(k, spec[-1])) for k, spec in SETTING_SPECS.items()}
    if out["ram_crit_pct"] <= out["ram_warn_pct"]:
        out["ram_crit_pct"] = min(100, out["ram_warn_pct"] + 1)
        if out["ram_crit_pct"] <= out["ram_warn_pct"]:
            out["ram_warn_pct"] = out["ram_crit_pct"] - 1
    return out


class Settings:
    """JSON-file backed, validated settings (thread-safe, copy-on-write)."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._data = validate_settings({})
        self.load()

    def load(self) -> None:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                self._data = validate_settings(raw)
        except (OSError, ValueError):
            pass

    def get(self) -> Dict[str, Any]:
        return self._data  # replaced wholesale on update, never mutated

    def _save(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps(self._data, indent=2), encoding="utf-8")
            os.replace(tmp, self.path)
        except OSError as exc:
            log.warning("Could not save settings: %s", exc)

    def update(self, partial: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
        """Apply a partial update; returns (new settings, human-readable notes)."""
        with self._lock:
            merged = dict(self._data)
            merged.update({k: v for k, v in partial.items() if k in SETTING_SPECS})
            new = validate_settings(merged)
            notes = [f"{k} was adjusted to {new[k]}" for k in partial
                     if k in new and new[k] != partial[k] and not isinstance(partial[k], bool)]
            self._data = new
            self._save()
            return new, notes

    def reset(self) -> Dict[str, Any]:
        with self._lock:
            self._data = validate_settings({})
            self._save()
            return self._data


# ============================================================================
# Database
# ============================================================================
class Database:
    """SQLite persistence for system samples and per-process memory history."""

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS system_samples(
        ts INTEGER PRIMARY KEY, ram_pct REAL, cpu_pct REAL, ram_used INTEGER,
        disk_read REAL, disk_write REAL, net_sent REAL, net_recv REAL);
    CREATE TABLE IF NOT EXISTS process_samples(
        key TEXT NOT NULL, ts INTEGER NOT NULL, name TEXT NOT NULL,
        pid INTEGER NOT NULL, rss INTEGER NOT NULL, PRIMARY KEY(key, ts)) WITHOUT ROWID;
    CREATE INDEX IF NOT EXISTS idx_proc_ts ON process_samples(ts);
    """

    def __init__(self, path: Path | str) -> None:
        self.path = str(path)
        self._lock = threading.RLock()
        self._conn: Optional[sqlite3.Connection] = None
        self._open()

    def _open(self) -> None:
        try:
            self._connect()
        except sqlite3.DatabaseError:
            log.exception("Database unreadable; moving it aside and starting fresh")
            try:
                if self._conn:
                    self._conn.close()
                os.replace(self.path, self.path + ".corrupt")
            except OSError:
                pass
            self._connect()

    def _connect(self) -> None:
        self._conn = sqlite3.connect(self.path, check_same_thread=False, timeout=10)
        try:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
        except sqlite3.DatabaseError:
            pass
        self._conn.executescript(self.SCHEMA)
        self._conn.commit()

    @property
    def conn(self) -> sqlite3.Connection:
        assert self._conn is not None, "database is closed"
        return self._conn

    def write_system_samples(self, rows: Iterable[tuple]) -> None:
        with self._lock, self.conn:
            self.conn.executemany(
                "INSERT OR REPLACE INTO system_samples VALUES (?,?,?,?,?,?,?,?)", list(rows))

    def write_process_samples(self, rows: Iterable[tuple]) -> None:
        with self._lock, self.conn:
            self.conn.executemany(
                "INSERT OR REPLACE INTO process_samples VALUES (?,?,?,?,?)", list(rows))

    def prune(self, cutoff_ts: int) -> None:
        with self._lock, self.conn:
            self.conn.execute("DELETE FROM system_samples WHERE ts < ?", (cutoff_ts,))
            self.conn.execute("DELETE FROM process_samples WHERE ts < ?", (cutoff_ts,))

    def clear(self) -> None:
        with self._lock:
            with self.conn:
                self.conn.execute("DELETE FROM system_samples")
                self.conn.execute("DELETE FROM process_samples")
            try:
                self.conn.execute("VACUUM")
            except sqlite3.DatabaseError:
                pass

    def counts(self) -> Tuple[int, int]:
        with self._lock:
            a = self.conn.execute("SELECT COUNT(*) FROM system_samples").fetchone()[0]
            b = self.conn.execute("SELECT COUNT(*) FROM process_samples").fetchone()[0]
        return a, b

    def system_series(self, since: int, max_points: int = 300) -> Dict[str, Any]:
        """Bucketed system history since *since* (unix seconds)."""
        span = max(1, int(time.time()) - since)
        bucket = max(1, span // max_points)
        with self._lock:
            rows = self.conn.execute(
                "SELECT (ts/?)*? AS b, AVG(ram_pct), AVG(cpu_pct) FROM system_samples "
                "WHERE ts >= ? GROUP BY b ORDER BY b", (bucket, bucket, since)).fetchall()
            first = self.conn.execute(
                "SELECT MIN(ts) FROM system_samples WHERE ts >= ?", (since,)).fetchone()[0]
        return {"t": [r[0] for r in rows], "ram": [round(r[1] or 0, 2) for r in rows],
                "cpu": [round(r[2] or 0, 2) for r in rows], "first_ts": first}

    def process_growth(self, since: int, limit: int = 300) -> List[Dict[str, Any]]:
        """First/last/peak memory per process key within the window."""
        out: List[Dict[str, Any]] = []
        with self._lock:
            groups = self.conn.execute(
                "SELECT key, MIN(ts), MAX(ts), COUNT(*), MAX(rss) FROM process_samples "
                "WHERE ts >= ? GROUP BY key HAVING COUNT(*) >= 2 "
                "ORDER BY MAX(rss) DESC LIMIT ?", (since, limit)).fetchall()
            for key, t0, t1, n, peak in groups:
                a = self.conn.execute(
                    "SELECT rss FROM process_samples WHERE key=? AND ts=?", (key, t0)).fetchone()
                b = self.conn.execute(
                    "SELECT rss, name, pid FROM process_samples WHERE key=? AND ts=?",
                    (key, t1)).fetchone()
                if a and b:
                    out.append({"key": key, "t0": t0, "t1": t1, "n": n, "peak": peak,
                                "first": a[0], "last": b[0], "name": b[1], "pid": b[2]})
        return out

    def process_series(self, key: str, since: int, max_points: int = 400) -> Dict[str, Any]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT ts, rss, name FROM process_samples WHERE key=? AND ts>=? ORDER BY ts",
                (key, since)).fetchall()
        if len(rows) > max_points:
            stride = math.ceil(len(rows) / max_points)
            rows = rows[::stride] + ([rows[-1]] if (len(rows) - 1) % stride else [])
        return {"key": key, "name": rows[-1][2] if rows else "",
                "t": [r[0] for r in rows], "v": [r[1] for r in rows]}

    def multi_process_series(self, keys: Sequence[str], since: int,
                             max_points: int = 300) -> Dict[str, Any]:
        """Time-aligned series for several keys (None where a sample is missing)."""
        if not keys:
            return {"t": [], "series": {}}
        span = max(1, int(time.time()) - since)
        bucket = max(1, span // max_points)
        marks = ",".join("?" for _ in keys)
        with self._lock:
            rows = self.conn.execute(
                f"SELECT key, (ts/?)*? AS b, AVG(rss) FROM process_samples "
                f"WHERE ts >= ? AND key IN ({marks}) GROUP BY key, b ORDER BY b",
                (bucket, bucket, since, *keys)).fetchall()
        times = sorted({r[1] for r in rows})
        index = {t: i for i, t in enumerate(times)}
        series: Dict[str, List[Optional[int]]] = {k: [None] * len(times) for k in keys}
        for key, b, avg in rows:
            series[key][index[b]] = int(avg)
        return {"t": times, "series": series}

    def recent_process_samples(self, since: int) -> List[tuple]:
        with self._lock:
            return self.conn.execute(
                "SELECT key, ts, name, pid, rss FROM process_samples WHERE ts >= ? ORDER BY ts",
                (since,)).fetchall()

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.commit()
                    self._conn.close()
                finally:
                    self._conn = None


# ============================================================================
# Memory history + leak detection (pure logic, unit-tested)
# ============================================================================
class ProcessHistory:
    """Bounded in-memory (timestamp, rss) history per stable process key."""

    def __init__(self, max_age_s: float = 1800.0, max_points: int = 2000) -> None:
        self.max_age_s = max_age_s
        self.max_points = max_points
        self._data: Dict[str, Deque[Tuple[float, int]]] = {}
        self._meta: Dict[str, Tuple[str, int]] = {}

    def add(self, ts: float, key: str, name: str, pid: int, rss: int) -> None:
        dq = self._data.get(key)
        if dq is None:
            dq = deque(maxlen=self.max_points)
            self._data[key] = dq
        if dq and ts <= dq[-1][0]:
            return  # ignore duplicate / out-of-order samples
        dq.append((float(ts), int(rss)))
        self._meta[key] = (name, int(pid))

    def prune(self, now: float) -> None:
        cutoff = now - self.max_age_s
        for key in list(self._data):
            dq = self._data[key]
            while dq and dq[0][0] < cutoff:
                dq.popleft()
            if not dq:
                del self._data[key]
                self._meta.pop(key, None)

    def keys(self) -> List[str]:
        return list(self._data)

    def samples(self, key: str) -> List[Tuple[float, int]]:
        return list(self._data.get(key, ()))

    def meta(self, key: str) -> Tuple[str, int]:
        return self._meta.get(key, ("?", 0))

    def clear(self) -> None:
        self._data.clear()
        self._meta.clear()

    def __len__(self) -> int:
        return len(self._data)


@dataclass
class LeakConfig:
    """Thresholds for the sustained-growth rule."""
    window_s: float = 1800.0
    min_samples: int = 6
    min_duration_s: float = 300.0
    min_growth_bytes: int = 50 * MB
    min_growth_pct: float = 15.0
    min_up_ratio: float = 0.8
    min_r2: float = 0.7
    max_gap_factor: float = 3.0

    @classmethod
    def from_settings(cls, cfg: Dict[str, Any]) -> "LeakConfig":
        window = cfg["leak_window_min"] * 60.0
        return cls(window_s=window, min_duration_s=min(300.0, window * 0.5),
                   min_growth_bytes=cfg["leak_min_growth_mb"] * MB)


SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2, "none": 3}


@dataclass
class LeakFinding:
    """Result of analysing one process's memory history."""
    key: str = ""
    name: str = ""
    pid: int = 0
    flagged: bool = False
    severity: str = "none"
    start_bytes: int = 0
    end_bytes: int = 0
    growth_bytes: int = 0
    growth_pct: float = 0.0
    duration_s: float = 0.0
    samples: int = 0
    rate_mb_min: float = 0.0
    up_ratio: float = 0.0
    r2: float = 0.0
    reasons: List[str] = field(default_factory=list)


def linear_fit(xs: Sequence[float], ys: Sequence[float]) -> Tuple[float, float]:
    """Least-squares slope and R^2 of ys over xs."""
    n = len(xs)
    if n < 2:
        return 0.0, 0.0
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    if sxx == 0:
        return 0.0, 0.0
    sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    syy = sum((y - my) ** 2 for y in ys)
    slope = sxy / sxx
    r2 = (sxy * sxy) / (sxx * syy) if syy > 0 else 0.0
    return slope, r2


def contiguous_tail(samples: Sequence[Tuple[float, int]],
                    max_gap_factor: float = 3.0) -> List[Tuple[float, int]]:
    """Latest run of samples with no gap larger than max_gap_factor x the median step.

    Handles missing samples, app restarts and long pauses: only the most recent
    continuous stretch is analysed.
    """
    s = list(samples)
    if len(s) < 3:
        return s
    diffs = [b[0] - a[0] for a, b in zip(s, s[1:])]
    limit = max(statistics.median(diffs) * max_gap_factor, 1.0)
    start = len(s) - 1
    for i in range(len(s) - 1, 0, -1):
        if s[i][0] - s[i - 1][0] > limit:
            break
        start = i - 1
    return s[start:]


def analyze_growth(samples: Sequence[Tuple[float, int]], cfg: LeakConfig,
                   key: str = "", name: str = "", pid: int = 0) -> LeakFinding:
    """Decide whether a (ts, rss) series shows sustained growth ("possible leak").

    A process is only flagged when ALL of these hold over the latest continuous
    window: enough samples and duration; growth above both an absolute and a
    relative threshold; nearly every interval flat-or-rising; each third of the
    window grows; and a straight line explains the trend (R^2).
    High but stable memory is deliberately NOT flagged.
    """
    f = LeakFinding(key=key, name=name, pid=pid)
    s = sorted(samples)
    if not s:
        f.reasons.append("No samples recorded.")
        return f
    last_t = s[-1][0]
    s = [x for x in s if x[0] >= last_t - cfg.window_s]
    s = contiguous_tail(s, cfg.max_gap_factor)
    n = len(s)
    f.samples = n
    f.duration_s = s[-1][0] - s[0][0]
    f.start_bytes, f.end_bytes = s[0][1], s[-1][1]
    if n < cfg.min_samples or f.duration_s < cfg.min_duration_s:
        f.reasons.append(
            f"Not enough continuous data yet ({n} samples over {format_duration(f.duration_s)}; "
            f"need {cfg.min_samples} samples over {format_duration(cfg.min_duration_s)}).")
        return f

    first, last = s[0][1], s[-1][1]
    growth = last - first
    f.growth_bytes = growth
    f.growth_pct = round(growth / first * 100.0, 1) if first > 0 else 0.0
    ys = [float(v) for _, v in s]
    xs = [t - s[0][0] for t, _ in s]
    steps = list(zip(ys, ys[1:]))
    up = sum(1 for a, b in steps if b - a >= -0.01 * a)
    f.up_ratio = round(up / len(steps), 3)
    slope, r2 = linear_fit(xs, ys)
    f.r2 = round(r2, 3)
    f.rate_mb_min = round(slope * 60.0 / MB, 2)
    i1, i2 = n // 3, (2 * n) // 3
    noise = 0.005 * first
    thirds_ok = (ys[i1] - ys[0] > noise and ys[i2] - ys[i1] > noise and ys[-1] - ys[i2] > noise)

    problems: List[str] = []
    if growth < cfg.min_growth_bytes:
        problems.append(f"Net growth ({format_bytes(growth)}) is below the "
                        f"{format_bytes(cfg.min_growth_bytes)} threshold.")
    if f.growth_pct < cfg.min_growth_pct:
        problems.append(f"Relative growth ({f.growth_pct:.0f}%) is below {cfg.min_growth_pct:.0f}%.")
    if f.up_ratio < cfg.min_up_ratio:
        problems.append(f"Memory also dropped often ({f.up_ratio * 100:.0f}% of intervals were "
                        f"flat or rising; need {cfg.min_up_ratio * 100:.0f}%).")
    if not thirds_ok:
        problems.append("Growth was not sustained through the whole window (it plateaued or fell).")
    if r2 < cfg.min_r2 or slope <= 0:
        problems.append(f"The trend is not steady (R²={r2:.2f}).")
    if problems:
        f.reasons = problems
        return f

    f.flagged = True
    f.severity = ("high" if (f.rate_mb_min >= 50 or f.growth_pct >= 100)
                  else "medium" if (f.rate_mb_min >= 10 or f.growth_pct >= 40) else "low")
    f.reasons = [
        f"Memory rose from {format_bytes(first)} to {format_bytes(last)} "
        f"(+{format_bytes(growth)}, +{f.growth_pct:.0f}%) over {format_duration(f.duration_s)} "
        f"across {n} samples.",
        f"Growth was sustained: {f.up_ratio * 100:.0f}% of {len(steps)} sampling intervals were "
        f"flat or rising, and each third of the window grew.",
        f"A straight-line fit explains {r2 * 100:.0f}% of the variation (R²={r2:.2f}), "
        f"averaging about +{f.rate_mb_min:.1f} MB/min.",
        "This is a pattern often seen with memory leaks, but it is not proof of one: "
        "applications also grow legitimately while loading content or filling caches.",
    ]
    return f


def detect_leaks(history: ProcessHistory, cfg: LeakConfig,
                 alive_keys: Optional[set] = None) -> List[LeakFinding]:
    """Analyse every tracked process and return flagged findings, worst first."""
    found: List[LeakFinding] = []
    for key in history.keys():
        if alive_keys is not None and key not in alive_keys:
            continue
        name, pid = history.meta(key)
        f = analyze_growth(history.samples(key), cfg, key, name, pid)
        if f.flagged:
            found.append(f)
    found.sort(key=lambda f: (SEVERITY_RANK[f.severity], -f.growth_bytes))
    return found


# ============================================================================
# Sustained-condition tracking + recommendation engine
# ============================================================================
class SustainedTracker:
    """Tracks for how long boolean conditions have been continuously true."""

    def __init__(self) -> None:
        self._since: Dict[str, float] = {}

    def update(self, flags: Dict[str, bool], now: float) -> Dict[str, float]:
        out: Dict[str, float] = {}
        for name, active in flags.items():
            if active:
                self._since.setdefault(name, now)
                out[name] = now - self._since[name]
            else:
                self._since.pop(name, None)
                out[name] = 0.0
        return out


def health_state(pct: float, warn: float, crit: float) -> str:
    return "critical" if pct >= crit else "elevated" if pct >= warn else "healthy"


class RecommendationEngine:
    """Rules-based, fully local recommendations. Every item explains its reasoning."""

    SEV = {"critical": 0, "warning": 1, "info": 2, "ok": 3}

    def evaluate(self, sysinfo: Dict[str, Any], procs: List[Dict[str, Any]],
                 findings: List[Dict[str, Any]], sustained: Dict[str, float],
                 cfg: Dict[str, Any], disks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        recs: List[Dict[str, Any]] = []
        total = sysinfo["ram_total"]
        pct = sysinfo["ram_pct"]
        warn, crit = cfg["ram_warn_pct"], cfg["ram_crit_pct"]
        caveat = ("Closing applications can free memory, but there is no guarantee it will "
                  "improve performance.")

        if pct >= warn:
            level = crit if pct >= crit else warn
            why = [f"Measured: {format_bytes(sysinfo['ram_used'])} of {format_bytes(total)} "
                   f"physical RAM in use ({pct:.1f}%).",
                   f"Rule: raised when RAM in use reaches your {'critical' if pct >= crit else 'warning'} "
                   f"threshold of {level}% (Settings → Alert thresholds).", caveat]
            if sustained.get("ram", 0) > 0:
                why.insert(1, f"It has stayed above {warn}% for {format_duration(sustained['ram'])}.")
            recs.append({"id": "ram-high", "severity": "critical" if pct >= crit else "warning",
                         "title": f"Your memory usage is above {level}%",
                         "detail": f"{format_bytes(sysinfo['ram_used'])} of {format_bytes(total)} is in use.",
                         "why": why})

        avail = sysinfo["ram_avail"]
        if total and (avail < GB or avail / total < 0.10):
            recs.append({"id": "ram-low-avail",
                         "severity": "critical" if avail < 512 * MB else "warning",
                         "title": "Your system has little available physical memory",
                         "detail": f"Only {format_bytes(avail)} is available.",
                         "why": [f"Measured available physical memory: {format_bytes(avail)} "
                                 f"({percent(avail, total):.1f}% of {format_bytes(total)}).",
                                 "Rule: raised when available memory is under 1 GB or under 10% of total.",
                                 "When RAM runs out Windows moves data to the page file, which can slow "
                                 "things down. " + caveat]})

        groups: Dict[str, Dict[str, Any]] = {}
        for p in procs:
            if p.get("rss") is None:
                continue
            g = groups.setdefault(p["name"].lower(), {"name": p["name"], "rss": 0, "count": 0})
            g["rss"] += p["rss"]
            g["count"] += 1
        ranked = sorted(groups.values(), key=lambda g: g["rss"], reverse=True)

        if ranked and total:
            top = ranked[0]
            gp = percent(top["rss"], total)
            if top["rss"] >= 1.5 * GB or gp >= 15:
                recs.append({"id": "top-app", "severity": "warning" if gp >= 25 else "info",
                             "title": f"{display_name(top['name'])} is currently using {format_bytes(top['rss'])} of RAM",
                             "detail": f"{top['count']} process(es), {gp:.1f}% of physical memory.",
                             "why": [f"Measured: {top['count']} process(es) named {top['name']} have a combined "
                                     f"working set of {format_bytes(top['rss'])} ({gp:.1f}% of RAM).",
                                     "Rule: shown when one application uses at least 1.5 GB or 15% of RAM.",
                                     "High usage alone does not mean something is wrong; it may be doing "
                                     "exactly what you asked. " + caveat]})
            big = [g for g in ranked if g["rss"] >= 500 * MB]
            if len(big) >= 3:
                names = ", ".join(f"{display_name(g['name'])} ({format_bytes(g['rss'])})" for g in big[:3])
                recs.append({"id": "many-big", "severity": "info",
                             "title": "Several applications are consuming significant memory",
                             "detail": names,
                             "why": [f"Measured: {len(big)} applications each use at least 500 MB.",
                                     f"Largest: {names}.",
                                     "Rule: shown when three or more applications exceed 500 MB each."]})

        for f in findings[:3]:
            sev = "warning" if f["severity"] in ("high", "medium") else "info"
            recs.append({"id": f"leak-{f['key']}", "severity": sev,
                         "title": f"{display_name(f['name'])} (PID {f['pid']}) has increased its memory usage "
                                  f"continuously over the last {format_duration(f['duration_s'])}",
                         "detail": f"Possible memory leak: +{format_bytes(f['growth_bytes'])} "
                                   f"(+{f['growth_pct']:.0f}%), about {f['rate_mb_min']:.1f} MB/min.",
                         "why": f["reasons"]})

        cpu_s = sustained.get("cpu", 0)
        if cpu_s >= cfg["sustained_seconds"]:
            busy = sorted((p for p in procs if p.get("cpu")), key=lambda p: p["cpu"], reverse=True)[:1]
            extra = f" Busiest process: {busy[0]['name']} ({busy[0]['cpu']:.0f}%)." if busy else ""
            recs.append({"id": "cpu-high", "severity": "warning",
                         "title": f"CPU usage has stayed above {cfg['cpu_warn_pct']}% for {format_duration(cpu_s)}",
                         "detail": f"Current CPU usage is {sysinfo['cpu_pct']:.0f}%." + extra,
                         "why": [f"Measured: system CPU at or above {cfg['cpu_warn_pct']}% continuously for "
                                 f"{format_duration(cpu_s)}.",
                                 f"Rule: raised after {cfg['sustained_seconds']} s of sustained high CPU."
                                 + extra, "Brief spikes are normal and are ignored."]})

        for d in disks:
            if d["pct"] >= 90:
                recs.append({"id": f"disk-{d['mount']}", "severity": "warning",
                             "title": f"Drive {d['mount']} is nearly full ({d['pct']:.0f}%)",
                             "detail": f"{format_bytes(d['total'] - d['used'])} free of {format_bytes(d['total'])}.",
                             "why": [f"Measured: {format_bytes(d['used'])} of {format_bytes(d['total'])} used.",
                                     "Rule: raised when a local drive is 90% full or more."]})

        if not recs:
            recs.append({"id": "all-ok", "severity": "ok", "title": "No problems detected",
                         "detail": "Memory, CPU and disk usage are within your thresholds.",
                         "why": [f"RAM {pct:.1f}% (warning at {warn}%), CPU {sysinfo['cpu_pct']:.0f}% "
                                 f"(warning at {cfg['cpu_warn_pct']}%).",
                                 "No process showed sustained memory growth."]})
        recs.sort(key=lambda r: self.SEV[r["severity"]])
        return recs


# ============================================================================
# Process scanning + monitor worker thread
# ============================================================================
class ProcessScanner:
    """Snapshot of all running processes. Tolerates processes vanishing mid-scan."""

    def __init__(self) -> None:
        self.ncpu = psutil.cpu_count(logical=True) or 1
        self._objs: Dict[str, psutil.Process] = {}
        self.exe_cache: Dict[str, str] = {}

    def scan(self) -> Tuple[List[Dict[str, Any]], int]:
        out: List[Dict[str, Any]] = []
        objs: Dict[str, psutil.Process] = {}
        denied = 0
        for p in psutil.process_iter():
            try:
                with p.oneshot():
                    pid = p.pid
                    if pid == 0:
                        continue
                    key = make_key(pid, p.create_time())
                    name = p.name()
                    try:
                        rss: Optional[int] = p.memory_info().rss
                    except psutil.AccessDenied:
                        rss = None
                        denied += 1
                    try:
                        cpu: Optional[float] = min(100.0, p.cpu_percent(None) / self.ncpu)
                    except psutil.AccessDenied:
                        cpu = None
                    try:
                        status = p.status()
                    except psutil.AccessDenied:
                        status = "unknown"
            except (psutil.NoSuchProcess, psutil.ZombieProcess):
                continue
            except (psutil.Error, OSError):
                continue
            objs[key] = p
            out.append({"key": key, "pid": pid, "name": name, "rss": rss, "cpu": cpu, "status": status})
        self._objs = objs
        for k in list(self.exe_cache):
            if k not in objs:
                del self.exe_cache[k]
        return out, denied

    def exe_for(self, key: str) -> str:
        if key in self.exe_cache:
            return self.exe_cache[key]
        exe = ""
        p = self._objs.get(key)
        if p is not None:
            try:
                exe = p.exe() or ""
            except (psutil.Error, OSError):
                exe = ""
        self.exe_cache[key] = exe
        return exe


TRACK_MIN_RSS = 16 * MB
MAX_TRACKED = 120
RING_MAX = 3600


class MonitorWorker(QThread):
    """Background sampling loop. All blocking psutil work happens here, never on the UI thread."""

    snapshot = Signal(str)
    alert = Signal(str, str)

    def __init__(self, settings: Settings, db: Database, parent: Optional[QObject] = None) -> None:
        super().__init__(parent)
        self.settings = settings
        self.db = db
        self.scanner = ProcessScanner()
        self.history = ProcessHistory()
        self.tracker = SustainedTracker()
        self.engine = RecommendationEngine()
        self.wants_processes = False
        self.findings: List[Dict[str, Any]] = []
        self.alive_keys: set = set()
        self._stop_evt = threading.Event()
        self._ring_lock = threading.Lock()
        self._ring: Deque[Tuple[float, ...]] = deque(maxlen=RING_MAX)
        self._acc: List[Tuple[float, ...]] = []
        self._prev_io: Optional[Tuple[float, Any, Any]] = None
        self._last_hist = -1e9
        self._last_db = time.monotonic()
        self._last_prune = time.monotonic()
        self._alert_times: Dict[str, float] = {}
        self._seed_history()

    # -- public helpers ------------------------------------------------
    def stop(self) -> None:
        self._stop_evt.set()

    def ring_arrays(self) -> Dict[str, List[float]]:
        with self._ring_lock:
            rows = list(self._ring)
        names = ["t", "ram", "cpu", "dr", "dw", "ns", "nr"]
        return {n: [r[i] for r in rows] for i, n in enumerate(names)}

    def exe_for(self, key: str) -> str:
        return self.scanner.exe_cache.get(key, "")

    def clear_memory_history(self) -> None:
        self.history.clear()
        self.findings = []

    # -- internals -------------------------------------------------------
    def _seed_history(self) -> None:
        cfg = self.settings.get()
        window = cfg["leak_window_min"] * 60
        self.history.max_age_s = window
        try:
            for key, ts, name, pid, rss in self.db.recent_process_samples(int(time.time() - window)):
                self.history.add(ts, key, name, pid, rss)
        except sqlite3.Error:
            log.exception("Could not seed history")

    def run(self) -> None:  # noqa: D401 - QThread entry point
        psutil.cpu_percent(None)  # prime
        self.scanner.scan()       # prime per-process CPU counters
        self._stop_evt.wait(0.4)
        while not self._stop_evt.is_set():
            started = time.monotonic()
            try:
                self._tick()
            except Exception:  # keep the loop alive no matter what
                log.exception("monitor tick failed")
            interval = self.settings.get()["refresh_interval"]
            self._stop_evt.wait(max(0.2, interval - (time.monotonic() - started)))
        try:
            self._flush_acc()
        except Exception:
            log.exception("final flush failed")

    def _collect_system(self, now_mono: float) -> Dict[str, Any]:
        vm = psutil.virtual_memory()
        mem = compute_memory_stats(vm.total, vm.available)
        info: Dict[str, Any] = {
            "ram_total": mem["total"], "ram_used": mem["used"], "ram_avail": mem["available"],
            "ram_pct": mem["percent"], "cpu_pct": round(psutil.cpu_percent(None), 1),
            "cores_logical": psutil.cpu_count(logical=True) or 0,
            "cores_physical": psutil.cpu_count(logical=False) or 0,
            "cpu_mhz": None, "cpu_mhz_max": None,
            "uptime": max(0.0, time.time() - psutil.boot_time()),
            "disk_read_bps": None, "disk_write_bps": None, "net_sent_bps": None, "net_recv_bps": None,
        }
        try:
            fr = psutil.cpu_freq()
            if fr and fr.current:
                info["cpu_mhz"] = round(fr.current)
                info["cpu_mhz_max"] = round(fr.max) if fr.max else None
        except (OSError, NotImplementedError, AttributeError):
            pass
        try:
            dio, nio = psutil.disk_io_counters(), psutil.net_io_counters()
        except (OSError, RuntimeError):
            dio = nio = None
        if self._prev_io is not None:
            t0, d0, n0 = self._prev_io
            dt = now_mono - t0
            if dt > 0:
                if dio is not None and d0 is not None:
                    info["disk_read_bps"] = max(0.0, (dio.read_bytes - d0.read_bytes) / dt)
                    info["disk_write_bps"] = max(0.0, (dio.write_bytes - d0.write_bytes) / dt)
                if nio is not None and n0 is not None:
                    info["net_sent_bps"] = max(0.0, (nio.bytes_sent - n0.bytes_sent) / dt)
                    info["net_recv_bps"] = max(0.0, (nio.bytes_recv - n0.bytes_recv) / dt)
        self._prev_io = (now_mono, dio, nio)
        return info

    @staticmethod
    def _collect_disks() -> List[Dict[str, Any]]:
        disks = []
        try:
            parts = psutil.disk_partitions(all=False)
        except OSError:
            return disks
        for part in parts:
            opts = (part.opts or "").lower()
            if IS_WINDOWS and "fixed" not in opts:
                continue
            try:
                u = psutil.disk_usage(part.mountpoint)
            except (PermissionError, OSError):
                continue
            disks.append({"mount": part.mountpoint.rstrip("\\/") or part.mountpoint,
                          "fstype": part.fstype, "total": u.total, "used": u.used,
                          "pct": round(u.percent, 1)})
        return disks

    def _record_history(self, now: float, procs: List[Dict[str, Any]], cfg: Dict[str, Any]) -> None:
        self.history.max_age_s = cfg["leak_window_min"] * 60
        tracked = set(self.history.keys())
        cands = sorted((p for p in procs if p["rss"] is not None
                        and (p["rss"] >= TRACK_MIN_RSS or p["key"] in tracked)),
                       key=lambda p: p["rss"], reverse=True)[:MAX_TRACKED]
        rows = []
        for p in cands:
            self.history.add(now, p["key"], p["name"], p["pid"], p["rss"])
            rows.append((p["key"], int(now), p["name"], p["pid"], p["rss"]))
        if rows:
            try:
                self.db.write_process_samples(rows)
            except sqlite3.Error:
                log.exception("write_process_samples failed")
        self.history.prune(now)

    def _flush_acc(self) -> None:
        if not self._acc:
            return
        n = len(self._acc)
        avg = [sum(r[i] for r in self._acc) / n for i in range(7)]
        ts = int(self._acc[-1][7])
        self._acc.clear()
        self.db.write_system_samples([(ts, avg[0], avg[1], int(avg[2]), avg[3], avg[4], avg[5], avg[6])])

    def _notify(self, key: str, title: str, text: str, cfg: Dict[str, Any]) -> None:
        if not cfg["notifications"]:
            return
        now = time.time()
        if now - self._alert_times.get(key, 0) >= 1800:
            self._alert_times[key] = now
            self.alert.emit(title, text)

    def _tick(self) -> None:
        cfg = self.settings.get()
        now, mono = time.time(), time.monotonic()
        sysinfo = self._collect_system(mono)
        t0 = time.perf_counter()
        procs, denied = self.scanner.scan()
        scan_ms = round((time.perf_counter() - t0) * 1000, 1)
        self.alive_keys = {p["key"] for p in procs}
        disks = self._collect_disks()

        z = lambda v: v or 0.0  # noqa: E731
        with self._ring_lock:
            self._ring.append((now, sysinfo["ram_pct"], sysinfo["cpu_pct"], z(sysinfo["disk_read_bps"]),
                               z(sysinfo["disk_write_bps"]), z(sysinfo["net_sent_bps"]), z(sysinfo["net_recv_bps"])))
        self._acc.append((sysinfo["ram_pct"], sysinfo["cpu_pct"], sysinfo["ram_used"],
                          z(sysinfo["disk_read_bps"]), z(sysinfo["disk_write_bps"]),
                          z(sysinfo["net_sent_bps"]), z(sysinfo["net_recv_bps"]), now))

        sustained = self.tracker.update({"ram": sysinfo["ram_pct"] >= cfg["ram_warn_pct"],
                                         "cpu": sysinfo["cpu_pct"] >= cfg["cpu_warn_pct"]}, now)

        if mono - self._last_hist >= cfg["history_interval"]:
            self._last_hist = mono
            self._record_history(now, procs, cfg)
            found = detect_leaks(self.history, LeakConfig.from_settings(cfg), self.alive_keys)
            self.findings = [asdict(f) for f in found]
            for f in found:
                if f.severity in ("high", "medium"):
                    self._notify("leak-" + f.key, "Possible memory leak",
                                 f"{display_name(f.name)} has grown by {format_bytes(f.growth_bytes)} "
                                 f"over {format_duration(f.duration_s)}.", cfg)
        else:
            self.findings = [f for f in self.findings if f["key"] in self.alive_keys]

        if mono - self._last_db >= max(10, cfg["refresh_interval"]):
            self._last_db = mono
            try:
                self._flush_acc()
            except sqlite3.Error:
                log.exception("system sample write failed")
        if mono - self._last_prune >= 600:
            self._last_prune = mono
            try:
                self.db.prune(int(now - cfg["retention_days"] * 86400))
            except sqlite3.Error:
                log.exception("prune failed")

        if sysinfo["ram_pct"] >= cfg["ram_crit_pct"] and sustained["ram"] >= 30:
            self._notify("ram-crit", "Memory usage is critical",
                         f"{sysinfo['ram_pct']:.0f}% of RAM has been in use for {format_duration(sustained['ram'])}.", cfg)

        recs = self.engine.evaluate(sysinfo, procs, self.findings, sustained, cfg, disks)

        ranked = sorted(procs, key=lambda p: p["rss"] if p["rss"] is not None else -1, reverse=True)
        top = []
        for p in ranked[:5]:
            if p["rss"] is None:
                continue
            self.scanner.exe_for(p["key"])
            top.append({"k": p["key"], "p": p["pid"], "n": p["name"], "r": p["rss"],
                        "pct": percent(p["rss"], sysinfo["ram_total"], 2)})

        ram_state = health_state(sysinfo["ram_pct"], cfg["ram_warn_pct"], cfg["ram_crit_pct"])
        cpu_state = "elevated" if sysinfo["cpu_pct"] >= cfg["cpu_warn_pct"] else "healthy"
        warnings = []
        if sustained["ram"] >= cfg["sustained_seconds"]:
            warnings.append(f"RAM has been above {cfg['ram_warn_pct']}% for {format_duration(sustained['ram'])}.")
        if sustained["cpu"] >= cfg["sustained_seconds"]:
            warnings.append(f"CPU has been above {cfg['cpu_warn_pct']}% for {format_duration(sustained['cpu'])}.")
        for f in self.findings[:2]:
            warnings.append(f"Possible memory leak: {display_name(f['name'])} (PID {f['pid']}).")
        overall = "critical" if ram_state == "critical" else (
            "elevated" if (ram_state == "elevated" or cpu_state == "elevated"
                           or any(f["severity"] == "high" for f in self.findings)) else "healthy")

        snap: Dict[str, Any] = {
            "ts": now, "interval": cfg["refresh_interval"], "sys": sysinfo, "disks": disks,
            "top": top, "nproc": len(procs),
            "health": {"ram": ram_state, "cpu": cpu_state, "overall": overall, "warnings": warnings},
            "recs": recs, "findings": self.findings,
            "meta": {"scan_ms": scan_ms, "denied": denied},
        }
        if self.wants_processes:
            snap["procs"] = [{"k": p["key"], "p": p["pid"], "n": p["name"], "r": p["rss"],
                              "c": None if p["cpu"] is None else round(p["cpu"], 1), "s": p["status"]}
                             for p in procs]
        self.snapshot.emit(json.dumps(snap, separators=(",", ":"), default=str))


# ============================================================================
# Embedded front-end (HTML / CSS / JavaScript) - rendered by Qt WebEngine, fully offline
# ============================================================================
FRONTEND_CSS = r''':root{--bg:#0B0D12;--card:#141821;--card2:#10141C;--border:#252B38;--text:#E7EAF2;--muted:#8E97AC;--faint:#5C6579;
--purple:#8B5CF6;--blue:#3B82F6;--green:#22C55E;--amber:#F59E0B;--red:#EF4444;--grid:#232938;--hover:#1A2030;
--accent:linear-gradient(135deg,#8B5CF6,#3B82F6);--shadow:0 8px 24px rgba(0,0,0,.35);--r:14px;
--font:Inter,"Segoe UI Variable Text","Segoe UI",system-ui,sans-serif;color-scheme:dark}
[data-theme=light]{--bg:#F3F5FA;--card:#FFFFFF;--card2:#F6F8FC;--border:#DCE1EC;--text:#141826;--muted:#566079;--faint:#8A93A8;
--grid:#E4E8F1;--hover:#EEF1F8;--shadow:0 6px 18px rgba(20,24,38,.08);color-scheme:light}
*{box-sizing:border-box}html,body{height:100%;margin:0}
body{background:var(--bg);color:var(--text);font:13px/1.45 var(--font);-webkit-font-smoothing:antialiased;overflow:hidden}
svg{width:18px;height:18px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round;flex:none}
button{font:inherit;color:inherit;cursor:pointer}
:focus-visible{outline:2px solid var(--blue);outline-offset:2px}
.hidden{display:none!important}
.app{display:grid;grid-template-columns:232px 1fr;height:100vh}
.sidebar{background:var(--card2);border-right:1px solid var(--border);display:flex;flex-direction:column;padding:18px 12px;gap:6px}
.brand{display:flex;align-items:center;gap:10px;padding:2px 8px 18px}
.logo{width:34px;height:34px;border-radius:10px;background:var(--accent);display:grid;place-items:center;color:#fff;box-shadow:0 4px 14px rgba(99,102,241,.4)}
.logo svg{width:20px;height:20px;stroke:#fff}
.brand-name{font-weight:700;font-size:14px;letter-spacing:-.2px;line-height:1.15}
.brand-name b{background:var(--accent);-webkit-background-clip:text;background-clip:text;color:transparent}
.nav{display:flex;flex-direction:column;gap:3px;flex:1}
.nav button{display:flex;align-items:center;gap:11px;border:0;background:none;padding:10px 12px;border-radius:10px;color:var(--muted);font-weight:500;text-align:left;transition:.15s}
.nav button:hover{background:var(--hover);color:var(--text)}
.nav button.active{background:linear-gradient(90deg,rgba(139,92,246,.18),rgba(59,130,246,.10));color:var(--text);box-shadow:inset 2px 0 0 var(--purple)}
.nav button.active svg{color:var(--purple)}
.side-status{display:flex;gap:10px;align-items:center;padding:12px;border:1px solid var(--border);border-radius:12px;background:var(--card)}
.ss-title{font-weight:600;font-size:12.5px}.ss-sub{color:var(--muted);font-size:11.5px}
.dot{width:9px;height:9px;border-radius:50%;background:var(--faint);flex:none}
.dot.healthy,.dot.ok{background:var(--green);box-shadow:0 0 0 4px rgba(34,197,94,.15)}
.dot.elevated{background:var(--amber);box-shadow:0 0 0 4px rgba(245,158,11,.15)}
.dot.critical{background:var(--red);box-shadow:0 0 0 4px rgba(239,68,68,.15)}
.main{display:flex;flex-direction:column;min-width:0;height:100vh}
.topbar{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:16px 26px;border-bottom:1px solid var(--border)}
.titles h1{margin:0;font-size:19px;font-weight:650;letter-spacing:-.3px}.titles p{margin:2px 0 0;color:var(--muted);font-size:12.5px}
.top-actions{display:flex;align-items:center;gap:12px}
.live{display:flex;align-items:center;gap:8px;font-size:12px;color:var(--muted);padding:6px 11px;border:1px solid var(--border);border-radius:99px;background:var(--card);white-space:nowrap}
.live .dot{animation:pulse 2s infinite}.live.stale .dot{background:var(--amber);animation:none;box-shadow:none}
@keyframes pulse{0%,100%{box-shadow:0 0 0 0 rgba(34,197,94,.5)}50%{box-shadow:0 0 0 5px rgba(34,197,94,0)}}
.search{display:flex;align-items:center;gap:8px;background:var(--card);border:1px solid var(--border);border-radius:10px;padding:0 10px;height:36px;width:250px;color:var(--muted);transition:.15s}
.search:focus-within{border-color:var(--purple);box-shadow:0 0 0 3px rgba(139,92,246,.18)}
.search input{flex:1;min-width:0;background:none;border:0;outline:0;color:var(--text);font:inherit}
kbd{font:11px var(--font);border:1px solid var(--border);border-radius:5px;padding:0 5px;color:var(--faint)}
.icon-btn{width:36px;height:36px;display:grid;place-items:center;border-radius:10px;border:1px solid var(--border);background:var(--card);color:var(--muted);transition:.15s}
.icon-btn:hover{color:var(--text);background:var(--hover)}.icon-btn.sm{width:28px;height:28px;border-radius:8px}
.content{flex:1;overflow:auto;padding:22px 26px 30px}
.page{display:none;animation:fade .25s}.page.active{display:block}
@keyframes fade{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:none}}
.grid{display:grid;grid-template-columns:repeat(12,1fr);gap:16px}
.c4{grid-column:span 4}.c5{grid-column:span 5}.c6{grid-column:span 6}.c7{grid-column:span 7}.c8{grid-column:span 8}.c12{grid-column:span 12}
@media(max-width:1180px){.c4,.c5,.c6,.c7,.c8{grid-column:span 12}}
@media(max-width:900px){.app{grid-template-columns:68px 1fr}.brand-name,.nav button span,.side-status>div,.search kbd{display:none}.nav button{justify-content:center}.side-status{justify-content:center}.search{width:170px}.topbar{padding:12px 16px}.content{padding:16px}}
.card{background:linear-gradient(180deg,var(--card),var(--card2));border:1px solid var(--border);border-radius:var(--r);padding:18px;box-shadow:var(--shadow);transition:border-color .2s;min-width:0;position:relative}
.card:hover{border-color:color-mix(in srgb,var(--purple) 35%,var(--border))}
.card h2{margin:0 0 14px;font-size:13px;font-weight:600;display:flex;align-items:center;gap:8px;color:var(--muted);text-transform:uppercase;letter-spacing:.6px}
.card h2 svg{width:16px;height:16px;color:var(--purple)}.card h2 .sp{flex:1}
.card h2 .tools{text-transform:none;letter-spacing:0;font-weight:500}
.skel-wrap{display:none;flex-direction:column;gap:12px}
body.loading .skel-wrap{display:flex}body.loading .real{display:none}
.skel{height:14px;border-radius:7px;background:linear-gradient(90deg,var(--hover) 25%,var(--border) 50%,var(--hover) 75%);background-size:200% 100%;animation:shim 1.3s infinite}
.skel.tall{height:90px}.w60{width:60%}.w90{width:90%}.w40{width:40%}
@keyframes shim{to{background-position:-200% 0}}
.ram-top{display:flex;gap:22px;align-items:center;flex-wrap:wrap}
.ring{position:relative;width:132px;height:132px;flex:none}.ring svg{width:132px;height:132px;transform:rotate(-90deg);stroke-width:10}
.ring .bg{stroke:var(--grid)}.ring .fg{stroke:var(--green);transition:stroke-dashoffset .7s cubic-bezier(.3,.7,.3,1),stroke .3s}
.ring .fg.elevated{stroke:var(--amber)}.ring .fg.critical{stroke:var(--red)}
.ring .mid{position:absolute;inset:0;display:grid;place-content:center;text-align:center}
.ring .mid b{font-size:26px;font-weight:700;letter-spacing:-.5px}.ring .mid small{color:var(--muted);font-size:11px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:14px;flex:1;min-width:220px}
.stat small{display:block;color:var(--muted);font-size:11.5px}.stat b{font-size:17px;font-weight:650;letter-spacing:-.3px}
.chart-wrap{position:relative;height:96px;margin-top:14px}.chart-wrap.big{height:190px;margin-top:6px}.chart-wrap.tall{height:260px}
.chart-wrap canvas{position:absolute;inset:0;width:100%;height:100%}
.chart-tip{position:absolute;pointer-events:none;background:var(--card);border:1px solid var(--border);box-shadow:var(--shadow);border-radius:9px;padding:7px 10px;font-size:11.5px;z-index:5;white-space:nowrap;transform:translateX(-50%)}
.chart-tip .tt{color:var(--muted);margin-bottom:3px}.chart-tip i{display:inline-block;width:8px;height:8px;border-radius:2px;margin-right:6px}
.bigpct{font-size:34px;font-weight:700;letter-spacing:-1px;line-height:1}
.drive{margin-bottom:12px}.drive .row{display:flex;justify-content:space-between;font-size:12.5px;margin-bottom:5px}.drive .row span{color:var(--muted)}
.bar{height:7px;border-radius:99px;background:var(--grid);overflow:hidden}
.bar i{display:block;height:100%;border-radius:99px;background:var(--accent);transition:width .6s cubic-bezier(.3,.7,.3,1)}
.bar i.mid{background:var(--amber)}.bar i.hi{background:var(--red)}
.io{display:flex;gap:18px;margin-top:6px;color:var(--muted);font-size:12px}.io b{color:var(--text);font-weight:600}
.kv{display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px dashed var(--border)}.kv:last-of-type{border:0}
.kv span{color:var(--muted)}
.pill{display:inline-flex;align-items:center;gap:6px;padding:2px 10px;border-radius:99px;font-size:11.5px;font-weight:600;border:1px solid transparent;white-space:nowrap}
.pill.healthy,.pill.ok,.pill.st-running{color:var(--green);background:rgba(34,197,94,.12);border-color:rgba(34,197,94,.25)}
.pill.elevated,.pill.warning,.pill.medium,.pill.st-stopped{color:var(--amber);background:rgba(245,158,11,.12);border-color:rgba(245,158,11,.25)}
.pill.critical,.pill.high{color:var(--red);background:rgba(239,68,68,.12);border-color:rgba(239,68,68,.25)}
.pill.info,.pill.low,.pill.hs{color:var(--blue);background:rgba(59,130,246,.12);border-color:rgba(59,130,246,.25)}
.pill.neutral{color:var(--muted);background:var(--hover);border-color:var(--border)}
.warns{margin-top:10px;display:flex;flex-direction:column;gap:8px}
.warn{display:flex;gap:9px;padding:9px 11px;border-radius:10px;background:rgba(245,158,11,.1);border:1px solid rgba(245,158,11,.22);font-size:12.5px}.warn svg{color:var(--amber);width:16px;height:16px;margin-top:1px}
.okline{display:flex;gap:9px;align-items:center;color:var(--muted);margin-top:10px;font-size:12.5px}.okline svg{color:var(--green);width:16px}
.top-item{display:grid;grid-template-columns:34px 1fr auto;gap:12px;align-items:center;padding:9px 0;border-bottom:1px solid var(--border)}.top-item:last-child{border:0}
.app-ico{width:32px;height:32px;border-radius:9px;background:var(--hover);display:grid;place-items:center;color:var(--muted);overflow:hidden;border:1px solid var(--border)}
.app-ico img{width:22px;height:22px}.app-ico svg{width:17px}
.ti-name{font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.ti-sub{color:var(--muted);font-size:11.5px}
.ti-mem{text-align:right;font-weight:650}.ti-mem small{display:block;color:var(--muted);font-weight:500}
.top-item .bar{grid-column:2/4;height:5px;margin-top:-4px}
.rec{border:1px solid var(--border);border-radius:11px;padding:11px 13px;margin-bottom:10px;background:var(--card2);border-left:3px solid var(--blue)}
.rec.critical{border-left-color:var(--red)}.rec.warning{border-left-color:var(--amber)}.rec.ok{border-left-color:var(--green)}
.rec .rt{font-weight:600}.rec .rd{color:var(--muted);margin-top:2px;font-size:12.5px}
details summary{cursor:pointer;color:var(--blue);font-size:12px;margin-top:7px;user-select:none}
details ul{margin:6px 0 0;padding-left:18px;color:var(--muted);font-size:12.3px}details li{margin:3px 0}
.toolbar{display:flex;align-items:center;gap:12px;margin-bottom:14px;flex-wrap:wrap}.toolbar .sp{flex:1}
.legend{display:flex;gap:14px;color:var(--muted);font-size:12px}.legend i{display:inline-block;width:9px;height:9px;border-radius:3px;margin-right:6px;vertical-align:-1px}
select,input[type=number]{background:var(--card);color:var(--text);border:1px solid var(--border);border-radius:9px;padding:7px 10px;font:inherit}
select:focus,input[type=number]:focus{outline:0;border-color:var(--purple)}
.btn{display:inline-flex;align-items:center;gap:7px;padding:7px 13px;border-radius:9px;border:1px solid var(--border);background:var(--card);font-weight:500;transition:.15s}
.btn:hover{background:var(--hover)}.btn.primary{background:var(--accent);border:0;color:#fff}.btn.danger{color:var(--red);border-color:rgba(239,68,68,.35)}.btn.danger:hover{background:rgba(239,68,68,.1)}
.btn svg{width:15px;height:15px}
.chips{display:inline-flex;gap:4px;background:var(--card);border:1px solid var(--border);border-radius:10px;padding:3px}
.chips button{border:0;background:none;padding:5px 12px;border-radius:7px;color:var(--muted);font-weight:500}.chips button.on{background:var(--accent);color:#fff}
.tablewrap{padding:0;overflow:hidden}
table{width:100%;border-collapse:collapse}
th{position:sticky;top:0;background:var(--card2);text-align:left;font-size:11.5px;text-transform:uppercase;letter-spacing:.5px;color:var(--muted);padding:11px 14px;border-bottom:1px solid var(--border);cursor:pointer;user-select:none;white-space:nowrap}
th:hover{color:var(--text)}th.num,td.num{text-align:right}th .ar{opacity:.0;margin-left:5px}th.sorted .ar{opacity:1;color:var(--purple)}
td{padding:8px 14px;border-bottom:1px solid var(--border);white-space:nowrap}
tbody tr{transition:background .1s}tbody tr:hover{background:var(--hover)}tbody tr:last-child td{border:0}
td.c-name{display:flex;align-items:center;gap:10px;max-width:340px}.pname{overflow:hidden;text-overflow:ellipsis}
td.num{font-variant-numeric:tabular-nums}
.mem{display:flex;align-items:center;justify-content:flex-end;gap:10px}.membar{width:60px;height:5px;border-radius:9px;background:var(--grid);overflow:hidden}.membar i{display:block;height:100%;background:var(--blue)}
.mem.mid .membar i{background:var(--amber)}.mem.hi .membar i{background:var(--red)}.mem.mid b,.mem.hi b{font-weight:650}.mem.hi b{color:var(--red)}.mem.mid b{color:var(--amber)}
.pager{display:flex;align-items:center;justify-content:space-between;padding:10px 14px;border-top:1px solid var(--border);color:var(--muted);font-size:12px}
.pager .btns{display:flex;gap:6px}
.empty{display:flex;flex-direction:column;align-items:center;gap:8px;padding:46px 20px;color:var(--muted);text-align:center}
.empty .eico{width:56px;height:56px;border-radius:16px;display:grid;place-items:center;background:var(--hover);border:1px solid var(--border)}.empty .eico svg{width:26px;height:26px;color:var(--purple)}
.empty b{color:var(--text);font-size:14px}.empty p{margin:0;max-width:420px}
.menu{position:fixed;z-index:50;min-width:210px;background:var(--card);border:1px solid var(--border);border-radius:11px;box-shadow:0 14px 36px rgba(0,0,0,.45);padding:5px;animation:fade .12s}
.menu button{display:flex;gap:10px;align-items:center;width:100%;border:0;background:none;padding:8px 10px;border-radius:7px;text-align:left}
.menu button:hover{background:var(--hover)}.menu button.danger{color:var(--red)}.menu hr{border:0;border-top:1px solid var(--border);margin:5px 0}
.menu button[disabled]{opacity:.4;cursor:not-allowed}
.modal-bd{position:fixed;inset:0;background:rgba(5,7,12,.6);z-index:60;display:grid;place-items:center;padding:20px;animation:fade .15s}
.modal{background:var(--card);border:1px solid var(--border);border-radius:16px;box-shadow:0 24px 60px rgba(0,0,0,.5);width:min(620px,100%);max-height:88vh;overflow:auto;padding:22px}
.modal h3{margin:0 0 4px;font-size:16px}.modal .sub{color:var(--muted);margin-bottom:14px}
.dgrid{display:grid;grid-template-columns:150px 1fr;gap:0}.dgrid>div{padding:7px 0;border-bottom:1px dashed var(--border);word-break:break-word}.dgrid>div:nth-child(odd){color:var(--muted)}
.note{margin-top:14px;padding:10px 12px;border-radius:10px;background:rgba(59,130,246,.1);border:1px solid rgba(59,130,246,.22);color:var(--muted);font-size:12.3px}
.modal .foot{display:flex;gap:8px;justify-content:flex-end;margin-top:16px}
#toasts{position:fixed;right:20px;bottom:20px;display:flex;flex-direction:column;gap:8px;z-index:80}
.toast{background:var(--card);border:1px solid var(--border);border-left:3px solid var(--blue);border-radius:10px;padding:10px 14px;box-shadow:var(--shadow);max-width:380px;animation:fade .2s}
.toast.err{border-left-color:var(--red)}.toast.ok{border-left-color:var(--green)}
.perf-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:16px}@media(max-width:1100px){.perf-grid{grid-template-columns:1fr}}
.tiles{display:flex;gap:18px;flex-wrap:wrap;margin-bottom:6px}.tile small{display:block;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.4px}.tile b{font-size:15px;font-variant-numeric:tabular-nums}
.leg{display:flex;gap:12px;margin-left:auto;font-size:12px;color:var(--muted);text-transform:none;letter-spacing:0;font-weight:500}.leg i{display:inline-block;width:9px;height:9px;border-radius:3px;margin-right:5px}
.finding{border:1px solid var(--border);border-radius:11px;padding:12px 14px;margin-bottom:10px;background:var(--card2)}
.finding .fh{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.finding .fh b{font-size:14px}.finding .fs{color:var(--muted);margin-top:4px}
.finding .fa{margin-top:8px;display:flex;gap:8px}
tr.sel{background:rgba(139,92,246,.1)!important}
.settings{max-width:820px;display:flex;flex-direction:column;gap:16px}
.srow{display:flex;align-items:center;justify-content:space-between;gap:20px;padding:12px 0;border-bottom:1px solid var(--border)}.srow:last-child{border:0;padding-bottom:0}
.srow .sl b{display:block;font-weight:600}.srow .sl span{color:var(--muted);font-size:12.3px}
.srow .ctl{display:flex;align-items:center;gap:10px;flex:none}
.toggle{position:relative;width:42px;height:24px;border-radius:99px;background:var(--grid);border:1px solid var(--border);transition:.2s;padding:0}
.toggle::after{content:"";position:absolute;top:2px;left:2px;width:18px;height:18px;border-radius:50%;background:#fff;transition:.2s;box-shadow:0 1px 3px rgba(0,0,0,.4)}
.toggle.on{background:var(--accent);border-color:transparent}.toggle.on::after{left:20px}
input[type=range]{accent-color:var(--purple);width:160px}.rv{min-width:44px;text-align:right;font-variant-numeric:tabular-nums;color:var(--muted)}
.fatal{margin:80px auto;max-width:520px;text-align:center}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
::-webkit-scrollbar{width:10px;height:10px}::-webkit-scrollbar-thumb{background:var(--border);border-radius:9px;border:2px solid var(--bg)}::-webkit-scrollbar-thumb:hover{background:var(--faint)}
'''

FRONTEND_JS = r'''(() => {
'use strict';
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const ico = (n, cls) => `<svg${cls ? ` class="${cls}"` : ''}><use href="#i-${n}"/></svg>`;
const pad = n => String(n).padStart(2, '0');
const fmtBytes = b => {
  if (b == null || isNaN(b)) return '–';
  const u = ['B','KB','MB','GB','TB']; let i = 0, v = Math.abs(b);
  while (v >= 1024 && i < 4) { v /= 1024; i++; }
  const d = i <= 1 ? 0 : (i === 2 ? (v >= 100 ? 0 : 1) : 2);
  return (b < 0 ? '-' : '') + v.toFixed(d) + ' ' + u[i];
};
const fmtRate = b => b == null ? '–' : fmtBytes(b) + '/s';
const fmtPct = (v, d = 1) => v == null ? '–' : v.toFixed(d) + '%';
const fmtDur = s => { s = Math.max(0, Math.floor(s)); const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
  return d ? `${d}d ${h}h ${m}m` : h ? `${h}h ${m}m` : m ? `${m}m ${s % 60}s` : `${s}s`; };
const fmtClock = (t, long) => { const d = new Date(t * 1000); return long ? `${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}` : `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`; };
const dispName = n => { const b = /\.exe$/i.test(n) ? n.slice(0, -4) : n; return b === b.toLowerCase() ? b.charAt(0).toUpperCase() + b.slice(1) : b; };
const levelOf = pct => pct >= 10 ? 'hi' : pct >= 5 ? 'mid' : '';

const S = { page: 'overview', snap: null, lastSnap: 0, settings: null, info: {}, ring: {t:[],ram:[],cpu:[],dr:[],dw:[],ns:[],nr:[]},
  sort: {k: 'rss', dir: -1}, idx: 0, size: 50, query: '', menuOpen: false, modalOpen: false, dirty: false,
  icons: new Map(), recsSig: '', openRecs: new Set(), histWin: 3600, hist: null, selKey: null, perfRange: 300, perfCharts: {}, histTimer: null };
let bridge = null;
const C = { purple: '#8B5CF6', blue: '#3B82F6', green: '#22C55E', amber: '#F59E0B', red: '#EF4444', cyan: '#06B6D4', pink: '#EC4899', grid: '#232938', muted: '#8E97AC', text: '#E7EAF2' };
const PALETTE = [C.purple, C.blue, C.cyan, C.amber, C.pink, C.green];

const call = (fn, ...args) => new Promise(res => {
  try { bridge[fn](...args, r => { try { res(JSON.parse(r)); } catch (e) { res(r); } }); } catch (e) { res({error: String(e)}); }
});

function toast(msg, kind) { const t = document.createElement('div'); t.className = 'toast ' + (kind || ''); t.textContent = msg; $('#toasts').appendChild(t); setTimeout(() => t.remove(), 5200); }

/* ---------------------------------------------------------------- charts */
class LineChart {
  constructor(canvas, o = {}) {
    this.cv = canvas; this.ctx = canvas.getContext('2d');
    this.o = Object.assign({ yMin: 0, yMax: null, fmt: v => String(v), mini: false, yFit: false, long: false }, o);
    this.t = []; this.series = []; this.hover = -1; this.w = 0; this.h = 0; this.anim = null;
    this.tip = document.createElement('div'); this.tip.className = 'chart-tip hidden'; canvas.parentElement.appendChild(this.tip);
    new ResizeObserver(() => this.resize()).observe(canvas.parentElement);
    canvas.addEventListener('mousemove', e => this.onMove(e));
    canvas.addEventListener('mouseleave', () => { this.hover = -1; this.tip.classList.add('hidden'); this.draw(); });
  }
  resize() {
    const r = this.cv.parentElement.getBoundingClientRect(); if (!r.width || !r.height) return;
    const dpr = window.devicePixelRatio || 1; this.w = r.width; this.h = r.height;
    this.cv.width = Math.round(r.width * dpr); this.cv.height = Math.round(r.height * dpr);
    this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0); this.draw();
  }
  setData(t, series) {
    const prev = this.series, same = prev.length === series.length && this.t.length > 1 && Math.abs(t.length - this.t.length) <= 1;
    this.anim = same ? { t0: performance.now(), from: prev.map(s => { const v = s.values; for (let i = v.length - 1; i >= 0; i--) if (v[i] != null) return v[i]; return null; }) } : null;
    this.t = t; this.series = series; this.draw();
  }
  val(si, i, k) {
    const v = this.series[si].values[i];
    if (this.anim && i === this.t.length - 1 && v != null && this.anim.from[si] != null) return this.anim.from[si] + (v - this.anim.from[si]) * k;
    return v;
  }
  draw() {
    const { ctx, w, h } = this; if (!w || !h) return; ctx.clearRect(0, 0, w, h);
    const mini = this.o.mini, P = mini ? {l: 0, r: 0, t: 4, b: 0} : {l: 54, r: 12, t: 10, b: 22};
    const n = this.t.length;
    ctx.font = '11px ' + getComputedStyle(document.body).fontFamily; ctx.textBaseline = 'middle';
    if (n < 2) { ctx.fillStyle = C.muted; ctx.textAlign = 'center'; ctx.fillText('Collecting data…', w / 2, h / 2); return; }
    let k = 1;
    if (this.anim) { k = Math.min(1, (performance.now() - this.anim.t0) / 380); k = 1 - Math.pow(1 - k, 3); if (k < 1) requestAnimationFrame(() => this.draw()); else this.anim = null; }
    let lo = Infinity, hi = -Infinity;
    this.series.forEach((s, si) => { for (let i = 0; i < n; i++) { const v = s.values[i]; if (v != null) { if (v < lo) lo = v; if (v > hi) hi = v; } } });
    if (!isFinite(lo)) { lo = 0; hi = 1; }
    let ymin = this.o.yMin, ymax = this.o.yMax;
    if (this.o.yFit) { let span = hi - lo; if (span < hi * 0.02) span = hi * 0.02 || 1; ymin = Math.max(0, lo - span * 0.25); ymax = hi + span * 0.25; }
    else if (ymax == null) { ymax = hi * 1.15 || 1; const p = Math.pow(10, Math.floor(Math.log10(ymax))); ymax = Math.ceil(ymax / p * 2) / 2 * p; }
    const x0 = P.l, x1 = w - P.r, y0 = P.t, y1 = h - P.b, t0 = this.t[0], t1 = this.t[n - 1] || t0 + 1;
    const X = i => x0 + (this.t[i] - t0) / ((t1 - t0) || 1) * (x1 - x0), Y = v => y1 - (v - ymin) / ((ymax - ymin) || 1) * (y1 - y0);
    const pr = S.settings || {};
    if (!mini) {
      ctx.fillStyle = C.muted; ctx.textAlign = 'right'; ctx.strokeStyle = C.grid; ctx.lineWidth = 1;
      for (let g = 0; g <= 4; g++) { const v = ymin + (ymax - ymin) * g / 4, y = Math.round(Y(v)) + .5;
        if (pr.chart_grid !== false) { ctx.beginPath(); ctx.moveTo(x0, y); ctx.lineTo(x1, y); ctx.stroke(); }
        ctx.fillText(this.o.fmt(v), x0 - 8, y); }
      ctx.textAlign = 'center';
      for (let g = 0; g <= 3; g++) { const tt = t0 + (t1 - t0) * g / 3, x = x0 + (x1 - x0) * g / 3; ctx.fillText(fmtClock(tt, this.o.long), Math.min(w - 28, Math.max(28, x)), h - 8); }
    }
    this.series.forEach((s, si) => {
      const segs = []; let cur = [];
      for (let i = 0; i < n; i++) { const v = this.val(si, i, k); if (v == null) { if (cur.length) segs.push(cur); cur = []; } else cur.push([X(i), Y(v)]); }
      if (cur.length) segs.push(cur);
      const col = s.color || PALETTE[si % PALETTE.length];
      segs.forEach(sg => {
        if (sg.length === 1) { ctx.fillStyle = col; ctx.beginPath(); ctx.arc(sg[0][0], sg[0][1], 2.5, 0, 6.3); ctx.fill(); return; }
        const path = () => { ctx.beginPath(); ctx.moveTo(sg[0][0], sg[0][1]);
          if (pr.chart_smooth !== false && sg.length > 2) { for (let j = 1; j < sg.length - 1; j++) { const xc = (sg[j][0] + sg[j + 1][0]) / 2, yc = (sg[j][1] + sg[j + 1][1]) / 2; ctx.quadraticCurveTo(sg[j][0], sg[j][1], xc, yc); } ctx.lineTo(sg[sg.length - 1][0], sg[sg.length - 1][1]); }
          else sg.forEach(p => ctx.lineTo(p[0], p[1])); };
        if (pr.chart_fill !== false && s.fill !== false) { path(); ctx.lineTo(sg[sg.length - 1][0], y1); ctx.lineTo(sg[0][0], y1); ctx.closePath();
          const gr = ctx.createLinearGradient(0, y0, 0, y1); gr.addColorStop(0, col + (this.series.length > 1 ? '30' : '55')); gr.addColorStop(1, col + '00'); ctx.fillStyle = gr; ctx.fill(); }
        path(); ctx.strokeStyle = col; ctx.lineWidth = 2; ctx.lineJoin = 'round'; ctx.stroke();
      });
    });
    if (this.hover >= 0 && this.hover < n) {
      const x = X(this.hover); ctx.strokeStyle = C.muted; ctx.globalAlpha = .5; ctx.beginPath(); ctx.moveTo(x, y0); ctx.lineTo(x, y1); ctx.stroke(); ctx.globalAlpha = 1;
      this.series.forEach((s, si) => { const v = s.values[this.hover]; if (v == null) return; ctx.fillStyle = s.color || PALETTE[si % PALETTE.length]; ctx.beginPath(); ctx.arc(x, Y(v), 3.5, 0, 6.3); ctx.fill(); });
    }
  }
  onMove(e) {
    const n = this.t.length; if (n < 2) return;
    const r = this.cv.getBoundingClientRect(), mini = this.o.mini, l = mini ? 0 : 54, rr = mini ? 0 : 12;
    const frac = (e.clientX - r.left - l) / ((r.width - l - rr) || 1), tt = this.t[0] + frac * (this.t[n - 1] - this.t[0]);
    let best = 0, bd = Infinity; for (let i = 0; i < n; i++) { const d = Math.abs(this.t[i] - tt); if (d < bd) { bd = d; best = i; } }
    this.hover = best; this.draw();
    const rows = this.series.map((s, si) => s.values[best] == null ? '' : `<div><i style="background:${s.color || PALETTE[si % PALETTE.length]}"></i>${esc(s.name || '')} <b>${esc(this.o.fmt(s.values[best]))}</b></div>`).join('');
    this.tip.innerHTML = `<div class="tt">${fmtClock(this.t[best], this.o.long)}</div>${rows}`; this.tip.classList.remove('hidden');
    this.tip.style.left = Math.max(70, Math.min(r.width - 70, e.clientX - r.left)) + 'px'; this.tip.style.top = '4px';
  }
}
const mkChart = (id, o) => new LineChart($('#' + id), o);

/* ------------------------------------------------------------ ring buffer */
function pushRing(snap) {
  const s = snap.sys, R = S.ring, z = v => v || 0;
  R.t.push(snap.ts); R.ram.push(s.ram_pct); R.cpu.push(s.cpu_pct); R.dr.push(z(s.disk_read_bps)); R.dw.push(z(s.disk_write_bps)); R.ns.push(z(s.net_sent_bps)); R.nr.push(z(s.net_recv_bps));
  if (R.t.length > 3600) for (const k in R) R[k].shift();
}
function sliceRing(sec) {
  const R = S.ring, n = R.t.length; if (!n) return null; const cut = R.t[n - 1] - sec; let i = 0; while (i < n && R.t[i] < cut) i++;
  const o = {}; for (const k in R) o[k] = R[k].slice(i); return o;
}
const stat = a => { const v = a.filter(x => x != null); if (!v.length) return null; return { cur: v[v.length - 1], avg: v.reduce((x, y) => x + y, 0) / v.length, min: Math.min(...v), max: Math.max(...v) }; };

/* ------------------------------------------------------------------ pages */
const PAGES = {
  overview: ['Overview', 'Live health of your memory, processor and disks'],
  processes: ['Processes', 'Everything running right now, sorted by what you care about'],
  performance: ['Performance', 'Live history with configurable time ranges'],
  history: ['History', 'Per-process memory over time and possible memory leaks'],
  settings: ['Settings', 'Appearance, monitoring, alerts and data'],
};
function nav(page) {
  S.page = page; $$('.page').forEach(p => p.classList.toggle('active', p.id === 'page-' + page));
  $$('.nav button').forEach(b => b.classList.toggle('active', b.dataset.page === page));
  $('#pageTitle').textContent = PAGES[page][0]; $('#pageSub').textContent = PAGES[page][1];
  if (bridge) bridge.set_page(page, () => {});
  clearInterval(S.histTimer);
  if (page === 'history') { loadHistory(); S.histTimer = setInterval(() => { if (!S.modalOpen) loadHistory(true); }, 30000); }
  renderAll(true);
}
function renderAll(force) {
  if (!S.snap) return;
  switch (S.page) {
    case 'overview': renderOverview(); break;
    case 'processes': if (force || !(S.menuOpen || S.modalOpen)) renderProcesses(); break;
    case 'performance': renderPerf(); break;
    case 'history': renderFindings(); break;
  }
  renderSide();
}

/* --------------------------------------------------------------- overview */
let chRam, chCpu;
const ICON_REQ = new Set();
function iconHtml(key) { const u = S.icons.get(key); return u ? `<img src="${u}" alt="">` : ico('app'); }
function wantIcon(key) {
  if (S.icons.has(key) || ICON_REQ.has(key)) return; ICON_REQ.add(key);
  call('get_icon', key).then(r => { ICON_REQ.delete(key); S.icons.set(key, r && r.uri ? r.uri : null);
    if (r && r.uri) $$(`[data-ico="${key}"]`).forEach(e => e.innerHTML = iconHtml(key)); });
}
function renderOverview() {
  const sn = S.snap, s = sn.sys, h = sn.health;
  const fg = $('#ramFg'); fg.style.strokeDashoffset = 326.7 * (1 - s.ram_pct / 100); fg.setAttribute('class', 'fg ' + h.ram);
  $('#ramPct').textContent = s.ram_pct.toFixed(0) + '%'; $('#ramTotal').textContent = fmtBytes(s.ram_total); $('#ramUsed').textContent = fmtBytes(s.ram_used); $('#ramAvail').textContent = fmtBytes(s.ram_avail);
  $('#cpuPct').textContent = s.cpu_pct.toFixed(0) + '%';
  $('#cpuCores').textContent = s.cores_physical ? `${s.cores_physical} cores / ${s.cores_logical} threads` : `${s.cores_logical} threads`;
  $('#cpuFreq').textContent = s.cpu_mhz ? (s.cpu_mhz / 1000).toFixed(2) + ' GHz' : 'n/a';
  const r5 = sliceRing(300), r2 = sliceRing(120);
  chRam.setData(r5.t, [{ name: 'RAM', values: r5.ram, color: C.purple }]); chCpu.setData(r2.t, [{ name: 'CPU', values: r2.cpu, color: C.blue }]);
  $('#drives').innerHTML = sn.disks.length ? sn.disks.map(d => `<div class="drive"><div class="row"><b>${esc(d.mount)}</b><span>${fmtBytes(d.used)} of ${fmtBytes(d.total)} · ${d.pct.toFixed(0)}%</span></div><div class="bar"><i class="${d.pct >= 90 ? 'hi' : d.pct >= 75 ? 'mid' : ''}" style="width:${d.pct}%"></i></div></div>`).join('') : `<div class="okline">${ico('info')}No local drives were reported.</div>`;
  $('#dRead').textContent = fmtRate(s.disk_read_bps); $('#dWrite').textContent = fmtRate(s.disk_write_bps);
  $('#hProcs').textContent = sn.nproc; $('#hUp').textContent = fmtDur(s.uptime);
  const lab = { healthy: 'Healthy', elevated: 'Elevated', critical: 'Critical' };
  $('#hRam').innerHTML = `<span class="pill ${h.ram}">${lab[h.ram]} · ${s.ram_pct.toFixed(0)}%</span>`; $('#hCpu').innerHTML = `<span class="pill ${h.cpu}">${lab[h.cpu]} · ${s.cpu_pct.toFixed(0)}%</span>`;
  $('#hWarn').innerHTML = h.warnings.length ? `<div class="warns">${h.warnings.map(w => `<div class="warn">${ico('alert')}<span>${esc(w)}</span></div>`).join('')}</div>` : `<div class="okline">${ico('check')}No sustained high usage detected.</div>`;
  $('#topList').innerHTML = sn.top.map(t => { wantIcon(t.k); return `<div class="top-item"><div class="app-ico" data-ico="${esc(t.k)}">${iconHtml(t.k)}</div><div style="min-width:0"><div class="ti-name">${esc(t.n)}</div><div class="ti-sub">PID ${t.p}</div></div><div class="ti-mem">${fmtBytes(t.r)}<small>${t.pct.toFixed(1)}% of RAM</small></div><div class="bar"><i class="${levelOf(t.pct)}" style="width:${Math.min(100, t.pct * 2.5)}%"></i></div></div>`; }).join('') || `<div class="empty"><p>No process memory data yet.</p></div>`;
  const sig = JSON.stringify(sn.recs.map(r => [r.id, r.title, r.detail]));
  if (sig !== S.recsSig) { S.recsSig = sig; renderRecs(); }
}
function renderRecs() {
  $('#recs').innerHTML = S.snap.recs.map(r => `<div class="rec ${r.severity}"><div class="rt">${esc(r.title)}</div><div class="rd">${esc(r.detail)}</div>
    <details data-id="${esc(r.id)}" ${S.openRecs.has(r.id) ? 'open' : ''}><summary>How was this generated?</summary><ul>${r.why.map(w => `<li>${esc(w)}</li>`).join('')}</ul></details></div>`).join('');
}
function renderSide() {
  const sn = S.snap; if (!sn) return; const h = sn.health.overall;
  const t = { healthy: ['System healthy', 'Usage within your limits'], elevated: ['Elevated usage', 'Check Overview for details'], critical: ['Critical memory usage', 'Check Overview for details'] }[h];
  $('#sideStatus').innerHTML = `<span class="dot ${h}"></span><div><div class="ss-title">${t[0]}</div><div class="ss-sub">${t[1]}</div></div>`;
}

/* -------------------------------------------------------------- processes */
function procRows() {
  const total = S.snap.sys.ram_total, q = S.query.trim().toLowerCase();
  let rows = (S.snap.procs || []).map(p => ({ key: p.k, pid: p.p, name: p.n, rss: p.r, pct: p.r == null ? null : p.r / total * 100, cpu: p.c, status: p.s }));
  if (q) rows = rows.filter(p => p.name.toLowerCase().includes(q) || String(p.pid).includes(q) || p.status.toLowerCase().includes(q));
  const { k, dir } = S.sort;
  rows.sort((a, b) => { let x = k === 'pct' ? a.rss : a[k], y = k === 'pct' ? b.rss : b[k];
    if (x == null && y == null) return 0; if (x == null) return 1; if (y == null) return -1;
    return (typeof x === 'string' ? x.localeCompare(y) : x - y) * dir; });
  return rows;
}
const STATUS = { running: ['Running', 'st-running'], stopped: ['Suspended', 'st-stopped'], sleeping: ['Sleeping', 'neutral'], idle: ['Idle', 'neutral'] };
function renderProcesses() {
  if (!S.snap.procs) { $('#procBody').innerHTML = Array(8).fill('<tr><td colspan="7"><div class="skel"></div></td></tr>').join(''); return; }
  const rows = procRows(), n = rows.length, pages = Math.max(1, Math.ceil(n / S.size)); if (S.idx >= pages) S.idx = pages - 1;
  const from = S.idx * S.size, view = rows.slice(from, from + S.size);
  $$('#procHead th[data-k]').forEach(th => { const on = th.dataset.k === S.sort.k; th.classList.toggle('sorted', on); th.querySelector('.ar').textContent = on ? (S.sort.dir > 0 ? '▲' : '▼') : '▼'; });
  $('#procCount').textContent = `${n} process${n === 1 ? '' : 'es'}${S.query ? ' match' : ' running'}`;
  $('#procBody').innerHTML = view.map(p => { const lv = p.pct == null ? '' : levelOf(p.pct), st = STATUS[p.status] || [p.status.charAt(0).toUpperCase() + p.status.slice(1), 'neutral'];
    return `<tr data-key="${esc(p.key)}"><td class="c-name"><span class="app-ico">${ico('app')}</span><span class="pname" title="${esc(p.name)}">${esc(p.name)}</span></td><td class="num">${p.pid}</td>
    <td class="num">${p.rss == null ? '<span style="color:var(--faint)" title="Access denied without administrator rights">Restricted</span>' : `<div class="mem ${lv}"><div class="membar"><i style="width:${Math.min(100, p.pct * 5)}%"></i></div><b>${fmtBytes(p.rss)}</b></div>`}</td>
    <td class="num">${p.pct == null ? '–' : p.pct.toFixed(2) + '%'}</td><td class="num">${p.cpu == null ? '–' : p.cpu.toFixed(1) + '%'}</td><td><span class="pill ${st[1]}">${esc(st[0])}</span></td>
    <td><button class="icon-btn sm" data-act="menu" aria-label="Actions for ${esc(p.name)}">${ico('more')}</button></td></tr>`; }).join('');
  $('#procEmpty').innerHTML = n ? '' : `<div class="empty"><div class="eico">${ico('search')}</div><b>No matching processes</b><p>Nothing matches “${esc(S.query)}”. Try a process name or PID.</p><button class="btn" id="clrSearch">Clear search</button></div>`;
  const cs = $('#clrSearch'); if (cs) cs.onclick = () => { $('#search').value = ''; S.query = ''; renderProcesses(); };
  $('#pagerInfo').textContent = n ? `Showing ${from + 1}–${from + view.length} of ${n}` : ''; $('#pgPrev').disabled = S.idx === 0; $('#pgNext').disabled = S.idx >= pages - 1;
}
function closeMenu() { $('#menu').classList.add('hidden'); S.menuOpen = false; }
function openMenu(btn, key) {
  const m = $('#menu'), r = btn.getBoundingClientRect();
  m.innerHTML = `<button data-m="details">${ico('info')}Process details</button><button data-m="folder">${ico('folder')}Open file location</button><button data-m="hist">${ico('chart')}Memory history</button><hr><button data-m="end" class="danger">${ico('stop')}End process…</button>`;
  m.dataset.key = key; m.classList.remove('hidden'); S.menuOpen = true;
  m.style.left = Math.max(8, Math.min(innerWidth - 226, r.right - 210)) + 'px'; m.style.top = Math.min(innerHeight - 190, r.bottom + 4) + 'px';
}
function openModal(html) { $('#modal').innerHTML = html; $('#modalBd').classList.remove('hidden'); S.modalOpen = true; }
function closeModal() { $('#modalBd').classList.add('hidden'); S.modalOpen = false; if (S.page === 'processes') renderProcesses(); }
async function showDetails(key) {
  openModal('<h3>Loading…</h3><div class="skel w90"></div>');
  const d = await call('get_process_details', key);
  if (!d || d.error || d.ok === false) { openModal(`<h3>Details unavailable</h3><p class="sub">${esc((d && (d.message || d.error)) || 'Unknown error')}</p><div class="foot"><button class="btn" data-close>Close</button></div>`); return; }
  const rows = [['Name', d.name], ['PID', d.pid], ['Status', d.status], ['Started', d.created], ['Memory (working set)', fmtBytes(d.rss)], ['Private memory', d.uss == null ? 'Unavailable' : fmtBytes(d.uss)], ['Virtual memory', fmtBytes(d.vms)], ['Threads', d.threads ?? 'Unavailable'], ['Handles', d.handles ?? 'Unavailable'],
    ['Parent', d.parent || 'Unavailable'], ['User', d.user || 'Unavailable'], ['Executable', d.exe || 'Unavailable'], ['Command line', d.cmdline || 'Unavailable']];
  const hint = d.restricted ? `<div class="note">${ico('info')} Some fields are unavailable because Windows restricts access to this process. Running WhereDidMyRAMGo as administrator would reveal more, but it is never required for basic monitoring.</div>` : '';
  openModal(`<h3>${esc(d.name)}</h3><div class="sub">Process ${d.pid}</div><div class="dgrid">${rows.map(r => `<div>${esc(r[0])}</div><div>${esc(r[1])}</div>`).join('')}</div>${hint}
    <div class="note">High memory use alone does not mean a process is misbehaving or harmful.</div><div class="foot"><button class="btn" data-open="${esc(key)}">${ico('folder')}Open file location</button><button class="btn primary" data-close>Close</button></div>`);
}
async function openFolder(key) { const r = await call('open_file_location', key); toast(r.message || (r.ok ? 'Opened.' : 'Could not open.'), r.ok ? 'ok' : 'err'); }
async function endProcess(key) { const r = await call('terminate_process', key); if (r && r.message) toast(r.message, r.ok ? 'ok' : (r.cancelled ? '' : 'err')); }

/* ------------------------------------------------------------ performance */
const PERF = [
  { id: 'ram', title: 'Memory usage', icon: 'ram', series: [['RAM', 'ram', C.purple]], fmt: v => v.toFixed(1) + '%', yMax: 100 },
  { id: 'cpu', title: 'CPU usage', icon: 'cpu', series: [['CPU', 'cpu', C.blue]], fmt: v => v.toFixed(1) + '%', yMax: 100 },
  { id: 'disk', title: 'Disk activity', icon: 'disk', series: [['Read', 'dr', C.cyan], ['Write', 'dw', C.amber]], fmt: fmtRate },
  { id: 'net', title: 'Network', icon: 'performance', series: [['Send', 'ns', C.pink], ['Receive', 'nr', C.green]], fmt: fmtRate },
];
function buildPerf() {
  const RANGES = [[60, '1 min'], [300, '5 min'], [900, '15 min'], [1800, '30 min'], [3600, '1 hour']];
  $('#rangeChips').innerHTML = RANGES.map(r => `<button data-r="${r[0]}" class="${r[0] === S.perfRange ? 'on' : ''}">${r[1]}</button>`).join('');
  $('#perfGrid').innerHTML = PERF.map(p => `<div class="card"><h2>${ico(p.icon)}${p.title}<span class="leg">${p.series.map(s => `<span><i style="background:${s[2]}"></i>${s[0]}</span>`).join('')}</span></h2><div class="tiles" id="tl-${p.id}"></div><div class="chart-wrap big"><canvas id="pc-${p.id}"></canvas></div></div>`).join('');
  PERF.forEach(p => { S.perfCharts[p.id] = mkChart('pc-' + p.id, { fmt: p.fmt, yMax: p.yMax ?? null }); });
}
function renderPerf() {
  const d = sliceRing(S.perfRange); if (!d) return;
  $('#perfNote').textContent = `${d.t.length} samples · every ${S.snap.interval}s`;
  PERF.forEach(p => {
    S.perfCharts[p.id].setData(d.t, p.series.map(s => ({ name: s[0], values: d[s[1]], color: s[2] })));
    $('#tl-' + p.id).innerHTML = p.series.map(s => { const st = stat(d[s[1]]); if (!st) return ''; const f = p.fmt;
      return `<div class="tile"><small>${p.series.length > 1 ? s[0] + ' · ' : ''}Current</small><b>${f(st.cur)}</b></div><div class="tile"><small>Avg</small><b>${f(st.avg)}</b></div><div class="tile"><small>Min</small><b>${f(st.min)}</b></div><div class="tile"><small>Max</small><b>${f(st.max)}</b></div>`; }).join('<div style="width:1px;background:var(--border)"></div>');
  });
}

/* ---------------------------------------------------------------- history */
let chGrow, chSys;
const TAGS = { leak: ['Possible memory leak', 'critical'], growing: ['Growing', 'warning'], high_stable: ['High, but stable', 'hs'], stable: ['Stable', 'neutral'] };
function renderFindings() {
  const f = S.snap ? S.snap.findings : [], cfg = S.settings;
  $('#leakNote').textContent = `Window: last ${cfg.leak_window_min} min · sampled every ${cfg.history_interval}s`;
  $('#findings').innerHTML = f.length ? f.map(x => `<div class="finding"><div class="fh"><b>${esc(dispName(x.name))}</b><span style="color:var(--muted)">PID ${x.pid}</span><span class="pill ${x.severity === 'high' ? 'critical' : x.severity === 'medium' ? 'warning' : 'info'}">Possible memory leak · ${esc(x.severity)}</span></div>
    <div class="fs">+${fmtBytes(x.growth_bytes)} (+${x.growth_pct.toFixed(0)}%) in ${fmtDur(x.duration_s)} · about ${x.rate_mb_min.toFixed(1)} MB/min · now ${fmtBytes(x.end_bytes)}</div>
    <details><summary>Why was this flagged?</summary><ul>${x.reasons.map(r => `<li>${esc(r)}</li>`).join('')}</ul></details>
    <div class="fa"><button class="btn" data-hist="${esc(x.key)}">${ico('chart')}Show history</button><button class="btn" data-detail="${esc(x.key)}">${ico('info')}Details</button></div></div>`).join('')
    : `<div class="empty"><div class="eico">${ico('shield')}</div><b>No sustained memory growth detected</b><p>A process is only flagged after its memory has grown steadily across at least ${Math.round(Math.min(300, cfg.leak_window_min * 30) / 60 * 10) / 10} minutes of continuous samples. Large-but-steady processes are not flagged.</p></div>`;
}
async function loadHistory(quiet) {
  const r = await call('get_history', S.histWin); if (!r || r.error) { if (!quiet) toast('Could not load history', 'err'); return; }
  S.hist = r; const sys = r.system;
  chSys.setData(sys.t, [{ name: 'RAM', values: sys.ram, color: C.purple }, { name: 'CPU', values: sys.cpu, color: C.blue }]); chSys.o.long = S.histWin > 86400;
  $('#histNote').textContent = r.coverage_s > 0 ? `Data covers ${fmtDur(r.coverage_s)} of the selected window` : 'No data recorded for this window yet';
  if (!S.selKey) drawGrowChart();
  const rows = r.procs;
  $('#growBody').innerHTML = rows.map(p => { const tg = TAGS[p.tag];
    return `<tr data-gkey="${esc(p.key)}" class="${p.key === S.selKey ? 'sel' : ''}"><td class="c-name"><span class="pname">${esc(p.name)}</span><span style="color:var(--muted)">${p.alive ? '' : '(exited)'} PID ${p.pid}</span></td><td class="num">${fmtBytes(p.last)}</td>
    <td class="num" style="color:${p.growth > 0 ? 'var(--amber)' : 'var(--muted)'}">${p.growth >= 0 ? '+' : ''}${fmtBytes(p.growth)} (${p.growth_pct >= 0 ? '+' : ''}${p.growth_pct.toFixed(0)}%)</td><td class="num">${p.rate >= 0 ? '+' : ''}${p.rate.toFixed(1)} MB/min</td><td class="num">${fmtBytes(p.peak)}</td><td><span class="pill ${tg[1]}">${tg[0]}</span></td></tr>`; }).join('');
  $('#growEmpty').innerHTML = rows.length ? '' : `<div class="empty"><div class="eico">${ico('history')}</div><b>Not enough history yet</b><p>WhereDidMyRAMGo records process memory every ${S.settings.history_interval} seconds while it runs. Leave it open and growth trends will appear here.</p></div>`;
}
function drawGrowChart() {
  const r = S.hist; if (!r) return; const ts = r.top_series, keys = Object.keys(ts.series);
  const names = {}; r.procs.forEach(p => names[p.key] = p);
  const series = keys.map((k, i) => ({ name: names[k] ? `${names[k].name} (${names[k].pid})` : k, values: ts.series[k], color: PALETTE[i % PALETTE.length], fill: false }));
  chGrow.o.long = S.histWin > 86400; chGrow.setData(ts.t, series);
  $('#growLeg').innerHTML = series.map(s => `<span><i style="background:${s.color}"></i>${esc(s.name)}</span>`).join(''); $('#growTitle').textContent = 'Memory over time · largest increases'; $('#growReset').classList.add('hidden');
}
async function focusProcess(key) {
  S.selKey = key; const r = await call('get_process_history', key, S.histWin); if (!r || r.error) return;
  const col = C.purple; chGrow.o.long = S.histWin > 86400; chGrow.setData(r.t, [{ name: r.name, values: r.v, color: col }]);
  $('#growLeg').innerHTML = `<span><i style="background:${col}"></i>${esc(r.name)}</span>`; $('#growTitle').textContent = 'Memory over time · ' + dispName(r.name); $('#growReset').classList.remove('hidden');
  $$('#growBody tr').forEach(tr => tr.classList.toggle('sel', tr.dataset.gkey === key));
}

/* --------------------------------------------------------------- settings */
const GROUPS = [
  ['Appearance', [['theme', 'Theme', 'Switch between light and dark', 'select', [['dark', 'Dark'], ['light', 'Light']]], ['chart_smooth', 'Smooth chart lines', 'Curve lines between samples', 'toggle'], ['chart_grid', 'Chart grid lines', 'Show horizontal guides', 'toggle'], ['chart_fill', 'Fill under lines', 'Gradient area beneath each line', 'toggle']]],
  ['Monitoring', [['refresh_interval', 'Refresh interval', 'How often live data is sampled', 'select', [[1, '1 second'], [2, '2 seconds'], [3, '3 seconds'], [5, '5 seconds'], [10, '10 seconds']]],
    ['history_interval', 'History sampling', 'How often process memory is recorded for leak detection', 'select', [[10, '10 seconds'], [15, '15 seconds'], [30, '30 seconds'], [60, '1 minute'], [120, '2 minutes'], [300, '5 minutes']]],
    ['leak_window_min', 'Leak-detection window', 'Growth is evaluated over this much recent history', 'select', [[10, '10 minutes'], [15, '15 minutes'], [30, '30 minutes'], [60, '1 hour'], [120, '2 hours'], [240, '4 hours']]],
    ['leak_min_growth_mb', 'Minimum growth to flag', 'Smaller increases are ignored', 'range', [10, 1024, 10, ' MB']],
    ['retention_days', 'History retention', 'Older samples are deleted automatically', 'range', [1, 90, 1, ' days']]]],
  ['Alert thresholds', [['ram_warn_pct', 'RAM warning', 'Raise a warning above this usage', 'range', [50, 99, 1, '%']], ['ram_crit_pct', 'RAM critical', 'Raise a critical alert above this usage', 'range', [51, 100, 1, '%']], ['cpu_warn_pct', 'CPU warning', 'Counts as busy above this usage', 'range', [30, 100, 1, '%']],
    ['sustained_seconds', 'Sustained for', 'How long usage must stay high before warning', 'select', [[30, '30 seconds'], [60, '1 minute'], [120, '2 minutes'], [300, '5 minutes'], [600, '10 minutes']]]]],
  ['Behaviour', [['start_with_windows', 'Start with Windows', 'Adds a per-user startup entry only when you turn this on', 'toggle'], ['notifications', 'Notifications', 'Native notifications for critical memory and possible leaks', 'toggle'], ['tray_enabled', 'System tray icon', 'Show an icon in the notification area', 'toggle'], ['close_to_tray', 'Close to tray', 'Closing the window keeps monitoring in the tray (needs the tray icon)', 'toggle'], ['launch_minimized', 'Launch minimised', 'Start in the background', 'toggle']]],
];
function buildSettings() {
  const root = $('#settingsRoot'); let html = '';
  GROUPS.forEach(g => { html += `<div class="card"><h2>${g[0]}</h2>`; g[1].forEach(it => { const [k, l, d, t, o] = it; let ctl = '';
    if (t === 'toggle') ctl = `<button class="toggle" role="switch" data-k="${k}" aria-label="${l}"></button>`;
    else if (t === 'select') ctl = `<select data-k="${k}">${o.map(x => `<option value="${x[0]}">${x[1]}</option>`).join('')}</select>`;
    else ctl = `<input type="range" data-k="${k}" min="${o[0]}" max="${o[1]}" step="${o[2]}" data-suf="${o[3]}"><span class="rv" data-rv="${k}"></span>`;
    html += `<div class="srow"><div class="sl"><b>${l}</b><span>${d}</span></div><div class="ctl">${ctl}</div></div>`; }); html += '</div>'; });
  html += `<div class="card"><h2>Data</h2><div class="srow"><div class="sl"><b>Clear monitoring history</b><span>Deletes recorded process and system history</span></div><div class="ctl"><button class="btn danger" id="btnClear">${ico('trash')}Clear history</button></div></div>
    <div class="srow"><div class="sl"><b>Clear all application data</b><span>Deletes history and resets every setting (and removes the startup entry)</span></div><div class="ctl"><button class="btn danger" id="btnReset">${ico('trash')}Clear everything</button></div></div>
    <div class="srow"><div class="sl"><b>About</b><span id="aboutTxt"></span></div></div></div>`;
  root.innerHTML = html;
  let deb = {};
  root.addEventListener('click', e => { const t = e.target.closest('.toggle'); if (t) { const v = !t.classList.contains('on'); t.classList.toggle('on', v); saveSetting(t.dataset.k, v); } });
  root.addEventListener('change', e => { const el = e.target; if (el.tagName === 'SELECT') saveSetting(el.dataset.k, isNaN(el.value) ? el.value : Number(el.value)); });
  root.addEventListener('input', e => { const el = e.target; if (el.type === 'range') { $(`[data-rv="${el.dataset.k}"]`).textContent = el.value + el.dataset.suf; clearTimeout(deb[el.dataset.k]); deb[el.dataset.k] = setTimeout(() => saveSetting(el.dataset.k, Number(el.value)), 350); } });
  $('#btnClear').onclick = clearHistory; $('#btnReset').onclick = async () => { const r = await call('reset_all'); if (r.ok) { S.settings = r.settings; applySettings(); toast('All data cleared and settings reset.', 'ok'); } };
}
function syncSettingsUi() {
  const s = S.settings; $$('#settingsRoot [data-k]').forEach(el => { const v = s[el.dataset.k]; if (el.classList.contains('toggle')) el.classList.toggle('on', !!v); else { el.value = v; if (el.type === 'range') $(`[data-rv="${el.dataset.k}"]`).textContent = v + el.dataset.suf; } });
  const i = S.info; $('#aboutTxt').textContent = `WhereDidMyRAMGo ${i.version} · ${i.admin ? 'running as administrator' : 'standard user (no elevation needed)'} · data: ${i.data_dir}`;
}
async function saveSetting(k, v) {
  const r = await call('save_settings', JSON.stringify({ [k]: v })); if (!r || r.error) { toast('Could not save setting', 'err'); return; }
  S.settings = r.settings; applySettings(); (r.notes || []).forEach(n => toast(n));
}
async function clearHistory() { const r = await call('clear_history'); if (r.ok) { toast('History cleared.', 'ok'); S.hist = null; S.selKey = null; if (S.page === 'history') loadHistory(); } }
function applySettings() {
  document.documentElement.dataset.theme = S.settings.theme;
  const dark = S.settings.theme === 'dark'; C.grid = dark ? '#232938' : '#E4E8F1'; C.muted = dark ? '#8E97AC' : '#566079'; C.text = dark ? '#E7EAF2' : '#141826';
  S.perfRange = S.settings.perf_range_s; syncSettingsUi();
  $$('#rangeChips button').forEach(b => b.classList.toggle('on', +b.dataset.r === S.perfRange));
  [chRam, chCpu, chGrow, chSys, ...Object.values(S.perfCharts)].forEach(c => c && c.draw());
  if (S.snap) { renderAll(true); }
}

/* ----------------------------------------------------------------- events */
function wire() {
  $$('.nav button').forEach(b => b.addEventListener('click', () => nav(b.dataset.page)));
  $('#btnSettings').onclick = () => nav('settings');
  document.addEventListener('click', e => {
    const g = e.target.closest('[data-goto]'); if (g) nav(g.dataset.goto);
    if (!e.target.closest('#menu') && !e.target.closest('[data-act=menu]')) closeMenu();
    if (e.target.closest('[data-close]') || e.target === $('#modalBd')) closeModal();
    const op = e.target.closest('[data-open]'); if (op) openFolder(op.dataset.open);
    const hi = e.target.closest('[data-hist]'); if (hi) focusProcess(hi.dataset.hist);
    const dt = e.target.closest('[data-detail]'); if (dt) showDetails(dt.dataset.detail);
  });
  $('#recs').addEventListener('toggle', e => { const d = e.target; if (d.tagName === 'DETAILS') { d.open ? S.openRecs.add(d.dataset.id) : S.openRecs.delete(d.dataset.id); } }, true);
  $('#procBody').addEventListener('click', e => { const tr = e.target.closest('tr'); if (!tr) return; const key = tr.dataset.key;
    if (e.target.closest('[data-act=menu]')) { e.stopPropagation(); openMenu(e.target.closest('button'), key); } else showDetails(key); });
  $('#menu').addEventListener('click', e => { const b = e.target.closest('button[data-m]'); if (!b) return; const key = $('#menu').dataset.key; closeMenu();
    if (b.dataset.m === 'details') showDetails(key); else if (b.dataset.m === 'folder') openFolder(key); else if (b.dataset.m === 'end') endProcess(key);
    else if (b.dataset.m === 'hist') { nav('history'); focusProcess(key); } });
  $('#procHead').addEventListener('click', e => { const th = e.target.closest('th[data-k]'); if (!th) return; const k = th.dataset.k;
    S.sort = S.sort.k === k ? { k, dir: -S.sort.dir } : { k, dir: (k === 'name' || k === 'status') ? 1 : -1 }; S.idx = 0; renderProcesses(); });
  $('#search').addEventListener('input', e => { S.query = e.target.value; S.idx = 0; if (S.page !== 'processes') nav('processes'); else renderProcesses(); });
  $('#pageSize').onchange = e => { S.size = +e.target.value; S.idx = 0; renderProcesses(); };
  $('#pgPrev').onclick = () => { S.idx = Math.max(0, S.idx - 1); renderProcesses(); }; $('#pgNext').onclick = () => { S.idx++; renderProcesses(); };
  $('#rangeChips').addEventListener('click', e => { const b = e.target.closest('button'); if (!b) return; S.perfRange = +b.dataset.r; $$('#rangeChips button').forEach(x => x.classList.toggle('on', x === b)); saveSetting('perf_range_s', S.perfRange); renderPerf(); });
  const H = [[900, '15 min'], [3600, '1 hour'], [21600, '6 hours'], [86400, '24 hours'], [604800, '7 days']];
  $('#histChips').innerHTML = H.map(h => `<button data-w="${h[0]}" class="${h[0] === S.histWin ? 'on' : ''}">${h[1]}</button>`).join('');
  $('#histChips').addEventListener('click', e => { const b = e.target.closest('button'); if (!b) return; S.histWin = +b.dataset.w; $$('#histChips button').forEach(x => x.classList.toggle('on', x === b)); loadHistory(); });
  $('#histRefresh').onclick = () => loadHistory(); $('#histClear').onclick = clearHistory;
  $('#growReset').onclick = () => { S.selKey = null; drawGrowChart(); $$('#growBody tr').forEach(tr => tr.classList.remove('sel')); };
  $('#growBody').addEventListener('click', e => { const tr = e.target.closest('tr'); if (tr) focusProcess(tr.dataset.gkey); });
  document.addEventListener('keydown', e => { if (e.key === 'Escape') { closeMenu(); if (S.modalOpen) closeModal(); }
    if (e.key === '/' && !/INPUT|SELECT|TEXTAREA/.test(document.activeElement.tagName)) { e.preventDefault(); $('#search').focus(); } });
  document.addEventListener('scroll', closeMenu, true);
  setInterval(() => { const live = $('#live'), age = (Date.now() / 1000) - S.lastSnap, lim = Math.max(6, ((S.snap && S.snap.interval) || 2) * 3);
    const stale = !S.lastSnap || age > lim; live.classList.toggle('stale', stale); $('#liveText').textContent = stale ? (S.lastSnap ? 'No data' : 'Connecting…') : `Live · every ${S.snap.interval}s`; }, 1000);
}

function onSnapshot(json) {
  let sn; try { sn = JSON.parse(json); } catch (e) { return; }
  S.snap = sn; S.lastSnap = Date.now() / 1000; pushRing(sn);
  if (document.body.classList.contains('loading')) { document.body.classList.remove('loading'); }
  renderAll(false);
}

function boot() {
  if (typeof QWebChannel === 'undefined' || !window.qt) { document.body.innerHTML = '<div class="fatal"><h2>Could not start the interface</h2><p>The Qt bridge is unavailable. Please restart the application.</p></div>'; return; }
  chRam = mkChart('chRam', { mini: true, yMax: 100, fmt: v => v.toFixed(0) + '%' }); chCpu = mkChart('chCpu', { mini: true, yMax: 100, fmt: v => v.toFixed(0) + '%' });
  chGrow = mkChart('chGrow', { fmt: fmtBytes, yFit: true }); chSys = mkChart('chSys', { yMax: 100, fmt: v => v.toFixed(0) + '%' });
  buildPerf(); wire();
  new QWebChannel(qt.webChannelTransport, ch => {
    bridge = ch.objects.bridge; bridge.snapshot.connect(onSnapshot);
    call('get_bootstrap').then(b => { S.settings = b.settings; S.info = b.info; if (b.series && b.series.t) { S.ring = b.series; }
      buildSettings(); applySettings(); nav('overview'); });
  });
}
boot();
})();
'''

HTML_TEMPLATE = r'''<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline' qrc:; style-src 'unsafe-inline'; img-src data:;">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WhereDidMyRAMGo</title>
<style>/*__CSS__*/</style>
</head>
<body class="loading">
<svg width="0" height="0" style="position:absolute" aria-hidden="true"><defs>
<symbol id="i-logo" viewBox="0 0 24 24"><rect x="2" y="7" width="20" height="10" rx="2"/><path d="M6 17v3M10 17v3M14 17v3M18 17v3M6 11h2M11 11h2M16 11h2"/></symbol>
<symbol id="i-overview" viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></symbol>
<symbol id="i-processes" viewBox="0 0 24 24"><path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/></symbol>
<symbol id="i-performance" viewBox="0 0 24 24"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></symbol>
<symbol id="i-history" viewBox="0 0 24 24"><path d="M3 12a9 9 0 1 0 3-6.7L3 8"/><path d="M3 3v5h5"/><path d="M12 7v5l3 2"/></symbol>
<symbol id="i-settings" viewBox="0 0 24 24"><path d="M4 21v-7M4 10V3M12 21v-9M12 8V3M20 21v-5M20 12V3M1 14h6M9 8h6M17 16h6"/></symbol>
<symbol id="i-search" viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></symbol>
<symbol id="i-more" viewBox="0 0 24 24"><circle cx="5" cy="12" r="1.5" fill="currentColor"/><circle cx="12" cy="12" r="1.5" fill="currentColor"/><circle cx="19" cy="12" r="1.5" fill="currentColor"/></symbol>
<symbol id="i-cpu" viewBox="0 0 24 24"><rect x="5" y="5" width="14" height="14" rx="2"/><rect x="9" y="9" width="6" height="6"/><path d="M9 1v4M15 1v4M9 19v4M15 19v4M1 9h4M1 15h4M19 9h4M19 15h4"/></symbol>
<symbol id="i-disk" viewBox="0 0 24 24"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14c0 1.7 4 3 9 3s9-1.3 9-3V5M3 12c0 1.7 4 3 9 3s9-1.3 9-3"/></symbol>
<symbol id="i-shield" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></symbol>
<symbol id="i-alert" viewBox="0 0 24 24"><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><path d="M12 9v4M12 17h.01"/></symbol>
<symbol id="i-info" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></symbol>
<symbol id="i-folder" viewBox="0 0 24 24"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></symbol>
<symbol id="i-stop" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><path d="M9 9h6v6H9z"/></symbol>
<symbol id="i-chart" viewBox="0 0 24 24"><path d="M3 3v18h18"/><path d="m7 15 4-4 3 3 5-6"/></symbol>
<symbol id="i-trash" viewBox="0 0 24 24"><path d="M3 6h18M8 6V4h8v2M6 6l1 14h10l1-14"/></symbol>
<symbol id="i-refresh" viewBox="0 0 24 24"><path d="M21 12a9 9 0 1 1-3-6.7L21 8"/><path d="M21 3v5h-5"/></symbol>
<symbol id="i-bulb" viewBox="0 0 24 24"><path d="M9 18h6M10 22h4M12 2a7 7 0 0 0-4 12.7c.6.5 1 1.3 1 2.3h6c0-1 .4-1.8 1-2.3A7 7 0 0 0 12 2z"/></symbol>
<symbol id="i-app" viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="16" rx="3"/><path d="M3 9h18"/></symbol>
<symbol id="i-check" viewBox="0 0 24 24"><path d="m5 12 5 5 9-10"/></symbol>
<symbol id="i-ram" viewBox="0 0 24 24"><rect x="2" y="7" width="20" height="10" rx="2"/><path d="M6 17v3M10 17v3M14 17v3M18 17v3M6 11h2M11 11h2M16 11h2"/></symbol>
</defs></svg>

<div class="app">
<aside class="sidebar">
  <div class="brand"><div class="logo"><svg><use href="#i-logo"/></svg></div><div class="brand-name">WhereDidMy<br><b>RAMGo</b></div></div>
  <nav class="nav" aria-label="Main">
    <button data-page="overview" class="active"><svg><use href="#i-overview"/></svg><span>Overview</span></button>
    <button data-page="processes"><svg><use href="#i-processes"/></svg><span>Processes</span></button>
    <button data-page="performance"><svg><use href="#i-performance"/></svg><span>Performance</span></button>
    <button data-page="history"><svg><use href="#i-history"/></svg><span>History</span></button>
    <button data-page="settings"><svg><use href="#i-settings"/></svg><span>Settings</span></button>
  </nav>
  <div class="side-status" id="sideStatus"><span class="dot"></span><div><div class="ss-title">Starting…</div><div class="ss-sub">Collecting data</div></div></div>
</aside>
<div class="main">
<header class="topbar">
  <div class="titles"><h1 id="pageTitle">Overview</h1><p id="pageSub"></p></div>
  <div class="top-actions">
    <div class="live stale" id="live"><span class="dot"></span><span id="liveText">Connecting…</span></div>
    <label class="search"><svg><use href="#i-search"/></svg><input id="search" placeholder="Search processes" autocomplete="off" spellcheck="false" aria-label="Search processes"><kbd>/</kbd></label>
    <button class="icon-btn" id="btnSettings" title="Settings" aria-label="Settings"><svg><use href="#i-settings"/></svg></button>
  </div>
</header>
<main class="content">

<section class="page active" id="page-overview"><div class="grid">
  <div class="card c6"><h2><svg><use href="#i-ram"/></svg>Memory</h2>
    <div class="skel-wrap"><div class="skel w60"></div><div class="skel tall"></div><div class="skel w90"></div></div>
    <div class="real"><div class="ram-top">
      <div class="ring"><svg viewBox="0 0 120 120"><circle class="bg" cx="60" cy="60" r="52"/><circle class="fg" id="ramFg" cx="60" cy="60" r="52" stroke-linecap="round" stroke-dasharray="326.7" stroke-dashoffset="326.7"/></svg>
        <div class="mid"><b id="ramPct">–</b><small>in use</small></div></div>
      <div class="stats"><div class="stat"><small>Total</small><b id="ramTotal">–</b></div><div class="stat"><small>Used</small><b id="ramUsed">–</b></div><div class="stat"><small>Available</small><b id="ramAvail">–</b></div></div>
    </div><div class="chart-wrap"><canvas id="chRam"></canvas></div></div></div>
  <div class="card c6"><h2><svg><use href="#i-cpu"/></svg>Processor</h2>
    <div class="skel-wrap"><div class="skel w60"></div><div class="skel tall"></div><div class="skel w90"></div></div>
    <div class="real"><div class="ram-top"><div><div class="bigpct" id="cpuPct">–</div><small style="color:var(--muted)">overall utilisation</small></div>
      <div class="stats"><div class="stat"><small>Cores</small><b id="cpuCores">–</b></div><div class="stat"><small>Frequency</small><b id="cpuFreq">–</b></div></div></div>
    <div class="chart-wrap"><canvas id="chCpu"></canvas></div></div></div>
  <div class="card c6"><h2><svg><use href="#i-disk"/></svg>Disks</h2>
    <div class="skel-wrap"><div class="skel w60"></div><div class="skel w90"></div><div class="skel w40"></div></div>
    <div class="real"><div id="drives"></div><div class="io"><span>Read <b id="dRead">–</b></span><span>Write <b id="dWrite">–</b></span></div></div></div>
  <div class="card c6"><h2><svg><use href="#i-shield"/></svg>System health</h2>
    <div class="skel-wrap"><div class="skel w60"></div><div class="skel w90"></div><div class="skel w40"></div></div>
    <div class="real"><div class="kv"><span>Running processes</span><b id="hProcs">–</b></div><div class="kv"><span>Uptime</span><b id="hUp">–</b></div>
    <div class="kv"><span>RAM status</span><span id="hRam"></span></div><div class="kv"><span>CPU status</span><span id="hCpu"></span></div><div id="hWarn"></div></div></div>
  <div class="card c7"><h2><svg><use href="#i-ram"/></svg>Biggest memory consumers<span class="sp"></span><span class="tools"><button class="btn" data-goto="processes">View all</button></span></h2>
    <div class="skel-wrap"><div class="skel w90"></div><div class="skel w90"></div><div class="skel w60"></div></div>
    <div class="real" id="topList"></div></div>
  <div class="card c5"><h2><svg><use href="#i-bulb"/></svg>Recommendations</h2>
    <div class="skel-wrap"><div class="skel w90"></div><div class="skel w60"></div></div>
    <div class="real" id="recs"></div></div>
</div></section>

<section class="page" id="page-processes">
  <div class="toolbar"><div id="procCount" style="color:var(--muted)"></div><div class="sp"></div>
    <div class="legend"><span><i style="background:var(--amber)"></i>≥ 5% of RAM</span><span><i style="background:var(--red)"></i>≥ 10% of RAM</span></div>
    <label style="color:var(--muted)">Rows <select id="pageSize"><option>25</option><option selected>50</option><option>100</option><option>250</option></select></label></div>
  <div class="card tablewrap"><table><thead><tr id="procHead">
    <th data-k="name">Process<span class="ar"></span></th><th data-k="pid" class="num">PID<span class="ar"></span></th><th data-k="rss" class="num">Memory<span class="ar"></span></th>
    <th data-k="pct" class="num">% of RAM<span class="ar"></span></th><th data-k="cpu" class="num">CPU<span class="ar"></span></th><th data-k="status">Status<span class="ar"></span></th><th style="width:44px;cursor:default"></th></tr></thead>
    <tbody id="procBody"></tbody></table><div id="procEmpty"></div>
    <div class="pager"><span id="pagerInfo"></span><div class="btns"><button class="btn" id="pgPrev">Previous</button><button class="btn" id="pgNext">Next</button></div></div></div>
</section>

<section class="page" id="page-performance">
  <div class="toolbar"><div class="chips" id="rangeChips"></div><div class="sp"></div><span style="color:var(--muted)" id="perfNote"></span></div>
  <div class="perf-grid" id="perfGrid"></div>
</section>

<section class="page" id="page-history">
  <div class="toolbar"><div class="chips" id="histChips"></div><div class="sp"></div><span id="histNote" style="color:var(--muted)"></span>
    <button class="btn" id="histRefresh"><svg><use href="#i-refresh"/></svg>Refresh</button><button class="btn danger" id="histClear"><svg><use href="#i-trash"/></svg>Clear history</button></div>
  <div class="grid">
    <div class="card c12"><h2><svg><use href="#i-alert"/></svg>Possible memory leaks<span class="sp"></span><span class="tools" id="leakNote" style="color:var(--muted)"></span></h2><div id="findings"></div></div>
    <div class="card c7"><h2><svg><use href="#i-chart"/></svg><span id="growTitle">Memory over time · largest increases</span><span class="sp"></span><span class="tools"><button class="btn hidden" id="growReset">Show top growers</button></span></h2>
      <div class="leg" id="growLeg" style="margin:0 0 6px"></div><div class="chart-wrap tall"><canvas id="chGrow"></canvas></div></div>
    <div class="card c5"><h2><svg><use href="#i-performance"/></svg>System usage</h2><div class="leg" style="margin:0 0 6px"><span><i style="background:#8B5CF6"></i>RAM %</span><span><i style="background:#3B82F6"></i>CPU %</span></div><div class="chart-wrap tall"><canvas id="chSys"></canvas></div></div>
    <div class="card c12 tablewrap"><div style="padding:18px 18px 0"><h2 style="margin:0 0 12px"><svg><use href="#i-processes"/></svg>Growth by process<span class="sp"></span><span class="tools" style="color:var(--muted)">Click a row to chart it</span></h2></div>
      <table><thead><tr><th style="cursor:default">Process</th><th class="num" style="cursor:default">Now</th><th class="num" style="cursor:default">Change</th><th class="num" style="cursor:default">Rate</th><th class="num" style="cursor:default">Peak</th><th style="cursor:default">Assessment</th></tr></thead><tbody id="growBody"></tbody></table><div id="growEmpty"></div></div>
  </div>
</section>

<section class="page" id="page-settings"><div class="settings" id="settingsRoot"></div></section>
</main></div></div>

<div id="menu" class="menu hidden" role="menu"></div>
<div id="modalBd" class="modal-bd hidden"><div class="modal" id="modal" role="dialog" aria-modal="true"></div></div>
<div id="toasts"></div>
<!--__QWC__-->
<script>/*__JS__*/</script>
</body></html>
'''


# ============================================================================
# Front-end assembly
# ============================================================================
def load_qwebchannel_js() -> str:
    """Read Qt's bundled qwebchannel.js so the page needs no external file."""
    f = QFile(":/qtwebchannel/qwebchannel.js")
    if f.open(QIODevice.OpenModeFlag.ReadOnly):
        try:
            return bytes(f.readAll().data()).decode("utf-8")
        finally:
            f.close()
    return ""


def build_html() -> str:
    """Combine template, CSS, JS and the Qt web-channel script into one document."""
    qwc = load_qwebchannel_js()
    tag = f"<script>{qwc}</script>" if qwc else '<script src="qrc:///qtwebchannel/qwebchannel.js"></script>'
    return (HTML_TEMPLATE.replace("/*__CSS__*/", FRONTEND_CSS)
            .replace("<!--__QWC__-->", tag).replace("/*__JS__*/", FRONTEND_JS))


# ============================================================================
# Qt bridge (the only door between JavaScript and privileged Python code)
# ============================================================================
class Bridge(QObject):
    """Slots callable from the page. Every argument is validated; every slot returns JSON."""

    snapshot = Signal(str)

    def __init__(self, settings: Settings, db: Database, worker: MonitorWorker) -> None:
        super().__init__()
        self.settings, self.db, self.worker = settings, db, worker
        self.window: Optional[QMainWindow] = None
        self.on_settings = None  # callback(dict) set by MainWindow
        self._icons: Dict[str, Optional[str]] = {}
        self._provider = QFileIconProvider()

    # -- helpers -------------------------------------------------------
    def _run(self, fn, *args) -> str:
        try:
            return json.dumps(fn(*args), default=str)
        except psutil.NoSuchProcess:
            return json.dumps({"ok": False, "message": "That process has already exited (or its PID was reused)."})
        except psutil.AccessDenied:
            return json.dumps({"ok": False, "message": "Windows denied access to this process. Some processes "
                               "can only be inspected when WhereDidMyRAMGo runs as administrator."})
        except Exception as exc:
            log.exception("bridge call %s failed", getattr(fn, "__name__", fn))
            return json.dumps({"ok": False, "error": str(exc), "message": f"Unexpected error: {exc}"})

    @staticmethod
    def _resolve(key: str) -> psutil.Process:
        parsed = parse_key(key)
        if parsed is None:
            raise ValueError("Invalid process identifier.")
        p = psutil.Process(parsed[0])
        if make_key(p.pid, p.create_time()) != key:
            raise psutil.NoSuchProcess(parsed[0])
        return p

    def _confirm(self, title: str, text: str, yes: str = "Yes") -> bool:
        box = QMessageBox(self.window)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle(title)
        box.setText(text)
        yes_btn = box.addButton(yes, QMessageBox.ButtonRole.AcceptRole)
        no_btn = box.addButton("Cancel", QMessageBox.ButtonRole.RejectRole)
        box.setDefaultButton(no_btn)
        box.exec()
        return box.clickedButton() is yes_btn

    # -- slots -----------------------------------------------------------
    @Slot(result=str)
    def get_bootstrap(self) -> str:
        def impl():
            return {"settings": self.settings.get(),
                    "info": {"version": APP_VERSION, "admin": is_admin(), "data_dir": str(data_dir()),
                             "platform": sys.platform},
                    "series": self.worker.ring_arrays()}
        return self._run(impl)

    @Slot(str)
    def set_page(self, page: str) -> None:
        self.worker.wants_processes = (page == "processes")

    @Slot(int, result=str)
    def get_history(self, window_s: int) -> str:
        def impl():
            window = max(60, min(int(window_s), 31 * 86400))
            now = int(time.time())
            since = now - window
            cfg = self.settings.get()
            total = psutil.virtual_memory().total
            system = self.db.system_series(since)
            leak_keys = {f["key"]: f for f in self.worker.findings}
            procs = []
            for r in self.db.process_growth(since):
                growth = r["last"] - r["first"]
                gpct = growth / r["first"] * 100 if r["first"] else 0.0
                span = r["t1"] - r["t0"]
                rate = growth / span * 60 / MB if span > 0 else 0.0
                if r["key"] in leak_keys:
                    tag = "leak"
                elif growth >= cfg["leak_min_growth_mb"] * MB and gpct >= 10:
                    tag = "growing"
                elif total and r["last"] / total >= 0.05 and abs(gpct) < 10:
                    tag = "high_stable"
                else:
                    tag = "stable"
                procs.append({"key": r["key"], "name": r["name"], "pid": r["pid"], "last": r["last"],
                              "peak": r["peak"], "growth": growth, "growth_pct": gpct, "rate": rate,
                              "tag": tag, "alive": r["key"] in self.worker.alive_keys})
            procs.sort(key=lambda p: p["growth"], reverse=True)
            procs = procs[:25]
            top = [p["key"] for p in procs[:5]]
            first = system.get("first_ts")
            return {"window": window, "system": system, "procs": procs,
                    "top_series": self.db.multi_process_series(top, since),
                    "coverage_s": (now - first) if first else 0}
        return self._run(impl)

    @Slot(str, int, result=str)
    def get_process_history(self, key: str, window_s: int) -> str:
        def impl():
            if parse_key(key) is None:
                raise ValueError("Invalid process identifier.")
            window = max(60, min(int(window_s), 31 * 86400))
            return self.db.process_series(key, int(time.time()) - window)
        return self._run(impl)

    @Slot(str, result=str)
    def get_process_details(self, key: str) -> str:
        def impl():
            p = self._resolve(key)
            restricted = False
            out: Dict[str, Any] = {"ok": True, "pid": p.pid}
            with p.oneshot():
                out["name"] = p.name()
                out["status"] = p.status()
                out["created"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(p.create_time()))
                for field_name, getter in (("rss", lambda: p.memory_info().rss), ("vms", lambda: p.memory_info().vms),
                                           ("threads", p.num_threads), ("exe", p.exe), ("user", p.username),
                                           ("handles", getattr(p, "num_handles", lambda: None))):
                    try:
                        out[field_name] = getter()
                    except (psutil.AccessDenied, OSError):
                        out[field_name] = None
                        restricted = True
                try:
                    out["cmdline"] = " ".join(p.cmdline())[:1500]
                except (psutil.AccessDenied, OSError):
                    out["cmdline"] = None
                    restricted = True
                try:
                    par = p.parent()
                    out["parent"] = f"{par.name()} ({par.pid})" if par else None
                except (psutil.Error, OSError):
                    out["parent"] = None
            try:
                out["uss"] = p.memory_full_info().uss
            except (psutil.Error, OSError, AttributeError):
                out["uss"] = None
            out["restricted"] = restricted
            return out
        return self._run(impl)

    @Slot(str, result=str)
    def get_icon(self, key: str) -> str:
        def impl():
            exe = self.worker.exe_for(key) if parse_key(key) else ""
            if not exe or not os.path.isfile(exe):
                return {"uri": None}
            if exe in self._icons:
                return {"uri": self._icons[exe]}
            uri = None
            icon = self._provider.icon(QFileInfo(exe))
            if not icon.isNull():
                pm = icon.pixmap(32, 32)
                if not pm.isNull():
                    ba, buf = QByteArray(), QBuffer()
                    buf.setBuffer(ba)
                    buf.open(QIODevice.OpenModeFlag.WriteOnly)
                    pm.save(buf, "PNG")
                    buf.close()
                    uri = "data:image/png;base64," + base64.b64encode(bytes(ba.data())).decode("ascii")
            self._icons[exe] = uri
            return {"uri": uri}
        return self._run(impl)

    @Slot(str, result=str)
    def open_file_location(self, key: str) -> str:
        def impl():
            p = self._resolve(key)
            exe = p.exe()
            if not exe or not os.path.isabs(exe) or not os.path.isfile(exe):
                return {"ok": False, "message": "The executable's location is not available for this process."}
            if IS_WINDOWS:
                subprocess.Popen(["explorer.exe", "/select,", exe])
            else:
                opener = "xdg-open" if sys.platform != "darwin" else "open"
                subprocess.Popen([opener, os.path.dirname(exe)])
            return {"ok": True, "message": "Opened the file location."}
        return self._run(impl)

    @Slot(str, result=str)
    def terminate_process(self, key: str) -> str:
        def impl():
            p = self._resolve(key)
            name, pid = p.name(), p.pid
            reason = protection_reason(name, pid)
            if reason:
                return {"ok": False, "message": f"Not allowed: {reason}"}
            text = (f"End “{name}” (PID {pid})?\n\nThe process will be asked to terminate. Unsaved data in that "
                    f"application may be lost.\n\nNote: high memory use does not mean a process is harmful, and "
                    f"ending it will not necessarily make your PC faster.")
            if not self._confirm("End process", text, "End process"):
                return {"ok": False, "cancelled": True, "message": "Cancelled. Nothing was changed."}
            try:
                p = self._resolve(key)  # re-verify identity after the dialog
                p.terminate()
                try:
                    p.wait(timeout=3)
                except psutil.TimeoutExpired:
                    return {"ok": False, "message": f"{name} was asked to close but is still running."}
            except psutil.AccessDenied:
                return {"ok": False, "message": f"Windows denied permission to end {name}. It belongs to another "
                        "user or is protected. Only if you are sure, run WhereDidMyRAMGo as administrator."}
            except psutil.NoSuchProcess:
                return {"ok": True, "message": f"{name} has already exited."}
            log.info("User terminated %s (%s)", name, pid)
            return {"ok": True, "message": f"{name} was ended."}
        return self._run(impl)

    @Slot(str, result=str)
    def save_settings(self, payload: str) -> str:
        def impl():
            partial = json.loads(payload)
            if not isinstance(partial, dict):
                raise ValueError("Settings payload must be an object.")
            new, notes = self.settings.update(partial)
            if "start_with_windows" in partial:
                ok, msg = set_startup(new["start_with_windows"])
                if not ok:
                    new, _ = self.settings.update({"start_with_windows": False})
                    notes.append(msg)
            if self.on_settings:
                self.on_settings(new)
            return {"ok": True, "settings": new, "notes": notes}
        return self._run(impl)

    @Slot(result=str)
    def clear_history(self) -> str:
        def impl():
            if not self._confirm("Clear history", "Delete all recorded system and process history?", "Clear history"):
                return {"ok": False}
            self.db.clear()
            self.worker.clear_memory_history()
            return {"ok": True}
        return self._run(impl)

    @Slot(result=str)
    def reset_all(self) -> str:
        def impl():
            if not self._confirm("Clear all data", "Delete all history and reset every setting to its default?",
                                 "Clear everything"):
                return {"ok": False}
            self.db.clear()
            self.worker.clear_memory_history()
            new = self.settings.reset()
            set_startup(False)
            if self.on_settings:
                self.on_settings(new)
            return {"ok": True, "settings": new}
        return self._run(impl)


# ============================================================================
# Window, tray, icon
# ============================================================================
def make_app_icon() -> QIcon:
    """Draw the application icon (gradient tile with a RAM-stick glyph)."""
    icon = QIcon()
    for size in (16, 24, 32, 48, 64, 128, 256):
        pm = QPixmap(size, size)
        pm.fill(Qt.GlobalColor.transparent)
        p = QPainter(pm)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        g = QLinearGradient(0, 0, size, size)
        g.setColorAt(0, QColor("#8B5CF6"))
        g.setColorAt(1, QColor("#3B82F6"))
        p.setBrush(g)
        p.setPen(Qt.PenStyle.NoPen)
        p.drawRoundedRect(QRectF(0, 0, size, size), size * 0.24, size * 0.24)
        p.setBrush(QColor("white"))
        p.drawRoundedRect(QRectF(size * 0.16, size * 0.30, size * 0.68, size * 0.34), size * 0.06, size * 0.06)
        p.setBrush(QColor("#5B5BE0"))
        for i in range(3):
            p.drawRect(QRectF(size * (0.26 + i * 0.19), size * 0.38, size * 0.11, size * 0.18))
        p.setBrush(QColor("white"))
        for i in range(5):
            p.drawRect(QRectF(size * (0.21 + i * 0.13), size * 0.66, size * 0.07, size * 0.12))
        p.end()
        icon.addPixmap(pm)
    return icon


def set_dark_titlebar(hwnd: int, dark: bool) -> None:
    """Ask Windows 10 (20H1+) / 11 for a dark or light native title bar."""
    if not IS_WINDOWS:
        return
    try:
        value = ctypes.c_int(1 if dark else 0)
        for attr in (20, 19):
            if ctypes.windll.dwmapi.DwmSetWindowAttribute(
                    ctypes.c_void_p(hwnd), attr, ctypes.byref(value), ctypes.sizeof(value)) == 0:
                break
    except Exception:
        pass


class AppPage(QWebEnginePage):
    """Web page that refuses navigation away from the app and logs JS console output."""

    def __init__(self, parent: QObject) -> None:
        super().__init__(parent)
        self._loaded = False
        self.loadFinished.connect(lambda ok: setattr(self, "_loaded", True))

    def acceptNavigationRequest(self, url, nav_type, is_main_frame):  # noqa: N802
        return True if not self._loaded else False

    def javaScriptConsoleMessage(self, level, message, line, source):  # noqa: N802
        if level != QWebEnginePage.JavaScriptConsoleMessageLevel.InfoMessageLevel:
            log.warning("JS[%s:%s] %s", source, line, message)


class MainWindow(QMainWindow):
    """Hosts the web UI; owns the tray icon and orderly shutdown."""

    def __init__(self, settings: Settings, db: Database, worker: MonitorWorker, bridge: Bridge,
                 icon: QIcon) -> None:
        super().__init__()
        self.settings, self.db, self.worker, self.bridge = settings, db, worker, bridge
        self._quitting = False
        self.setWindowTitle(APP_NAME)
        self.setWindowIcon(icon)
        self.resize(1360, 860)
        self.setMinimumSize(900, 600)
        bridge.window = self
        bridge.on_settings = self.apply_settings

        self.view = QWebEngineView(self)
        self.page = AppPage(self.view)
        self.page.setBackgroundColor(QColor("#0B0D12"))
        self.view.setPage(self.page)
        self.view.setContextMenuPolicy(Qt.ContextMenuPolicy.NoContextMenu)
        self.channel = QWebChannel(self.page)
        self.channel.registerObject("bridge", bridge)
        self.page.setWebChannel(self.channel)
        worker.snapshot.connect(bridge.snapshot)
        self.view.setHtml(build_html(), QUrl("https://wheredidmyramgo.invalid/"))
        self.setCentralWidget(self.view)

        self.tray = QSystemTrayIcon(icon, self)
        self.tray.setToolTip(APP_NAME)
        menu = QMenu()
        act_show = QAction("Show WhereDidMyRAMGo", menu)
        act_show.triggered.connect(self.show_window)
        act_quit = QAction("Quit", menu)
        act_quit.triggered.connect(self.quit_app)
        menu.addAction(act_show)
        menu.addSeparator()
        menu.addAction(act_quit)
        self._tray_menu = menu
        self.tray.setContextMenu(menu)
        self.tray.activated.connect(self._tray_clicked)
        worker.alert.connect(self.on_alert)
        self.apply_settings(settings.get())

    def apply_settings(self, cfg: Dict[str, Any]) -> None:
        want_tray = (cfg["tray_enabled"] or cfg["notifications"]) and QSystemTrayIcon.isSystemTrayAvailable()
        self.tray.setVisible(bool(want_tray))
        self.page.setBackgroundColor(QColor("#0B0D12" if cfg["theme"] == "dark" else "#F3F5FA"))
        set_dark_titlebar(int(self.winId()), cfg["theme"] == "dark")

    def on_alert(self, title: str, text: str) -> None:
        if self.tray.isVisible():
            self.tray.showMessage(title, text, QSystemTrayIcon.MessageIcon.Warning, 8000)

    def show_window(self) -> None:
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def _tray_clicked(self, reason) -> None:
        if reason == QSystemTrayIcon.ActivationReason.Trigger:
            self.show_window()

    def quit_app(self) -> None:
        self._quitting = True
        self.close()

    def closeEvent(self, event) -> None:  # noqa: N802
        cfg = self.settings.get()
        if not self._quitting and cfg["close_to_tray"] and self.tray.isVisible():
            self.hide()
            event.ignore()
            return
        self.shutdown()
        event.accept()
        QApplication.quit()

    def shutdown(self) -> None:
        """Stop the worker thread, close the database, hide the tray icon."""
        log.info("Shutting down")
        self.worker.stop()
        if not self.worker.wait(8000):
            log.warning("Worker did not stop in time")
        self.db.close()
        self.tray.hide()


# ============================================================================
# Unit tests  (python wheredidmyramgo.py --test)
# ============================================================================
def _series(start_bytes: int, step_bytes: int, n: int, dt: float = 30.0, t0: float = 1_000_000.0):
    return [(t0 + i * dt, start_bytes + i * step_bytes) for i in range(n)]


class TestMemoryMath(unittest.TestCase):
    def test_stats(self):
        s = compute_memory_stats(16 * GB, 4 * GB)
        self.assertEqual(s["used"], 12 * GB)
        self.assertEqual(s["percent"], 75.0)

    def test_clamps_and_zero_total(self):
        self.assertEqual(compute_memory_stats(100, 500)["used"], 0)
        self.assertEqual(compute_memory_stats(0, 0)["percent"], 0.0)

    def test_format_bytes_and_duration(self):
        self.assertEqual(format_bytes(1536), "2 KB")
        self.assertEqual(format_bytes(int(2.4 * GB)), "2.40 GB")
        self.assertEqual(format_bytes(None), "-")
        self.assertEqual(format_duration(3725), "1h 2m")

    def test_keys(self):
        self.assertEqual(make_key(10, 123.456), make_key(10, 123.456))
        self.assertNotEqual(make_key(10, 123.456), make_key(10, 999.0))  # PID reuse
        self.assertEqual(parse_key("10:12346"), (10, 12346))
        for bad in ("abc", "1:2:3", "", None, 5, "1;DROP"):
            self.assertIsNone(parse_key(bad))

    def test_protection(self):
        self.assertIsNotNone(protection_reason("csrss.exe", 600))
        self.assertIsNotNone(protection_reason("anything.exe", 4))
        self.assertIsNone(protection_reason("notepad.exe", 999999))


class TestHistorySampling(unittest.TestCase):
    def test_bounded_points(self):
        h = ProcessHistory(max_age_s=1e9, max_points=10)
        for i in range(100):
            h.add(float(i), "1:1", "a.exe", 1, i)
        self.assertEqual(len(h.samples("1:1")), 10)

    def test_prune_by_age_and_drop_empty(self):
        h = ProcessHistory(max_age_s=60)
        h.add(0, "1:1", "a", 1, 1)
        h.add(100, "2:2", "b", 2, 1)
        h.prune(120)
        self.assertEqual(h.keys(), ["2:2"])

    def test_ignores_duplicate_timestamps(self):
        h = ProcessHistory()
        h.add(5, "1:1", "a", 1, 10)
        h.add(5, "1:1", "a", 1, 99)
        h.add(4, "1:1", "a", 1, 99)
        self.assertEqual(h.samples("1:1"), [(5.0, 10)])

    def test_sustained_tracker(self):
        t = SustainedTracker()
        self.assertEqual(t.update({"x": True}, 100)["x"], 0)
        self.assertEqual(t.update({"x": True}, 130)["x"], 30)
        self.assertEqual(t.update({"x": False}, 140)["x"], 0)
        self.assertEqual(t.update({"x": True}, 150)["x"], 0)


class TestLeakDetection(unittest.TestCase):
    cfg = LeakConfig(window_s=1800, min_samples=6, min_duration_s=300, min_growth_bytes=50 * MB)

    def test_steady_growth_is_flagged(self):
        f = analyze_growth(_series(200 * MB, 8 * MB, 30), self.cfg, "k", "leaky.exe", 7)
        self.assertTrue(f.flagged, f.reasons)
        self.assertGreater(f.rate_mb_min, 10)
        self.assertIn("not proof", " ".join(f.reasons))

    def test_high_but_stable_is_not_flagged(self):
        f = analyze_growth(_series(4 * GB, 0, 30), self.cfg)
        self.assertFalse(f.flagged)

    def test_noisy_stable_is_not_flagged(self):
        s = [(1e6 + i * 30, 500 * MB + (5 * MB if i % 2 else -5 * MB)) for i in range(30)]
        self.assertFalse(analyze_growth(s, self.cfg).flagged)

    def test_sawtooth_is_not_flagged(self):
        s = [(1e6 + i * 30, 300 * MB + (i % 10) * 30 * MB) for i in range(40)]
        self.assertFalse(analyze_growth(s, self.cfg).flagged)

    def test_plateau_after_jump_is_not_flagged(self):
        s = [(1e6 + i * 30, (200 if i < 5 else 400) * MB) for i in range(30)]
        self.assertFalse(analyze_growth(s, self.cfg).flagged)

    def test_too_few_samples(self):
        f = analyze_growth(_series(100 * MB, 20 * MB, 4), self.cfg)
        self.assertFalse(f.flagged)
        self.assertIn("Not enough", f.reasons[0])

    def test_small_growth_below_threshold(self):
        self.assertFalse(analyze_growth(_series(100 * MB, 1 * MB, 30), self.cfg).flagged)

    def test_gap_uses_only_latest_continuous_run(self):
        old = _series(100 * MB, 0, 20, t0=1_000_000)
        new = _series(100 * MB, 8 * MB, 25, t0=1_000_000 + 20 * 30 + 7200)  # 2h gap (app was closed)
        tail = contiguous_tail(old + new)
        self.assertEqual(len(tail), 25)
        self.assertTrue(analyze_growth(old + new, self.cfg).flagged)

    def test_restart_creates_new_identity_not_a_false_leak(self):
        h = ProcessHistory(max_age_s=1e9)
        for i, (t, v) in enumerate(_series(900 * MB, 0, 20)):
            h.add(t, make_key(100, 1.0), "app.exe", 100, v)
        for i, (t, v) in enumerate(_series(50 * MB, 0, 20, t0=1_000_000 + 20 * 30)):
            h.add(t, make_key(100, 2.0), "app.exe", 100, v)  # same PID, new start time
        self.assertEqual(len(h.keys()), 2)
        self.assertEqual(detect_leaks(h, self.cfg), [])

    def test_alive_filter(self):
        h = ProcessHistory(max_age_s=1e9)
        for t, v in _series(200 * MB, 8 * MB, 30):
            h.add(t, "1:1", "x.exe", 1, v)
        self.assertEqual(len(detect_leaks(h, self.cfg, {"1:1"})), 1)
        self.assertEqual(detect_leaks(h, self.cfg, set()), [])

    def test_linear_fit(self):
        slope, r2 = linear_fit([0, 1, 2, 3], [1, 3, 5, 7])
        self.assertAlmostEqual(slope, 2.0)
        self.assertAlmostEqual(r2, 1.0)


class TestRecommendations(unittest.TestCase):
    def _sys(self, pct, total=16 * GB):
        used = int(total * pct / 100)
        return {"ram_total": total, "ram_used": used, "ram_avail": total - used, "ram_pct": float(pct), "cpu_pct": 10.0}

    def test_ram_rule_and_explanation(self):
        r = RecommendationEngine().evaluate(self._sys(90), [], [], {}, validate_settings({}), [])
        top = r[0]
        self.assertEqual(top["id"], "ram-high")
        self.assertIn("85%", top["title"])
        self.assertTrue(top["why"])
        self.assertIn("no guarantee", " ".join(top["why"]).lower())

    def test_app_aggregation(self):
        procs = [{"name": "chrome.exe", "pid": i, "rss": 400 * MB, "cpu": 0} for i in range(7)]
        r = RecommendationEngine().evaluate(self._sys(40), procs, [], {}, validate_settings({}), [])
        self.assertTrue(any("Chrome" in x["title"] and "GB" in x["title"] for x in r))

    def test_all_ok(self):
        r = RecommendationEngine().evaluate(self._sys(30), [], [], {}, validate_settings({}), [])
        self.assertEqual(r[0]["id"], "all-ok")

    def test_leak_recommendation_uses_cautious_language(self):
        f = asdict(analyze_growth(_series(200 * MB, 8 * MB, 30), LeakConfig(), "k", "leaky.exe", 7))
        r = RecommendationEngine().evaluate(self._sys(30), [], [f], {}, validate_settings({}), [])
        self.assertTrue(any("Possible memory leak" in x["detail"] for x in r))


class TestStorageAndSettings(unittest.TestCase):
    def test_database_roundtrip_and_clear(self):
        with tempfile.TemporaryDirectory() as d:
            db = Database(Path(d) / "t.db")
            now = int(time.time())
            db.write_process_samples([("1:1", now - 100 + i * 10, "a.exe", 1, 100 + i) for i in range(10)])
            db.write_system_samples([(now - 50, 40.0, 10.0, 1, 0.0, 0.0, 0.0, 0.0)])
            g = db.process_growth(now - 200)
            self.assertEqual(len(g), 1)
            self.assertEqual(g[0]["last"] - g[0]["first"], 9)
            self.assertEqual(len(db.system_series(now - 200)["t"]), 1)
            self.assertEqual(db.process_series("1:1'; DROP TABLE process_samples;--", now - 200)["t"], [])
            self.assertEqual(db.counts(), (1, 10))
            db.clear()
            self.assertEqual(db.counts(), (0, 0))
            db.close()

    def test_settings_validation(self):
        s = validate_settings({"refresh_interval": 999, "theme": "neon", "notifications": "yes", "ram_warn_pct": 95,
                               "ram_crit_pct": 90, "bogus": 1})
        self.assertEqual(s["refresh_interval"], 10)
        self.assertEqual(s["theme"], "dark")
        self.assertFalse(s["notifications"] and s["start_with_windows"])
        self.assertGreater(s["ram_crit_pct"], s["ram_warn_pct"])
        self.assertNotIn("bogus", s)
        self.assertFalse(validate_settings({})["start_with_windows"])  # off by default

    def test_settings_persist(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "s.json"
            Settings(p).update({"theme": "light", "retention_days": 14})
            again = Settings(p).get()
            self.assertEqual((again["theme"], again["retention_days"]), ("light", 14))


def run_tests() -> int:
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


# ============================================================================
# Entry point
# ============================================================================
def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=APP_NAME)
    parser.add_argument("--test", action="store_true", help="run the unit tests and exit")
    parser.add_argument("--export-icon", metavar="PATH", help="write the app icon as .ico and exit")
    parser.add_argument("--minimized", action="store_true", help="start minimised")
    parser.add_argument("--disable-gpu", action="store_true", help="software rendering (troubleshooting)")
    args, qt_args = parser.parse_known_args(argv if argv is not None else sys.argv[1:])

    if args.test:
        return run_tests()
    if args.disable_gpu:
        os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = (os.environ.get("QTWEBENGINE_CHROMIUM_FLAGS", "") + " --disable-gpu").strip()

    directory = data_dir()
    setup_logging(directory)
    if IS_WINDOWS:
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("WhereDidMyRAMGo.App.1")
        except Exception:
            pass

    app = QApplication([sys.argv[0]] + qt_args)
    app.setApplicationName(APP_NAME)
    app.setQuitOnLastWindowClosed(False)
    icon = make_app_icon()
    app.setWindowIcon(icon)

    if args.export_icon:
        ok = icon.pixmap(256, 256).save(args.export_icon, "ICO")
        print(("Wrote " + args.export_icon) if ok else "Could not write icon")
        return 0 if ok else 1

    settings = Settings(directory / "settings.json")
    db = Database(directory / "history.db")
    worker = MonitorWorker(settings, db)
    bridge = Bridge(settings, db, worker)
    window = MainWindow(settings, db, worker, bridge, icon)
    app.aboutToQuit.connect(lambda: (worker.stop(), worker.wait(3000)))
    worker.start()

    if args.minimized or settings.get()["launch_minimized"]:
        window.showMinimized()
    else:
        window.show()
    log.info("%s %s started (admin=%s)", APP_NAME, APP_VERSION, is_admin())
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
