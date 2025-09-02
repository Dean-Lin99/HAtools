# device_updater_with_server.py
# -*- coding: utf-8 -*-

import sys
import os
import re
import csv
import ipaddress
import hashlib
import base64
import datetime
import socket
import time
import queue
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote, quote_plus, urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import secrets
import copy

import pandas as pd
import requests

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QFileDialog, QLineEdit, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView, QCheckBox,
    QMessageBox, QAbstractItemView, QProgressBar, QGroupBox, QSplitter,
    QTextEdit, QFormLayout
)
from PySide6.QtCore import Qt, QThread, Signal, QTimer, QEventLoop


# =========================
# 固定參數（不提供 UI）
# =========================
DEFAULT_BYPASS_PROXY = True
DEFAULT_PORT_CANDIDATES = [80, 8080, 3377]
DEFAULT_WORKERS = 32
DEFAULT_RETRIES = 2
DEFAULT_TIMEOUT = 10
DEFAULT_COMPANY_ID = "FSC"
DEFAULT_RESPONSE = "123"
DEFAULT_VERSION = "init"


# =========================
# Excel 匯入規則
# =========================
def is_nullish(v) -> bool:
    if v is None:
        return True
    s = str(v).strip()
    return s == "" or s.lower() in ("nan", "none")


def is_valid_ip(s):
    try:
        ipstr = str(s).replace(" ", "").strip()
        if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ipstr):
            return False
        ip = ipaddress.ip_address(ipstr)
        if ip.is_multicast or ip.is_reserved or ip.is_loopback or ip.is_unspecified or ip.is_link_local:
            return False
        if ipstr in ("255.255.255.255", "0.0.0.0", "255.255.255.0", "255.255.0.0", "255.0.0.0"):
            return False
        return ip.version == 4
    except Exception:
        return False


def find_ip_col_index(df):
    for col in range(len(df.columns)):
        valid = sum(1 for cell in df.iloc[:, col] if is_valid_ip(cell))
        if valid >= 2:
            return col
    return None


def is_first_column_serial(col, min_length=5):
    numbers = []
    for val in col:
        if is_nullish(val):
            numbers.append(None)
            continue
        try:
            numbers.append(int(str(val).strip()))
        except:
            numbers.append(None)
    max_streak = 0
    streak = 0
    prev = None
    for n in numbers:
        if n is not None and (prev is None or n == prev + 1):
            streak += 1
        else:
            streak = 1 if n is not None else 0
        prev = n
        max_streak = max(max_streak, streak)
    return max_streak >= min_length


def extract_room_no_from_row(row, type_col_idx, skip_first_col=False):
    parts = []
    for i in range(type_col_idx):
        if skip_first_col and i == 0:
            continue
        val = row[i]
        if is_nullish(val):
            continue
        s = str(val).strip()
        if re.fullmatch(r"\d+", s):
            parts.append(s)
    return "".join(parts)


def process_one_sheet(df_raw):
    ip_col_idx = find_ip_col_index(df_raw)
    if ip_col_idx is None or ip_col_idx < 2:
        return None
    devtype_col_idx = ip_col_idx - 2
    name_col_idx = ip_col_idx - 1

    skip_first = False
    if df_raw.shape[1] > 0:
        try:
            skip_first = is_first_column_serial(df_raw.iloc[:, 0], min_length=5)
        except Exception:
            skip_first = False

    devices = []
    for _, row in df_raw.iterrows():
        ip_raw = row[ip_col_idx] if ip_col_idx < len(row) else ""
        ip = "" if is_nullish(ip_raw) else str(ip_raw).replace(" ", "").strip()
        if not is_valid_ip(ip):
            continue

        dev_type_raw = row[devtype_col_idx] if devtype_col_idx >= 0 else ""
        dev_type = "" if is_nullish(dev_type_raw) else str(dev_type_raw).strip()
        if "管理中心" in dev_type:
            continue

        name_raw = row[name_col_idx] if name_col_idx >= 0 else ""
        name = "" if is_nullish(name_raw) else str(name_raw).strip()

        room_no = extract_room_no_from_row(row, devtype_col_idx, skip_first)
        devices.append({
            "設備類型": dev_type,
            "名稱": name,
            "IP": ip,
            "房號": room_no,
        })

    if not devices:
        return None

    df = pd.DataFrame(devices).drop_duplicates(subset="IP")
    return df.to_dict(orient="records")


def load_excel_and_parse_devices(file_path):
    xls = pd.ExcelFile(file_path)

    if "貼紙印製" in xls.sheet_names:
        df_raw = pd.read_excel(file_path, sheet_name="貼紙印製", header=None, dtype=str)
        res = process_one_sheet(df_raw)
        if res is not None:
            return res

    for sheet in xls.sheet_names:
        if sheet == "貼紙印製":
            continue
        df_raw = pd.read_excel(file_path, sheet_name=sheet, header=None, dtype=str)
        res = process_one_sheet(df_raw)
        if res is not None:
            return res

    return []


# =========================
# 內建檔案伺服器（多檔、verify 映射、進度追蹤）
# =========================
class ServerLogSink:
    def __init__(self):
        self.q = queue.Queue()

    def push(self, msg: str):
        self.q.put(msg)

    def drain(self, n=200):
        out = []
        for _ in range(n):
            try:
                out.append(self.q.get_nowait())
            except queue.Empty:
                break
        return out


def _primary_lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip and ip != "127.0.0.1":
            return ip
    except Exception:
        pass
    return "127.0.0.1"


def httpdate(ts: float) -> str:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")


def file_md5_and_size(path: str):
    md5 = hashlib.md5()
    size = 0
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            md5.update(chunk)
            size += len(chunk)
    return md5.hexdigest(), size


def md5_base64_from_hex(hexstr: str) -> str:
    try:
        raw = bytes.fromhex(hexstr)
        return base64.b64encode(raw).decode("ascii")
    except Exception:
        return ""


def guess_content_type(filename: str) -> str:
    name = filename.lower()
    if name.endswith(".apk"):
        return "application/vnd.android.package-archive"
    if name.endswith(".pkg"):
        return "application/octet-stream"
    if name.endswith(".bin"):
        return "application/octet-stream"
    if name.endswith(".zip"):
        return "application/zip"
    return "application/octet-stream"


def build_file_meta(path: str) -> dict:
    if not path or not os.path.isfile(path):
        raise FileNotFoundError(f"file not found: {path}")
    fn = os.path.basename(path)
    md5_hex, size = file_md5_and_size(path)
    return {
        "path": path,
        "filename": fn,
        "size": size,
        "md5_hex": md5_hex,
        "md5_b64": md5_base64_from_hex(md5_hex),
        "last_modified": httpdate(os.path.getmtime(path)),
        "etag": f"\"{md5_hex}\"",
        "content_type": guess_content_type(fn),
    }


class DownloadHandler(BaseHTTPRequestHandler):
    # === 固定安全預設（UI 不再開放更改） ===
    protocol_version = "HTTP/1.1"
    header_profile = "standard"     # 固定
    force_connection = "close"      # 固定
    accept_ranges = True            # 固定
    include_meta_headers = True     # 固定

    # === 既有功能 ===
    registry = {}                   # route -> meta（/files/<filename>）
    default_route = None
    ctype_override = {}             # route -> override
    verify_map = {}                 # verify(str) -> route(str)
    lock = threading.Lock()
    log_sink: ServerLogSink = None

    # === 新增：傳輸進度追蹤 ===
    progress_lock = threading.Lock()
    # key -> dict(ip, filename, route, total, sent, start_ts, last_ts, done)
    progress_map = {}

    @classmethod
    def _progress_key(cls, client_ip: str, route: str, req_id: int) -> str:
        return f"{client_ip}|{route}|{req_id}"

    @classmethod
    def progress_start(cls, client_ip: str, filename: str, route: str, total: int, req_id: int):
        key = cls._progress_key(client_ip, route, req_id)
        with cls.progress_lock:
            cls.progress_map[key] = {
                "ip": client_ip, "filename": filename, "route": route,
                "total": int(total), "sent": 0,
                "start_ts": time.time(), "last_ts": time.time(),
                "done": False
            }
        return key

    @classmethod
    def progress_add(cls, key: str, add_bytes: int):
        with cls.progress_lock:
            if key in cls.progress_map:
                e = cls.progress_map[key]
                e["sent"] = min(e["total"], e["sent"] + int(add_bytes))
                e["last_ts"] = time.time()

    @classmethod
    def progress_done(cls, key: str):
        with cls.progress_lock:
            if key in cls.progress_map:
                e = cls.progress_map[key]
                e["sent"] = max(e["sent"], 0)
                e["done"] = True
                e["last_ts"] = time.time()

    @classmethod
    def snapshot_progress(cls):
        with cls.progress_lock:
            return copy.deepcopy(cls.progress_map)

    @classmethod
    def has_active_transfers(cls) -> bool:
        with cls.progress_lock:
            for e in cls.progress_map.values():
                if not e.get("done"):
                    return True
        return False

    # 多廠固定下載端點別名
    VENDOR_DOWNLOAD_PATHS = {
        "/api/cmd/download",
        "/cmd/download",
        "/download",
        "/api/download",
        "/firmware/download",
        "/api/firmware/download",
    }
    VERIFY_KEYS = ("verify", "v", "token", "auth", "key")
    FILENAME_KEYS = ("filename", "file", "name", "fn")

    @classmethod
    def register_verify(cls, verify: str, route: str):
        if not verify or not route:
            return
        with cls.lock:
            cls.verify_map[verify] = route

    @classmethod
    def clear_verify(cls, verify: str):
        with cls.lock:
            cls.verify_map.pop(verify, None)

    def _get_meta_by_route(self, route: str):
        with DownloadHandler.lock:
            meta = DownloadHandler.registry.get(route)
            return meta

    def _find_route_by_filename(self, filename: str) -> str | None:
        if not filename:
            return None
        with DownloadHandler.lock:
            for route, meta in DownloadHandler.registry.items():
                if meta and meta.get("filename") == filename:
                    return route
        return None

    def _q(self, raw_path: str) -> dict:
        try:
            return parse_qs(urlparse(raw_path).query, keep_blank_values=True)
        except Exception:
            return {}

    def _pick_default_route(self) -> str | None:
        with DownloadHandler.lock:
            return DownloadHandler.default_route

    def _resolve_vendor_download_route(self, raw_path: str) -> str | None:
        parsed = urlparse(raw_path)
        path = parsed.path
        qs = self._q(raw_path)

        segs = [s for s in path.split("/") if s]
        verify_in_path = None
        if len(segs) >= 2 and ("/" + "/".join(segs[:2])) in DownloadHandler.VENDOR_DOWNLOAD_PATHS:
            verify_in_path = segs[2] if len(segs) >= 3 else None
        elif len(segs) >= 3 and ("/" + "/".join(segs[:3])) in DownloadHandler.VENDOR_DOWNLOAD_PATHS:
            verify_in_path = segs[3] if len(segs) >= 4 else None

        verify_val = (verify_in_path or "").strip()
        if not verify_val:
            for k in DownloadHandler.VERIFY_KEYS:
                tmp = (qs.get(k, [""])[0] or "").strip()
                if tmp:
                    verify_val = tmp
                    break

        if verify_val:
            with DownloadHandler.lock:
                route = DownloadHandler.verify_map.get(verify_val)
            if route:
                return route

        filename = ""
        for k in DownloadHandler.FILENAME_KEYS:
            v = (qs.get(k, [""])[0] or "").strip()
            if v:
                filename = v
                break
        if filename:
            route = self._find_route_by_filename(filename)
            if route:
                return route

        return self._pick_default_route()

    def _resolve_route_for_request(self, raw_path: str) -> str | None:
        path = raw_path.split("?", 1)[0]
        if path == "/healthz":
            return "__health__"
        if path in DownloadHandler.VENDOR_DOWNLOAD_PATHS or any(
            path.startswith(p + "/") for p in DownloadHandler.VENDOR_DOWNLOAD_PATHS
        ):
            route = self._resolve_vendor_download_route(raw_path)
            if route:
                return route
            else:
                return None
        return path

    @classmethod
    def update_registry_and_opts(cls, *, registry, default_route, ctype_override):
        with cls.lock:
            cls.registry = registry.copy()
            cls.default_route = default_route
            cls.ctype_override = ctype_override.copy() if ctype_override else {}

    def _log(self, code, msg=""):
        try:
            client = self.client_address[0]
        except Exception:
            client = "-"
        line = f"[{time.strftime('%H:%M:%S')}] {client} {self.command} {self.path} -> {code} {msg}".strip()
        if DownloadHandler.log_sink:
            DownloadHandler.log_sink.push(line)

    def _resolved_ctype(self, route: str, meta: dict) -> str:
        ct = DownloadHandler.ctype_override.get(route, "") or meta["content_type"]
        return ct

    def _send_headers(self, route: str, meta: dict, status: int, length: int, content_range: str | None = None):
        try:
            self.send_response(status)
            self.send_header("Cache-Control", "no-cache, private")
            ct = "text/plain; charset=utf-8" if route == "__health__" else self._resolved_ctype(route, meta)
            self.send_header("Content-Type", ct)
            self.send_header("Connection", DownloadHandler.force_connection)
            self.send_header("Content-Length", str(length))
            if DownloadHandler.accept_ranges and content_range:
                self.send_header("Content-Range", content_range)
            if route != "__health__":
                self.send_header("Content-Disposition", f'attachment; filename="{meta.get("filename","file")}"')
                if DownloadHandler.include_meta_headers:
                    self.send_header("ETag", meta.get("etag", ""))
                    self.send_header("Last-Modified", meta.get("last_modified", ""))
                    if meta.get("md5_b64"):
                        self.send_header("Content-MD5", meta["md5_b64"])
                    if meta.get("md5_hex"):
                        self.send_header("X-MD5", meta["md5_hex"])
            self.end_headers()
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _serve_404(self, msg="Not Found"):
        body = msg.encode("utf-8", "ignore")
        self.send_response(404)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command == "GET":
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass
        self._log(404, msg)

    def do_HEAD(self):
        route = self._resolve_route_for_request(self.path)
        if route == "__health__":  # 健康檢查
            msg = b"ok"
            self._send_headers(route, {"filename": "health"}, 200, len(msg))
            self._log(200, "healthz")
            return
        if not route:
            return self._serve_404("No route")
        meta = self._get_meta_by_route(route)
        if not meta:
            return self._serve_404("No such file")
        length = meta["size"]
        self._send_headers(route, meta, 200, length)
        self._log(200, f"HEAD size={meta['size']} route={route}")

    def do_GET(self):
        route = self._resolve_route_for_request(self.path)
        if route == "__health__":
            msg = b"ok"
            self._send_headers(route, {"filename": "health"}, 200, len(msg))
            try:
                self.wfile.write(msg)
            except (BrokenPipeError, ConnectionResetError):
                pass
            self._log(200, "healthz")
            return
        if not route:
            return self._serve_404("No route")
        meta = self._get_meta_by_route(route)
        if not meta:
            return self._serve_404("No such file (route not in registry)")

        size = meta["size"]
        client_ip = self.client_address[0] if self.client_address else "-"
        req_id = id(self)  # 區分同一 IP 的並行請求
        progress_key = None

        range_header = self.headers.get("Range", "")
        if range_header and range_header.startswith("bytes="):
            try:
                rng = range_header.split("=", 1)[1]
                start_s, end_s = (rng.split("-", 1) + [""])[:2]
                start = int(start_s) if start_s else 0
                end = int(end_s) if end_s else size - 1
                start = max(0, start)
                end = min(size - 1, end)
                length = end - start + 1
                self._send_headers(route, meta, 206, length, content_range=f"bytes {start}-{end}/{size}")
                progress_key = DownloadHandler.progress_start(client_ip, meta["filename"], route, length, req_id)
                sent = 0
                with open(meta["path"], "rb") as f:
                    f.seek(start)
                    remaining = length
                    while remaining > 0:
                        chunk = f.read(min(64 * 1024, remaining))
                        if not chunk:
                            break
                        try:
                            self.wfile.write(chunk)
                        except (BrokenPipeError, ConnectionResetError):
                            self._log(499, f"client closed, sent:{sent}/{length} route={route}")
                            return
                        sent += len(chunk)
                        remaining -= len(chunk)
                        DownloadHandler.progress_add(progress_key, len(chunk))
                DownloadHandler.progress_done(progress_key)
                self._log(206, f"RANGE {start}-{end} route={route}")
                return
            except Exception as e:
                return self._serve_404(f"Bad Range: {e}")

        # 標準全檔下載
        self._send_headers(route, meta, 200, size)
        progress_key = DownloadHandler.progress_start(client_ip, meta["filename"], route, size, req_id)
        sent = 0
        try:
            with open(meta["path"], "rb") as f:
                while True:
                    chunk = f.read(64 * 1024)
                    if not chunk:
                        break
                    try:
                        self.wfile.write(chunk)
                    except (BrokenPipeError, ConnectionResetError):
                        self._log(499, f"client closed, sent:{sent}/{size} route={route}")
                        return
                    sent += len(chunk)
                    DownloadHandler.progress_add(progress_key, len(chunk))
            DownloadHandler.progress_done(progress_key)
            self._log(200, f"sent:{sent}/{size} route={route}")
        except Exception as e:
            self._log(500, f"error:{e}")

    def log_message(self, fmt, *args):  # 靜音
        pass


class QuietThreadingHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True  # 避免重啟卡住

    def handle_error(self, request, client_address):
        exc_type, exc, tb = sys.exc_info()
        if isinstance(exc, (ConnectionResetError, BrokenPipeError, TimeoutError)):
            try:
                DownloadHandler.log_sink and DownloadHandler.log_sink.push(
                    f"[{time.strftime('%H:%M:%S')}] {client_address[0]} connection closed early"
                )
            finally:
                return
        return super().handle_error(request, client_address)


class FileServerThread(QThread):
    started_ok = Signal(str)
    failed = Signal(str)
    stopped = Signal()

    def __init__(self, bind_ip, port, log_sink: ServerLogSink):
        super().__init__()
        self.bind_ip = bind_ip
        self.port = int(port)
        self.httpd = None
        self.log_sink = log_sink

    def run(self):
        try:
            DownloadHandler.log_sink = self.log_sink
            self.httpd = QuietThreadingHTTPServer((self.bind_ip, self.port), DownloadHandler)
            self.started_ok.emit(f"http://{self.bind_ip}:{self.port}/")
            DownloadHandler.log_sink and DownloadHandler.log_sink.push(
                f"[{time.strftime('%H:%M:%S')}] file server started on {self.bind_ip}:{self.port}"
            )
            self.httpd.serve_forever()
        except Exception as e:
            self.failed.emit(str(e))

    def stop(self):
        try:
            if self.httpd:
                self.httpd.shutdown()
        finally:
            self.stopped.emit()


# =========================
# Requests 工作階段（可繞過系統代理）
# =========================
def create_session(bypass_proxy: bool = True) -> requests.Session:
    s = requests.Session()
    if bypass_proxy:
        s.trust_env = False
        s.proxies = {}
    return s


# =========================
# 更新工具（分開偵測 info_port / cmd_endpoint）
# =========================
CMD_PATH_CANDIDATES = [
    "/cmd/sync",
    "/api/cmd/sync",
    "/cmd",
    "/api/cmd",
    "/device/cmd",
    "/api/device/cmd",
    "/upgrade",
    "/api/upgrade",
    "/api/remote/upgrade",
    "/command",
    "/api/command",
]


def try_http_probe(ip, port, path, timeout: float, session: requests.Session) -> bool:
    try:
        r = session.get(f"http://{ip}:{port}{path}", timeout=timeout)
        return 200 <= r.status_code < 500
    except requests.RequestException:
        return False


def detect_info_port(ip, port_candidates: list[int], timeout=1.0, session: requests.Session | None = None):
    s = session or create_session(True)
    for p in port_candidates:
        if try_http_probe(ip, p, "/device/info", timeout=timeout, session=s):
            return p
    for p in port_candidates:
        if try_http_probe(ip, p, "/", timeout=timeout, session=s):
            return p
    return None


def _endpoint_accepts_post(session: requests.Session, url: str, timeout: float) -> bool:
    try:
        resp = session.options(url, timeout=timeout)
        allow = (resp.headers.get("Allow", "") or "").upper()
        if "POST" in allow:
            return True
    except requests.RequestException:
        pass
    try:
        resp = session.post(url, json={"action": "noop"}, timeout=timeout)
        if resp.status_code != 405:
            return True
    except requests.RequestException:
        pass
    return False


def detect_cmd_endpoint(ip, port_candidates: list[int], timeout=1.5, session: requests.Session | None = None):
    s = session or create_session(True)
    for p in port_candidates:
        for path in CMD_PATH_CANDIDATES:
            url = f"http://{ip}:{p}{path}"
            if _endpoint_accepts_post(s, url, timeout=timeout):
                return p, path
    return None, None


def get_device_room(ip, port, timeout=3, session: requests.Session | None = None):
    s = session or create_session(True)
    try:
        r = s.get(f"http://{ip}:{port}/device/info", timeout=timeout)
        if r.status_code == 200:
            try:
                data = r.json()
                room = str(data.get("room_id", "")).strip()
                return room
            except Exception:
                return ""
    except requests.RequestException:
        pass
    return ""


def gen_token_and_verify(room_no: str):
    now = datetime.datetime.now()
    text = f"remote{now.strftime('%Y%m%d')}{room_no}{now.strftime('%H%M%S')}".lower()
    md5_str = hashlib.md5(text.encode("utf-8")).hexdigest()
    return md5_str, md5_str


def gen_verify_opaque_like():
    def rand_hex(n): return secrets.token_hex(n // 2)
    payload = {
        "iv": base64.b64encode(secrets.token_bytes(16)).decode("ascii"),
        "value": base64.b64encode(secrets.token_bytes(64)).decode("ascii"),
        "mac": rand_hex(64),
    }
    raw = json.dumps(payload, separators=(',', ':')).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def tcp_port_open(ip: str, port: int, timeout: float = 0.8) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False


class UpdateWorker(QThread):
    one_done = Signal(dict)
    progress = Signal(int, int)
    all_done = Signal()

    def __init__(self, targets, fw_items, default_index,
                 srv_host, srv_port,
                 use_vendor_path, verify_mode, verify_fixed,
                 company_id, response, version, timeout, retries, max_workers,
                 port_candidates, bypass_proxy: bool):
        super().__init__()
        self.targets = targets
        self.fw_items = fw_items
        self.default_index = max(0, int(default_index)) if fw_items else -1
        self.srv_host = srv_host.strip()
        self.srv_port = int(srv_port)
        self.use_vendor_path = use_vendor_path
        self.verify_mode = verify_mode      # 'none' | 'fixed' | 'md5' | 'opaque'
        self.verify_fixed = (verify_fixed or "").strip()
        self.company_id = company_id
        self.response = response
        self.version = version
        self.timeout = timeout
        self.retries = retries
        self.max_workers = max(1, int(max_workers))
        self.port_candidates = port_candidates or DEFAULT_PORT_CANDIDATES
        self.bypass_proxy = bool(bypass_proxy)

    def _pick_fw_for_device(self, dev):
        text = ((dev.get("設備類型", "") or "") + " " + (dev.get("名稱", "") or "")).lower()
        for i, it in enumerate(self.fw_items):
            kw = (it.get("keyword") or "").lower().strip()
            if kw and kw in text:
                return i, it
        if 0 <= self.default_index < len(self.fw_items):
            return self.default_index, self.fw_items[self.default_index]
        return 0, self.fw_items[0]

    def _make_verify(self, room: str):
        if self.verify_mode == "fixed":
            return self.verify_fixed
        if self.verify_mode == "md5":
            _token, _verify = gen_token_and_verify(room)
            return _verify
        if self.verify_mode == "opaque":
            return gen_verify_opaque_like()
        return ""

    def run(self):
        total, done = len(self.targets), 0
        info_port_cache = {}
        cmd_ep_cache = {}

        session = create_session(self.bypass_proxy)

        def do_one(dev):
            ip = (dev.get("IP") or "").strip()
            room_excel = (dev.get("房號") or "").strip()

            reachable = [p for p in self.port_candidates if tcp_port_open(ip, p, timeout=0.8)]
            if not reachable:
                return {
                    "ip": ip, "room": room_excel or "0", "port": "-",
                    "code": -1,
                    "detail": f"[port_scan=none] 目標無任何開放的候選埠（{self.port_candidates}），可能離線/防火牆阻擋"
                }

            info_port = info_port_cache.get(ip)
            if info_port is None:
                info_port = detect_info_port(ip, reachable, timeout=1.0, session=session)
                info_port_cache[ip] = info_port

            cmd_port, cmd_path = cmd_ep_cache.get(ip, (None, None))
            if cmd_port is None or cmd_path is None:
                cmd_port, cmd_path = detect_cmd_endpoint(ip, reachable, timeout=1.5, session=session)
                if cmd_port is None and 3377 in reachable:
                    cmd_port, cmd_path = 3377, "/cmd/sync"
                cmd_ep_cache[ip] = (cmd_port, cmd_path)

            if not cmd_port or not cmd_path:
                return {
                    "ip": ip, "room": room_excel or "0", "port": "-",
                    "code": -1,
                    "detail": f"[info_port={info_port} cmd=?] 無法找到可接受 POST 的 API（試過端口 {reachable}、路徑 {', '.join(CMD_PATH_CANDIDATES)}）"
                }

            room_from_dev = ""
            if info_port:
                room_from_dev = get_device_room(ip, info_port, session=session) or ""
            if not room_from_dev and cmd_port and cmd_port != info_port:
                room_from_dev = get_device_room(ip, cmd_port, session=session) or ""
            room = room_from_dev or room_excel or "0"

            token, _ = gen_token_and_verify(room)

            idx, fw = self._pick_fw_for_device(dev)
            route = fw["route"]
            filename = fw["filename"]
            fw_size = fw["size"]
            fw_md5 = fw["md5_hex"]

            verify = self._make_verify(room)
            if self.use_vendor_path:
                if not verify:
                    verify = gen_verify_opaque_like()
                DownloadHandler.register_verify(verify, route)
                fw_url = f"http://{self.srv_host}:{self.srv_port}/api/cmd/download?verify={quote_plus(verify)}"
            else:
                fw_url = f"http://{self.srv_host}:{self.srv_port}{route}"
                if verify:
                    fw_url = f"{fw_url}?verify={quote_plus(verify)}"

            action_candidates = ["sw_upgrade", "upgrade", "sw-upgrade"]

            def try_post(url: str, act: str):
                body = {
                    "action": act,
                    "filename": filename,
                    "path": fw_url,
                    "version": self.version,
                    "size": fw_size,
                    "hash": fw_md5,
                }
                headers = {
                    "Content-Type": "application/json",
                    "company-id": self.company_id,
                    "token": token,
                    "response": self.response,
                    "Connection": "close",
                }
                return session.post(url, json=body, headers=headers, timeout=self.timeout)

            base_url = f"http://{ip}:{cmd_port}{cmd_path}"
            last_code, last_detail = None, ""
            tried = 0

            for attempt in range(1, self.retries + 1):
                sent = False
                for act in action_candidates:
                    try:
                        r = try_post(base_url, act)
                        tried += 1
                        last_code = r.status_code
                        last_detail = (r.text or "").strip()
                        sent = True
                        if 200 <= r.status_code < 300:
                            break
                        if r.status_code in (400, 401, 403):
                            break
                        if r.status_code in (404, 405):
                            ports_to_try = []
                            if info_port and info_port not in ports_to_try:
                                ports_to_try.append(info_port)
                            if cmd_port not in ports_to_try:
                                ports_to_try.append(cmd_port)
                            for p in reachable:
                                if p not in ports_to_try:
                                    ports_to_try.append(p)

                            done_fallback = False
                            for p in ports_to_try:
                                for alt_path in CMD_PATH_CANDIDATES:
                                    if p == cmd_port and alt_path == cmd_path:
                                        continue
                                    alt_url = f"http://{ip}:{p}{alt_path}"
                                    for alt_act in action_candidates:
                                        try:
                                            rr = try_post(alt_url, alt_act)
                                            tried += 1
                                            last_code = rr.status_code
                                            last_detail = (rr.text or "").strip()
                                            if 200 <= rr.status_code < 300 or rr.status_code in (400, 401, 403):
                                                cmd_ep_cache[ip] = (p, alt_path)
                                                cmd_port, cmd_path = p, alt_path
                                                base_url = alt_url
                                                done_fallback = True
                                                break
                                        except requests.RequestException:
                                            pass
                                    if done_fallback:
                                        break
                                if done_fallback:
                                    break
                            if done_fallback and (200 <= last_code < 300 or last_code in (400, 401, 403)):
                                break
                    except requests.exceptions.ConnectTimeout:
                        last_code, last_detail = -1, f"連線逾時（#{attempt}）"
                    except requests.exceptions.ReadTimeout:
                        last_code, last_detail = -1, f"讀取逾時（#{attempt}）"
                    except requests.exceptions.RequestException as e:
                        last_code, last_detail = -1, f"連線錯誤：{e}（#{attempt}）"
                    except Exception as e:
                        last_code, last_detail = -1, f"例外：{e}（#{attempt}）"
                if sent and (last_code is not None) and (200 <= last_code < 300 or last_code in (400, 401, 403, 404, 405)):
                    break

            detail_prefix = f"[tries={tried} info_port={info_port} cmd_port={cmd_port} cmd_path={cmd_path} fw={filename} url={fw_url}] "
            last_detail = (detail_prefix + last_detail)[:500]
            return {"ip": ip, "room": room, "port": str(cmd_port), "code": last_code, "detail": last_detail}

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = [pool.submit(do_one, d) for d in self.targets]
            for fut in as_completed(futures):
                info = fut.result()
                self.one_done.emit(info)
                done += 1
                self.progress.emit(done, total)

        self.all_done.emit()


# =========================
# GUI
# =========================
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("設備更新工具")
        self.resize(1400, 960)

        self.devices = []

        self.server_thread: FileServerThread | None = None
        self.server_running = False
        self.log_sink = ServerLogSink()

        # 韌體清單：每筆 {path, filename, route, size, md5_hex, keyword, ctype_override}
        self.fw_items: list[dict] = []
        self.default_fw_index = -1

        # 下載進度 rows 映射
        self.dl_rows = {}  # key -> row

        self._build_ui()

        self.timer = QTimer(self)
        self.timer.timeout.connect(self._on_timer)
        self.timer.start(500)

    # ---------- UI ----------
    def _build_ui(self):
        root = QSplitter(Qt.Vertical)
        self.setCentralWidget(root)

        top = QWidget()
        top_l = QVBoxLayout(top)
        top_l.setSpacing(8)

        # 匯入列
        row1 = QHBoxLayout()
        btn_import = QPushButton("匯入 Excel")
        btn_import.clicked.connect(self.on_import)
        row1.addWidget(btn_import)
        row1.addStretch(1)
        top_l.addLayout(row1)

        # 伺服器（極簡）
        gb_srv = QGroupBox("檔案伺服器")
        f = QFormLayout(gb_srv)

        self.le_public_host = QLineEdit()
        self.le_public_host.setText(_primary_lan_ip())
        self.le_srv_port = QLineEdit("8000")

        self.btn_srv_toggle = QPushButton("啟動伺服器")
        self.btn_srv_toggle.clicked.connect(self.on_toggle_server)

        f.addRow("Server Host（本機 IP）：", self.le_public_host)
        f.addRow("File Server Port：", self.le_srv_port)
        f.addRow(self.btn_srv_toggle)

        # 韌體清單
        gb_fw = QGroupBox("韌體清單")
        vfw = QVBoxLayout(gb_fw)
        btns = QHBoxLayout()
        btn_add_fw = QPushButton("加入韌體檔")
        btn_add_fw.clicked.connect(self.on_add_fw)
        btn_del_fw = QPushButton("移除選取")
        btn_del_fw.clicked.connect(self.on_del_fw)
        btn_set_default = QPushButton("設為預設")
        btn_set_default.clicked.connect(self.on_set_default_fw)
        btns.addWidget(btn_add_fw)
        btns.addWidget(btn_del_fw)
        btns.addWidget(btn_set_default)
        btns.addStretch(1)
        vfw.addLayout(btns)

        self.tbl_fw = QTableWidget(0, 6)
        self.tbl_fw.setHorizontalHeaderLabels(["預設", "檔名", "URL 路徑", "匹配關鍵字", "Content-Type(覆寫)", "本地檔案"])
        hh = self.tbl_fw.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        for i in range(1, 6):
            hh.setSectionResizeMode(i, QHeaderView.ResizeToContents if i != 5 else QHeaderView.Stretch)
        self.tbl_fw.setEditTriggers(QAbstractItemView.DoubleClicked | QAbstractItemView.SelectedClicked)
        vfw.addWidget(self.tbl_fw)

        # 伺服器請求日誌
        gb_log = QGroupBox("伺服器請求日誌")
        vlog = QVBoxLayout(gb_log)
        self.te_logs = QTextEdit()
        self.te_logs.setReadOnly(True)
        vlog.addWidget(self.te_logs)

        srv_row = QHBoxLayout()
        srv_row.addWidget(gb_srv, 3)
        srv_row.addWidget(gb_fw, 5)
        srv_row.addWidget(gb_log, 4)
        top_l.addLayout(srv_row)

        # 控制列（僅搜尋與全選/取消）
        ctrl = QHBoxLayout()
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("搜尋（設備類型 / 名稱 / IP / 房號）")
        self.search_edit.textChanged.connect(self.apply_filter)
        ctrl.addWidget(self.search_edit, 3)
        btn_all = QPushButton("全選")
        btn_all.clicked.connect(lambda: self.set_all_checked(True))
        btn_none = QPushButton("取消全選")
        btn_none.clicked.connect(lambda: self.set_all_checked(False))
        ctrl.addWidget(btn_all)
        ctrl.addWidget(btn_none)
        ctrl.addStretch(1)
        top_l.addLayout(ctrl)

        # 裝置清單
        self.tbl = QTableWidget(0, 5)
        self.tbl.setHorizontalHeaderLabels(["選取", "設備類型", "名稱", "IP", "房號"])
        self.tbl.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tbl.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tbl.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tbl.setAlternatingRowColors(True)
        top_l.addWidget(self.tbl, 1)

        root.addWidget(top)

        # 下半：執行與結果 + 下載進度
        bottom = QWidget()
        b_l = QVBoxLayout(bottom)
        b_l.setSpacing(8)
        run_row = QHBoxLayout()
        self.btn_start = QPushButton("開始更新")
        self.btn_start.clicked.connect(self.start_update)
        self.btn_export = QPushButton("匯出結果 CSV")
        self.btn_export.clicked.connect(self.export_results)
        run_row.addWidget(self.btn_start)
        run_row.addStretch(1)
        run_row.addWidget(self.btn_export)
        b_l.addLayout(run_row)

        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        b_l.addWidget(self.progress)

        self.tbl_res = QTableWidget(0, 5)
        self.tbl_res.setHorizontalHeaderLabels(["IP", "房號", "Port", "狀態碼", "訊息"])
        rh = self.tbl_res.horizontalHeader()
        for i in range(5):
            rh.setSectionResizeMode(i, QHeaderView.ResizeToContents)
        rh.setStretchLastSection(True)
        self.tbl_res.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tbl_res.setAlternatingRowColors(True)
        b_l.addWidget(self.tbl_res, 1)

        # 下載進度監看
        gb_dl = QGroupBox("下載進度")
        vdl = QVBoxLayout(gb_dl)
        self.tbl_dl = QTableWidget(0, 5)
        self.tbl_dl.setHorizontalHeaderLabels(["IP", "檔名", "傳輸量", "進度", "狀態"])
        hd = self.tbl_dl.horizontalHeader()
        hd.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        hd.setSectionResizeMode(1, QHeaderView.Stretch)
        hd.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        hd.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        hd.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.tbl_dl.setEditTriggers(QAbstractItemView.NoEditTriggers)
        vdl.addWidget(self.tbl_dl)
        b_l.addWidget(gb_dl, 1)

        root.addWidget(bottom)
        root.setSizes([560, 400])

    # ---------- 檔案伺服器 ----------
    def _rebuild_server_registry(self):
        reg = {}
        default_route = None
        bad = []
        ctype_override = {}
        used_routes = set()

        if self.default_fw_index < 0 and self.fw_items:
            self.default_fw_index = 0
        if self.default_fw_index >= len(self.fw_items):
            self.default_fw_index = len(self.fw_items) - 1 if self.fw_items else -1

        for idx, it in enumerate(self.fw_items):
            try:
                meta = build_file_meta(it["path"])
            except Exception as e:
                bad.append(f"{it.get('filename', it.get('path', '?'))}: {e}")
                continue

            route_candidate = "/files/" + quote(it["filename"], safe="")
            route = route_candidate
            if route in used_routes or route in reg:
                route = "/files/" + quote(meta["md5_hex"][:8] + "-" + it["filename"], safe="")
            used_routes.add(route)

            it.update({
                "route": route,
                "size": meta["size"],
                "md5_hex": meta["md5_hex"],
            })
            meta["route"] = route
            reg[route] = meta

            ct_override = (it.get("ctype_override") or "").strip()
            if ct_override:
                ctype_override[route] = ct_override

            if idx == self.default_fw_index:
                default_route = route

        DownloadHandler.update_registry_and_opts(
            registry=reg,
            default_route=default_route,
            ctype_override=ctype_override
        )

        # UI 同步
        self.tbl_fw.blockSignals(True)
        self.tbl_fw.setRowCount(0)
        for i, it in enumerate(self.fw_items):
            if not it.get("route"):
                continue
            r = self.tbl_fw.rowCount()
            self.tbl_fw.insertRow(r)
            self.tbl_fw.setItem(r, 0, QTableWidgetItem("★" if i == self.default_fw_index else ""))
            self.tbl_fw.setItem(r, 1, QTableWidgetItem(it["filename"]))
            self.tbl_fw.setItem(r, 2, QTableWidgetItem(it["route"]))

            kw_item = QTableWidgetItem(it.get("keyword", ""))
            kw_item.setFlags(kw_item.flags() | Qt.ItemIsEditable)
            self.tbl_fw.setItem(r, 3, kw_item)

            ct_item = QTableWidgetItem(it.get("ctype_override", ""))
            ct_item.setFlags(ct_item.flags() | Qt.ItemIsEditable)
            self.tbl_fw.setItem(r, 4, ct_item)

            self.tbl_fw.setItem(r, 5, QTableWidgetItem(it["path"]))
        self.tbl_fw.blockSignals(False)

        if bad:
            QMessageBox.warning(self, "無法加入的韌體檔",
                                "以下檔案無法載入，已略過：\n\n" + "\n".join(bad))

    # === 加入/刪除/設預設 ===
    def on_add_fw(self):
        path, _ = QFileDialog.getOpenFileName(self, "選擇韌體檔", "", "韌體檔 (*.pkg *.apk);;所有檔案 (*.*)")
        if not path:
            return
        if not os.path.isfile(path):
            QMessageBox.warning(self, "提醒", "檔案不存在。")
            return
        item = {
            "path": path,
            "filename": os.path.basename(path),
            "keyword": "",
            "ctype_override": "",
            "route": "",
            "size": 0,
            "md5_hex": "",
        }
        self.fw_items.append(item)
        if self.default_fw_index == -1:
            self.default_fw_index = 0
        self._rebuild_server_registry()

    def on_del_fw(self):
        rows = sorted({i.row() for i in self.tbl_fw.selectedIndexes()}, reverse=True)
        if not rows:
            return
        for r in rows:
            route_item = self.tbl_fw.item(r, 2)
            if not route_item:
                continue
            route = route_item.text()
            for idx, it in enumerate(list(self.fw_items)):
                if it.get("route") == route:
                    self.fw_items.pop(idx)
                    break
        if self.default_fw_index >= len(self.fw_items):
            self.default_fw_index = len(self.fw_items) - 1
        self._rebuild_server_registry()

    def on_set_default_fw(self):
        rows = sorted({i.row() for i in self.tbl_fw.selectedIndexes()})
        if not rows:
            return
        route_item = self.tbl_fw.item(rows[0], 2)
        if route_item:
            route = route_item.text()
            for i, it in enumerate(self.fw_items):
                if it.get("route") == route:
                    self.default_fw_index = i
                    break
        self._rebuild_server_registry()
    # === 結束 ===

    def _self_ping_server(self, host: str, port: int, timeout: float = 1.5) -> tuple[bool, str]:
        try:
            r = requests.get(f"http://{host}:{port}/healthz", timeout=timeout)
            if 200 <= r.status_code < 300:
                return True, "healthz ok"
        except Exception as e:
            return False, f"healthz fail: {e}"
        return False, "healthz unexpected"

    def _has_active_downloads(self) -> bool:
        return DownloadHandler.has_active_transfers()

    def on_toggle_server(self):
        if not self.server_running:
            bind = "0.0.0.0"
            try:
                port = int(self.le_srv_port.text().strip() or "8000")
            except:
                port = 8000
            self.server_thread = FileServerThread(bind_ip=bind, port=port, log_sink=self.log_sink)
            self.server_thread.started_ok.connect(lambda _: None)
            self.server_thread.failed.connect(lambda e: QMessageBox.critical(self, "啟動失敗", str(e)))
            self.server_thread.start()
            self.server_running = True
            self.btn_srv_toggle.setText("停止伺服器")
        else:
            if self._has_active_downloads():
                ret = QMessageBox.question(self, "仍有下載進行中",
                                           "目前仍有設備在下載韌體，確定要停止伺服器嗎？",
                                           QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
                if ret != QMessageBox.Yes:
                    return
            try:
                if self.server_thread:
                    self.server_thread.stop()
            finally:
                self.server_running = False
                self.btn_srv_toggle.setText("啟動伺服器")
                QMessageBox.information(self, "伺服器", "已停止。")

    def flush_server_logs(self):
        lines = self.log_sink.drain(200)
        if lines:
            self.te_logs.append("\n".join(lines))
            if self.te_logs.document().blockCount() > 2000:
                self.te_logs.clear()

    def update_download_progress(self):
        snap = DownloadHandler.snapshot_progress()
        # 新增/更新列
        for key, e in snap.items():
            ip = e.get("ip", "-")
            filename = e.get("filename", "-")
            total = int(e.get("total", 0)) or 0
            sent = int(e.get("sent", 0)) or 0
            done = bool(e.get("done", False))
            pct = int(sent * 100 / total) if total > 0 else 0

            if key not in self.dl_rows:
                r = self.tbl_dl.rowCount()
                self.tbl_dl.insertRow(r)
                self.tbl_dl.setItem(r, 0, QTableWidgetItem(ip))
                self.tbl_dl.setItem(r, 1, QTableWidgetItem(filename))
                self.tbl_dl.setItem(r, 2, QTableWidgetItem(f"{sent}/{total}"))
                pb = QProgressBar()
                pb.setRange(0, 100)
                pb.setValue(pct)
                self.tbl_dl.setCellWidget(r, 3, pb)
                self.tbl_dl.setItem(r, 4, QTableWidgetItem("完成" if done else "進行中"))
                self.dl_rows[key] = r
            else:
                r = self.dl_rows[key]
                self.tbl_dl.item(r, 2).setText(f"{sent}/{total}")
                pb = self.tbl_dl.cellWidget(r, 3)
                if isinstance(pb, QProgressBar):
                    pb.setValue(pct)
                status_item = self.tbl_dl.item(r, 4)
                if status_item:
                    status_item.setText("完成" if done else "進行中")

    def _on_timer(self):
        self.flush_server_logs()
        self.update_download_progress()

    # ---------- 匯入/表格 ----------
    def on_import(self):
        path, _ = QFileDialog.getOpenFileName(self, "匯入 Excel", "", "Excel Files (*.xls *.xlsx)")
        if not path:
            return
        try:
            self.devices = load_excel_and_parse_devices(path)
            self.populate_table(self.devices)
            QMessageBox.information(self, "成功", f"匯入成功，共 {len(self.devices)} 筆")
        except Exception as e:
            QMessageBox.critical(self, "錯誤", f"匯入失敗：{e}")

    def populate_table(self, devices):
        self.tbl.setRowCount(0)
        for d in devices:
            r = self.tbl.rowCount()
            self.tbl.insertRow(r)
            cb = QCheckBox()
            cb.setChecked(False)
            w = QWidget()
            lay = QHBoxLayout(w)
            lay.setContentsMargins(0, 0, 0, 0)
            lay.addWidget(cb, alignment=Qt.AlignCenter)
            self.tbl.setCellWidget(r, 0, w)
            self.tbl.setItem(r, 1, QTableWidgetItem(d.get("設備類型", "")))
            self.tbl.setItem(r, 2, QTableWidgetItem(d.get("名稱", "")))
            self.tbl.setItem(r, 3, QTableWidgetItem(d.get("IP", "")))
            self.tbl.setItem(r, 4, QTableWidgetItem(d.get("房號", "")))

    def set_all_checked(self, checked: bool):
        for r in range(self.tbl.rowCount()):
            w = self.tbl.cellWidget(r, 0)
            if not w:
                continue
            cb = w.findChild(QCheckBox)
            if cb:
                cb.setChecked(checked)

    def apply_filter(self):
        kw = (self.search_edit.text() or "").lower()
        for r in range(self.tbl.rowCount()):
            texts = []
            for c in range(1, self.tbl.columnCount()):
                it = self.tbl.item(r, c)
                if it:
                    texts.append(it.text().lower())
            self.tbl.setRowHidden(r, kw not in " ".join(texts))

    def get_selected_devices(self):
        res = []
        for r in range(self.tbl.rowCount()):
            w = self.tbl.cellWidget(r, 0)
            cb = w.findChild(QCheckBox) if w else None
            if cb and cb.isChecked() and not self.tbl.isRowHidden(r):
                res.append({
                    "設備類型": self.tbl.item(r, 1).text() if self.tbl.item(r, 1) else "",
                    "名稱": self.tbl.item(r, 2).text() if self.tbl.item(r, 2) else "",
                    "IP": self.tbl.item(r, 3).text() if self.tbl.item(r, 3) else "",
                    "房號": self.tbl.item(r, 4).text() if self.tbl.item(r, 4) else "",
                })
        return res

    # ---------- 更新 ----------
    def _ensure_server_running(self) -> bool:
        if self.server_running:
            return True
        bind = "0.0.0.0"
        try:
            port = int(self.le_srv_port.text().strip() or "8000")
        except:
            port = 8000

        loop = QEventLoop()
        timed_out = {"v": False}

        def on_started(_):
            self.server_running = True
            self.btn_srv_toggle.setText("停止伺服器")
            loop.quit()

        def on_failed(e):
            QMessageBox.critical(self, "啟動失敗", str(e))
            loop.quit()

        def on_timeout():
            timed_out["v"] = True
            loop.quit()

        self.server_thread = FileServerThread(bind_ip=bind, port=port, log_sink=self.log_sink)
        self.server_thread.started_ok.connect(on_started)
        self.server_thread.failed.connect(on_failed)
        self.server_thread.start()

        QTimer.singleShot(5000, on_timeout)
        loop.exec()

        if not self.server_running:
            if timed_out["v"]:
                QMessageBox.critical(self, "啟動逾時", "等待檔案伺服器啟動逾時（5 秒）。請確認防火牆/埠未被佔用。")
            return False

        ok, msg = self._self_ping_server(self.le_public_host.text().strip() or _primary_lan_ip(), port)
        if not ok:
            self.log_sink.push(f"[{time.strftime('%H:%M:%S')}] self-check {msg}")
        else:
            self.log_sink.push(f"[{time.strftime('%H:%M:%S')}] self-check passed")

        return True

    def start_update(self):
        targets = self.get_selected_devices()
        if not targets:
            QMessageBox.warning(self, "提醒", "請至少勾選一台設備")
            return
        if not self.fw_items:
            QMessageBox.warning(self, "提醒", "請先於『韌體清單』加入至少一個韌體檔。")
            return

        public_host = (self.le_public_host.text().strip() or _primary_lan_ip())
        if public_host in ("0.0.0.0", "127.0.0.1"):
            QMessageBox.critical(self, "設定錯誤", "Server Host 不可為 0.0.0.0 / 127.0.0.1，請改成區網可達 IP。")
            return

        # 回寫關鍵字 / Content-Type 覆寫
        for r in range(self.tbl_fw.rowCount()):
            route_item = self.tbl_fw.item(r, 2)
            kw_item = self.tbl_fw.item(r, 3)
            ct_item = self.tbl_fw.item(r, 4)
            if not route_item:
                continue
            route = route_item.text()
            for it in self.fw_items:
                if it.get("route") == route:
                    it["keyword"] = (kw_item.text().strip() if kw_item else "")
                    it["ctype_override"] = (ct_item.text().strip() if ct_item else "")
                    break

        # 重新建立伺服器註冊
        self._rebuild_server_registry()

        if not self._ensure_server_running():
            return

        # 組 worker 用清單
        worker_fws = []
        for it in self.fw_items:
            if not it.get("route"):
                continue
            worker_fws.append({
                "route": it["route"],
                "filename": it["filename"],
                "size": it["size"],
                "md5_hex": it["md5_hex"],
                "keyword": it.get("keyword", ""),
            })
        if not worker_fws:
            QMessageBox.warning(self, "提醒", "沒有可用的韌體檔（皆無法載入）。")
            return

        default_route = None
        if 0 <= self.default_fw_index < len(self.fw_items):
            default_route = self.fw_items[self.default_fw_index].get("route")
        worker_default_index = 0
        if default_route:
            for i, wf in enumerate(worker_fws):
                if wf["route"] == default_route:
                    worker_default_index = i
                    break

        # 固定策略
        use_vendor_path = True
        verify_mode = "opaque"
        verify_fixed = ""

        self.tbl_res.setRowCount(0)
        self.progress.setValue(0)

        self.btn_start.setEnabled(False)
        self.worker = UpdateWorker(
            targets=targets,
            fw_items=worker_fws,
            default_index=worker_default_index,
            srv_host=public_host,
            srv_port=self.le_srv_port.text().strip() or "8000",
            use_vendor_path=use_vendor_path,
            verify_mode=verify_mode,
            verify_fixed=verify_fixed,
            company_id=DEFAULT_COMPANY_ID,
            response=DEFAULT_RESPONSE,
            version=DEFAULT_VERSION,
            timeout=DEFAULT_TIMEOUT,
            retries=DEFAULT_RETRIES,
            max_workers=DEFAULT_WORKERS,
            port_candidates=DEFAULT_PORT_CANDIDATES,
            bypass_proxy=DEFAULT_BYPASS_PROXY
        )
        self.worker.one_done.connect(self.on_one_done)
        self.worker.progress.connect(self.on_progress)
        self.worker.all_done.connect(self.on_all_done)
        self.worker.start()

    def on_one_done(self, info: dict):
        r = self.tbl_res.rowCount()
        self.tbl_res.insertRow(r)
        self.tbl_res.setItem(r, 0, QTableWidgetItem(info.get("ip", "")))
        self.tbl_res.setItem(r, 1, QTableWidgetItem(info.get("room", "")))
        self.tbl_res.setItem(r, 2, QTableWidgetItem(info.get("port", "")))
        self.tbl_res.setItem(r, 3, QTableWidgetItem(str(info.get("code"))))
        self.tbl_res.setItem(r, 4, QTableWidgetItem(info.get("detail", "")))
        self.tbl_res.scrollToBottom()

    def on_progress(self, done, total):
        self.progress.setValue(int(done * 100 / max(1, total)))

    def on_all_done(self):
        self.btn_start.setEnabled(True)
        QMessageBox.information(self, "完成", "所有已勾選的設備都處理完畢。")

    # ---------- 匯出結果 ----------
    def export_results(self):
        if self.tbl_res.rowCount() == 0:
            QMessageBox.information(self, "無資料", "目前沒有可匯出的結果。")
            return
        default = f"更新結果_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        path, _ = QFileDialog.getSaveFileName(self, "匯出結果 CSV", default, "CSV Files (*.csv)")
        if not path:
            return
        headers = ["IP", "房號", "Port", "狀態碼", "訊息"]
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(headers)
            for r in range(self.tbl_res.rowCount()):
                row = []
                for c in range(self.tbl_res.columnCount()):
                    it = self.tbl_res.item(r, c)
                    row.append(it.text() if it else "")
                w.writerow(row)
        QMessageBox.information(self, "完成", f"已匯出：{os.path.basename(path)}")

    # ---------- 關閉防呆 ----------
    def closeEvent(self, event):
        if self._has_active_downloads():
            ret = QMessageBox.question(self, "仍有下載進行中",
                                       "目前仍有設備在下載韌體，確定要關閉應用程式嗎？",
                                       QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if ret != QMessageBox.Yes:
                event.ignore()
                return
        super().closeEvent(event)


# =========================
# 進入點
# =========================
if __name__ == "__main__":
    import warnings
    warnings.filterwarnings("ignore")
    app = QApplication(sys.argv)
    win = MainWindow()
    win.showMaximized()
    sys.exit(app.exec())
