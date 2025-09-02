# upgrade_flow_analyzer.py
# -*- coding: utf-8 -*-
"""
更新流程分析工具（GUI + HTTP 代理）
- 修正 502 迴圈：停用 requests 環境代理、強制直連、加入代理迴圈偵測
- 可調「上游逾時秒數」
"""

# -----------------------------
# 啟動前：純檔名快掃，避免標準庫遮蔽（不 import 可疑模組）
# -----------------------------
def _preflight_shadow_scan_and_exit_if_needed():
    import sys, os
    conflicts = []
    script_dir = os.path.dirname(os.path.abspath(__file__))
    cwd = os.path.abspath(os.getcwd())
    check_dirs = []
    for p in [script_dir, cwd]:
        if p not in check_dirs:
            check_dirs.append(p)
    suspects = ("linecache.py", "enum.py", "inspect.py")
    for base in check_dirs:
        try:
            names = set(os.listdir(base))
        except Exception:
            names = set()
        for s in suspects:
            if s in names:
                conflicts.append(os.path.join(base, s))
        pycache = os.path.join(base, "__pycache__")
        if os.path.isdir(pycache):
            try:
                pc_names = os.listdir(pycache)
                for s in suspects:
                    stem = s.replace(".py", "")
                    if any(n.startswith(stem) and n.endswith(".pyc") for n in pc_names):
                        conflicts.append(os.path.join(pycache, f"{stem}.cpython-*.pyc（可能存在）"))
            except Exception:
                pass
    if conflicts:
        msg = (
            "偵測到與標準庫同名的檔案，會導致 PySide6 啟動失敗：\n\n"
            + "\n".join(f"  - {c}" for c in conflicts)
            + "\n\n請更名或移除，並刪除所有 __pycache__ 後再執行。"
        )
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(None, msg, "環境衝突偵測", 0x00000010 | 0x00040000)
        except Exception:
            pass
        print(msg, flush=True)
        raise SystemExit(1)

_preflight_shadow_scan_and_exit_if_needed()

# -----------------------------
# 之後才載入第三方與標準模組
# -----------------------------
import sys
import os
import threading
import time
import json
import csv
import hashlib
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, urlunsplit, urlparse, parse_qs

import requests

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTableWidget, QTableWidgetItem,
    QHeaderView, QGroupBox, QFormLayout, QPlainTextEdit, QSplitter,
    QFileDialog, QMessageBox, QComboBox, QSpinBox, QCheckBox
)
from PySide6.QtCore import Qt, Signal, QObject


# -----------------------------
# 全域設定 / 常數
# -----------------------------
DEFAULT_PROXY_PORT = 18080
DEFAULT_TIMEOUT_SEC = 30
LOG_DIR = "logs"

WATCH_DEVICE_DEFAULT = "192.168.200.8"
WATCH_MGMT_DEFAULT = "192.168.200.3:8000"

HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "proxy-connection"
}


class EventBus(QObject):
    new_log = Signal(dict)
    new_essentials = Signal(dict)
    new_device_meta = Signal(dict)


class ProxyHandler(BaseHTTPRequestHandler):
    # 由 ProxyServerThread 注入
    event_bus: EventBus = None
    session: requests.Session = None
    timeout_sec: int = DEFAULT_TIMEOUT_SEC
    save_csv_path: str = None
    save_jsonl_path: str = None
    lock = threading.Lock()
    server_version = "UpgradeProxy/0.5"

    def _read_request_body(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length > 0:
            return self.rfile.read(length)
        return b""

    def _filter_headers(self, headers):
        out = {}
        for k, v in headers.items():
            if k.lower() not in HOP_BY_HOP:
                out[k] = v
        out.pop("Proxy-Connection", None)
        return out

    def _ensure_absolute_url(self):
        raw = self.path
        parts = urlsplit(raw)
        if parts.scheme and parts.netloc:
            return raw
        host = self.headers.get("Host")
        if not host:
            return None
        return urlunsplit(("http", host, raw, "", ""))

    def _relay(self, method: str):
        started = time.time()
        url = self._ensure_absolute_url()
        if not url:
            self.send_error(400, "Bad request: missing Host")
            return

        parts = urlsplit(url)
        if parts.scheme.lower() != "http":
            self.send_error(501, "Only HTTP is supported by this proxy")
            return

        # 代理迴圈偵測：若上游剛好指向本代理自己，直接擋下
        try:
            srv_port = getattr(self.server, "server_address", ("", 0))[1]
        except Exception:
            srv_port = 0
        tgt_port = parts.port or (80 if parts.scheme.lower() == "http" else 443)
        if (parts.hostname in ("127.0.0.1", "localhost") and srv_port and tgt_port == srv_port):
            self.send_error(502, f"Proxy loop detected: target {parts.hostname}:{tgt_port} equals this proxy")
            return

        req_headers = self._filter_headers(self.headers)
        req_body = self._read_request_body()

        try:
            # 重要：強制直連，不吃任何環境代理；超時可調
            resp = self.session.request(
                method=method,
                url=url,
                headers=req_headers,
                data=req_body if req_body else None,
                allow_redirects=False,
                timeout=ProxyHandler.timeout_sec,
                stream=False,
                proxies={"http": None, "https": None},
            )
        except requests.RequestException as e:
            self.send_error(502, f"Upstream error: {e}")
            return

        self.send_response(resp.status_code)
        for k, v in resp.headers.items():
            if k.lower() not in HOP_BY_HOP:
                self.send_header(k, v)
        self.end_headers()
        content = resp.content or b""
        if content:
            self.wfile.write(content)

        elapsed = time.time() - started

        log_item = {
            "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "client_ip": self.client_address[0],
            "method": method,
            "url": url,
            "status": resp.status_code,
            "req_len": len(req_body or b""),
            "resp_len": len(content),
            "elapsed_ms": int(elapsed * 1000),
            "req_headers": dict(self.headers),
            "resp_headers": dict(resp.headers),
            "req_body_preview": (req_body[:4096].decode("utf-8", errors="ignore") if req_body else ""),
        }

        self._append_logs(log_item)

        if ProxyHandler.event_bus:
            ProxyHandler.event_bus.new_log.emit(log_item)

        self._maybe_extract_upgrade_essentials(url, req_headers, log_item["req_body_preview"], content)

    def _append_logs(self, item: dict):
        os.makedirs(LOG_DIR, exist_ok=True)
        try:
            with ProxyHandler.lock:
                with open(ProxyHandler.save_jsonl_path, "a", encoding="utf-8") as jf:
                    jf.write(json.dumps(item, ensure_ascii=False) + "\n")
        except Exception:
            pass
        try:
            row = [
                item.get("ts", ""),
                item.get("client_ip", ""),
                item.get("method", ""),
                item.get("url", ""),
                item.get("status", ""),
                item.get("req_len", ""),
                item.get("resp_len", ""),
                item.get("elapsed_ms", ""),
            ]
            write_header = not os.path.exists(ProxyHandler.save_csv_path)
            with ProxyHandler.lock:
                with open(ProxyHandler.save_csv_path, "a", newline="", encoding="utf-8") as cf:
                    w = csv.writer(cf)
                    if write_header:
                        w.writerow(["time", "client_ip", "method", "url", "status", "req_len", "resp_len", "elapsed_ms"])
                    w.writerow(row)
        except Exception:
            pass

    def _maybe_extract_upgrade_essentials(self, url: str, req_headers: dict, req_body_text: str, resp_body_bytes: bytes):
        try:
            parts = urlsplit(url)
            path = parts.path or "/"
            host = parts.hostname or ""

            # 1) 解析 /cmd/sync POST
            if path.endswith("/cmd/sync"):
                essentials = {
                    "device_ip": host,
                    "url": url,
                    "method": self.command,
                    "headers": {
                        "company-id": req_headers.get("company-id"),
                        "token": req_headers.get("token"),
                    },
                    "action": None,
                    "filename": None,
                    "path": None,
                    "verify": None,
                }
                body = req_body_text.strip()
                if body:
                    try:
                        data = json.loads(body)
                        essentials["action"] = data.get("action")
                        essentials["filename"] = data.get("filename")
                        essentials["path"] = data.get("path")
                        if essentials["path"]:
                            u = urlparse(essentials["path"])
                            qs = parse_qs(u.query or "")
                            essentials["verify"] = qs.get("verify", [""])[0]
                    except Exception:
                        pass

                if ProxyHandler.event_bus:
                    ProxyHandler.event_bus.new_essentials.emit(essentials)

            # 2) 嘗試解析 /device/info
            if path.endswith("/device/info") and resp_body_bytes:
                meta = {"device_ip": host, "type": "device_info", "room_id": None}
                try:
                    text = resp_body_bytes.decode("utf-8", errors="ignore")
                    j = json.loads(text)
                    meta["room_id"] = j.get("room_id")
                except Exception:
                    pass
                if ProxyHandler.event_bus:
                    ProxyHandler.event_bus.new_device_meta.emit(meta)

            # 3) 嘗試解析 /time
            if path.endswith("/time") and resp_body_bytes:
                meta = {"device_ip": host, "type": "time", "time": None}
                try:
                    text = resp_body_bytes.decode("utf-8", errors="ignore")
                    j = json.loads(text)
                    meta["time"] = j.get("time")
                except Exception:
                    pass
                if ProxyHandler.event_bus:
                    ProxyHandler.event_bus.new_device_meta.emit(meta)

        except Exception:
            pass

    # 支援基本方法（不支援 CONNECT/HTTPS）
    def do_GET(self): self._relay("GET")
    def do_POST(self): self._relay("POST")
    def do_PUT(self): self._relay("PUT")
    def do_DELETE(self): self._relay("DELETE")
    def do_HEAD(self): self._relay("HEAD")
    def do_OPTIONS(self): self._relay("OPTIONS")
    def do_CONNECT(self):
        self.send_error(501, "CONNECT not supported. Use HTTP only.")


class ProxyServerThread(threading.Thread):
    def __init__(self, host: str, port: int, timeout_sec: int, event_bus: EventBus):
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self.timeout_sec = timeout_sec
        self.httpd = None
        self.event_bus = event_bus

    def run(self):
        os.makedirs(LOG_DIR, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        ProxyHandler.save_csv_path = os.path.join(LOG_DIR, f"access_{stamp}.csv")
        ProxyHandler.save_jsonl_path = os.path.join(LOG_DIR, f"access_{stamp}.jsonl")
        ProxyHandler.event_bus = self.event_bus

        # 建立 session：停用環境代理，避免迴圈
        sess = requests.Session()
        sess.trust_env = False
        ProxyHandler.session = sess
        ProxyHandler.timeout_sec = self.timeout_sec

        self.httpd = ThreadingHTTPServer((self.host, self.port), ProxyHandler)
        try:
            self.httpd.serve_forever(poll_interval=0.2)
        except Exception:
            pass

    def stop(self):
        if self.httpd:
            try:
                self.httpd.shutdown()
            except Exception:
                pass


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("更新流程分析工具 (HTTP 代理攔截)")
        self.resize(1240, 780)

        self.event_bus = EventBus()
        self.event_bus.new_log.connect(self.on_new_log)
        self.event_bus.new_essentials.connect(self.on_new_essentials)
        self.event_bus.new_device_meta.connect(self.on_new_device_meta)

        self.proxy_thread: ProxyServerThread | None = None
        self.latest_essentials = {}
        self.device_time_iso = None

        self._build_ui()

    def _build_ui(self):
        root = QWidget()
        self.setCentralWidget(root)
        lay = QVBoxLayout(root)

        ctrl = QHBoxLayout()
        lay.addLayout(ctrl)

        ctrl.addWidget(QLabel("HTTP 代理埠"))
        self.port_edit = QSpinBox()
        self.port_edit.setRange(1024, 65535)
        self.port_edit.setValue(DEFAULT_PROXY_PORT)
        ctrl.addWidget(self.port_edit)

        ctrl.addWidget(QLabel("上游逾時(秒)"))
        self.timeout_edit = QSpinBox()
        self.timeout_edit.setRange(5, 300)
        self.timeout_edit.setValue(DEFAULT_TIMEOUT_SEC)
        ctrl.addWidget(self.timeout_edit)

        self.start_btn = QPushButton("啟動代理")
        self.start_btn.clicked.connect(self.start_proxy)
        ctrl.addWidget(self.start_btn)

        self.stop_btn = QPushButton("停止代理")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_proxy)
        ctrl.addWidget(self.stop_btn)

        self.help_btn = QPushButton("Proxy 設定說明")
        self.help_btn.clicked.connect(self.show_proxy_help)
        ctrl.addWidget(self.help_btn)

        ctrl.addStretch()

        hint = QLabel(f"目標管理網頁： http://{WATCH_MGMT_DEFAULT}    目標設備： {WATCH_DEVICE_DEFAULT}:3377")
        hint.setStyleSheet("color:#888;")
        lay.addWidget(hint)

        split = QSplitter(Qt.Horizontal)
        lay.addWidget(split, 1)

        # 左側：攔截列表
        left = QWidget()
        left_lay = QVBoxLayout(left)
        split.addWidget(left)

        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(["#", "時間", "方法", "URL", "狀態", "REQ", "RESP"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        left_lay.addWidget(self.table)

        ex = QHBoxLayout()
        left_lay.addLayout(ex)
        self.export_csv_btn = QPushButton("匯出目前列表為 CSV")
        self.export_csv_btn.clicked.connect(self.export_current_csv)
        ex.addWidget(self.export_csv_btn)
        self.export_jsonl_btn = QPushButton("開啟近期 JSONL 位置")
        self.export_jsonl_btn.clicked.connect(self.open_logs_dir)
        ex.addWidget(self.export_jsonl_btn)
        ex.addStretch()

        # 右側：Essentials + Token Lab
        right = QWidget()
        right_lay = QVBoxLayout(right)
        split.addWidget(right)

        box1 = QGroupBox("Upgrade Essentials（升級所需參數彙整）")
        f1 = QFormLayout(box1)

        self.device_ip_lbl = QLabel("-")
        self.token_lbl = QLabel("-")
        self.company_lbl = QLabel("-")
        self.action_lbl = QLabel("-")
        self.filename_lbl = QLabel("-")
        self.path_lbl = QLabel("-")
        self.verify_lbl = QLabel("-")

        f1.addRow("Device IP", self.device_ip_lbl)
        f1.addRow("token", self.token_lbl)
        f1.addRow("company-id", self.company_lbl)
        f1.addRow("action", self.action_lbl)
        f1.addRow("filename", self.filename_lbl)
        f1.addRow("path", self.path_lbl)
        f1.addRow("verify", self.verify_lbl)

        right_lay.addWidget(box1)

        self.json_view = QPlainTextEdit()
        self.json_view.setReadOnly(True)
        right_lay.addWidget(self.json_view, 1)

        hjson = QHBoxLayout()
        self.copy_json_btn = QPushButton("複製 Essentials JSON")
        self.copy_json_btn.clicked.connect(self.copy_essentials_json)
        hjson.addWidget(self.copy_json_btn)
        hjson.addStretch()
        right_lay.addLayout(hjson)

        box2 = QGroupBox("Token Lab（MD5 驗證器）")
        f2 = QFormLayout(box2)

        self.remote_edit = QLineEdit("remote")
        self.date_edit = QLineEdit("")
        self.time_edit = QLineEdit("")
        self.room_raw_edit = QLineEdit("")
        self.rule_combo = QComboBox()
        self.rule_combo.addItems(["去尾 2 碼", "去尾 4 碼", "不裁切（手動自己填房號）"])
        self.room_used_edit = QLineEdit("")
        self.token_calc_btn = QPushButton("計算 MD5")
        self.token_calc_btn.clicked.connect(self.calc_token)

        self.token_result_lbl = QLabel("-")
        self.compare_captured_chk = QCheckBox("與最近捕獲 token 比對")
        self.match_lbl = QLabel("-")

        f2.addRow("remote", self.remote_edit)
        f2.addRow("日期(YYYYMMDD)", self.date_edit)
        f2.addRow("時間(HHMMSS)", self.time_edit)
        f2.addRow("room_id(原始)", self.room_raw_edit)
        f2.addRow("房號裁切規則", self.rule_combo)
        f2.addRow("房號(用於MD5)", self.room_used_edit)
        f2.addRow(self.token_calc_btn, self.token_result_lbl)
        f2.addRow(self.compare_captured_chk, self.match_lbl)

        right_lay.addWidget(box2)

        self.status_lbl = QLabel("就緒")
        self.statusBar().addPermanentWidget(self.status_lbl, 1)

    # --- Proxy 控制 ---
    def start_proxy(self):
        port = int(self.port_edit.value())
        timeout_sec = int(self.timeout_edit.value())
        try:
            self.proxy_thread = ProxyServerThread("0.0.0.0", port, timeout_sec, self.event_bus)
            self.proxy_thread.start()
        except Exception as e:
            QMessageBox.critical(self, "啟動失敗", f"無法啟動代理：{e}")
            return
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_lbl.setText(f"代理執行中： http://127.0.0.1:{port}  （請把瀏覽器的 HTTP 代理設為此位址）")

    def stop_proxy(self):
        if self.proxy_thread:
            self.proxy_thread.stop()
            self.proxy_thread = None
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_lbl.setText("代理已停止")

    def show_proxy_help(self):
        msg = (
            "設定方式（以 Chrome 為例）：\n"
            "1) 按「啟動代理」，保持 Port（預設 18080）。\n"
            "2) Windows → 設定 → 網路與網際網路 → Proxy → 手動設定 Proxy：\n"
            "   只填『HTTP 代理』位址 127.0.0.1、連接埠為本工具顯示的埠（預設 18080）。\n"
            "   其他（HTTPS、SOCKS）請先留空或關閉。\n"
            "3) 開 http://192.168.200.3:8000/ 進行更新。\n"
            "4) 工具會攔截並解析 /cmd/sync、/device/info、/time。\n\n"
            "⚠️ 若仍出現 127.0.0.1:18080 逾時，代表有其他程式把『系統環境代理』吃進去造成迴圈，\n"
            "   但本工具已強制直連，請確認你不是直接在網址列打 http://127.0.0.1:18080/"
        )
        QMessageBox.information(self, "Proxy 設定說明", msg)

    # --- 日誌表格 ---
    def on_new_log(self, item: dict):
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.table.setItem(row, 0, QTableWidgetItem(str(row + 1)))
        self.table.setItem(row, 1, QTableWidgetItem(item.get("ts", "")))
        self.table.setItem(row, 2, QTableWidgetItem(item.get("method", "")))
        self.table.setItem(row, 3, QTableWidgetItem(item.get("url", "")))
        self.table.setItem(row, 4, QTableWidgetItem(str(item.get("status", ""))))
        self.table.setItem(row, 5, QTableWidgetItem(str(item.get("req_len", ""))))
        self.table.setItem(row, 6, QTableWidgetItem(str(item.get("resp_len", ""))))

        url = item.get("url", "")
        if url.endswith("/cmd/sync"):
            for c in range(self.table.columnCount()):
                self.table.item(row, c).setBackground(Qt.yellow)
        elif url.endswith("/device/info") or url.endswith("/time"):
            for c in range(self.table.columnCount()):
                self.table.item(row, c).setBackground(Qt.lightGray)

        self.table.scrollToBottom()

    # --- Essentials 顯示 ---
    def on_new_essentials(self, data: dict):
        self.latest_essentials = data
        self.device_ip_lbl.setText(data.get("device_ip") or "-")
        self.token_lbl.setText((data.get("headers") or {}).get("token") or "-")
        self.company_lbl.setText((data.get("headers") or {}).get("company-id") or "-")
        self.action_lbl.setText(data.get("action") or "-")
        self.filename_lbl.setText(data.get("filename") or "-")
        self.path_lbl.setText(data.get("path") or "-")
        self.verify_lbl.setText(data.get("verify") or "-")
        self.json_view.setPlainText(json.dumps(data, ensure_ascii=False, indent=2))
        if self.device_time_iso:
            self._try_fill_from_iso(self.device_time_iso)

    def on_new_device_meta(self, meta: dict):
        if meta.get("type") == "time":
            self.device_time_iso = meta.get("time")
            if self.device_time_iso:
                self._try_fill_from_iso(self.device_time_iso)
        elif meta.get("type") == "device_info":
            rid = meta.get("room_id")
            if rid and not self.room_raw_edit.text():
                self.room_raw_edit.setText(str(rid))
                self._auto_apply_room_rule()

    def _try_fill_from_iso(self, iso_str: str):
        try:
            if len(iso_str) >= 5 and (iso_str[-5] in ["+", "-"]) and iso_str[-3] != ":":
                iso_str = iso_str[:-2] + ":" + iso_str[-2:]
            dt = datetime.fromisoformat(iso_str)
            self.date_edit.setText(dt.strftime("%Y%m%d"))
            self.time_edit.setText(dt.strftime("%H%M%S"))
        except Exception:
            pass

    def _auto_apply_room_rule(self):
        rule = self.rule_combo.currentText()
        raw = self.room_raw_edit.text().strip()
        if not raw:
            return
        if rule.startswith("去尾 2"):
            room_used = raw[:-2] if len(raw) > 2 else raw
        elif rule.startswith("去尾 4"):
            room_used = raw[:-4] if len(raw) > 4 else raw
        else:
            room_used = raw
        self.room_used_edit.setText(room_used)

    # --- Token Lab ---
    def calc_token(self):
        remote = self.remote_edit.text().strip()
        ymd = self.date_edit.text().strip()
        hms = self.time_edit.text().strip()
        room = self.room_used_edit.text().strip()

        if not (remote and ymd and hms and room):
            QMessageBox.warning(self, "欄位不足", "請填完 remote / 日期 / 時間 / 房號（裁切後）再試。")
            return

        s = f"{remote}{ymd}{room}{hms}".lower()
        md5 = hashlib.md5(s.encode("utf-8")).hexdigest()
        self.token_result_lbl.setText(md5)

        if self.compare_captured_chk.isChecked():
            captured = (self.latest_essentials.get("headers") or {}).get("token") if self.latest_essentials else None
            if captured:
                self.match_lbl.setText("✅ 一致" if captured == md5 else "❌ 不一致")
            else:
                self.match_lbl.setText("（尚未捕獲 token）")

    # --- 其他 ---
    def copy_essentials_json(self):
        if not self.latest_essentials:
            QMessageBox.information(self, "尚無資料", "還沒有捕獲到 /cmd/sync。")
        else:
            QApplication.clipboard().setText(json.dumps(self.latest_essentials, ensure_ascii=False, indent=2))
            self.status_lbl.setText("已複製 Essentials JSON")

    def export_current_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "另存 CSV", "", "CSV Files (*.csv)")
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                headers = ["#", "時間", "方法", "URL", "狀態", "REQ", "RESP"]
                w.writerow(headers)
                for r in range(self.table.rowCount()):
                    row = []
                    for c in range(self.table.columnCount()):
                        it = self.table.item(r, c)
                        row.append(it.text() if it else "")
                    w.writerow(row)
            QMessageBox.information(self, "完成", f"已輸出：{path}")
        except Exception as e:
            QMessageBox.critical(self, "失敗", f"寫檔失敗：{e}")

    def open_logs_dir(self):
        os.makedirs(LOG_DIR, exist_ok=True)
        path = os.path.abspath(LOG_DIR)
        try:
            if sys.platform.startswith("win"):
                os.startfile(path)  # type: ignore
            elif sys.platform == "darwin":
                os.system(f'open "{path}"')
            else:
                os.system(f'xdg-open "{path}"')
        except Exception:
            QMessageBox.information(self, "路徑", path)


def main():
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
