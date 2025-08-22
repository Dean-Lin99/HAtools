# updater_with_embedded_fileserver_v2.py
# -*- coding: utf-8 -*-

import sys
import os
import threading
import socket
import hashlib
import ipaddress
from urllib.parse import urlsplit, parse_qs
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from PySide6.QtCore import Qt, QThread, Signal, Slot
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QGroupBox, QFormLayout, QLabel, QLineEdit, QPushButton, QTextEdit,
    QProgressBar, QTableWidget, QTableWidgetItem, QHeaderView,
    QFileDialog, QSpinBox, QCheckBox, QMessageBox, QSplitter, QAbstractItemView
)

APP_TITLE = "設備韌體更新工具（檔案伺服器 + verify 驗證 + /cmd/sync 觸發）"
DEFAULT_FILESERVER_PORT = 8000
DEFAULT_DEVICE_PORT = 80
DEFAULT_THREADS = 32
DEFAULT_DOWNLOAD_PATH = "/api/cmd/download"  # 與管理中心一致
DEFAULT_COMPANY_ID = "FSC"
DEFAULT_TOKEN = "ac46ab7ef852960860fd12ce6421d507"
DEFAULT_RESPONSE = "123"
DEFAULT_VERSION = "init"
DEFAULT_FILENAME = "OUTDOOR.PKG"

# ========== 工具 ==========
def is_ipv4(s: str) -> bool:
    try:
        ipaddress.ip_address(s.strip())
        return True
    except Exception:
        return False

def parse_ip_port(line: str, default_port: int):
    s = line.strip().split()[0].split(",")[0]
    if ":" in s:
        ip, p = s.rsplit(":", 1)
        if is_ipv4(ip):
            try:
                return ip, int(p)
            except Exception:
                return ip, default_port
        return None, None
    else:
        return (s, default_port) if is_ipv4(s) else (None, None)

def local_ipv4_list():
    ips = set()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    ips.add("0.0.0.0")
    ips.add("127.0.0.1")
    return list(sorted(ips))

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

def normalize_path(p: str) -> str:
    return p if p.startswith("/") else ("/" + p)

# ========== 內建檔案伺服器 ==========
class FirmwareDownloadHandler(BaseHTTPRequestHandler):
    # 由伺服器執行緒注入
    firmware_path = None
    download_route = DEFAULT_DOWNLOAD_PATH
    content_filename = DEFAULT_FILENAME
    require_verify = False
    expected_verify = ""

    def _extract_verify(self):
        # 允許 GET 帶 query ?verify=xxx；也容忍奇怪客戶端在 GET 帶 body（忽略）
        path = self.path.split("?", 1)[0]
        qs = ""
        if "?" in self.path:
            qs = self.path.split("?", 1)[1]
        params = parse_qs(qs)
        v = params.get("verify", [""])[0]
        return path, v

    def _check_verify(self):
        if not self.require_verify:
            return True
        _, v = self._extract_verify()
        return (v == self.expected_verify and v != "")

    def _common_headers(self, status=200, length=None, content_type="application/octet-stream"):
        self.send_response(status)
        self.send_header("Cache-Control", "no-cache, private")
        if length is not None:
            self.send_header("Content-Length", str(length))
        self.send_header("Content-Type", content_type)
        # 關鍵：一些機型需要 filename
        if self.content_filename:
            self.send_header("Content-Disposition", f'attachment; filename="{self.content_filename}"')
        self.end_headers()

    def _serve_head(self):
        if not self._check_verify():
            self._common_headers(403, 0, "text/plain; charset=utf-8")
            return
        if not self.firmware_path or not os.path.isfile(self.firmware_path):
            self._common_headers(404, 0, "text/plain; charset=utf-8")
            return
        sz = os.path.getsize(self.firmware_path)
        self._common_headers(200, sz, "application/octet-stream")

    def _serve_get(self):
        if not self._check_verify():
            out = b"Forbidden: invalid verify"
            self._common_headers(403, len(out), "text/plain; charset=utf-8")
            self.wfile.write(out)
            return
        if not self.firmware_path or not os.path.isfile(self.firmware_path):
            out = b"No firmware file"
            self._common_headers(404, len(out), "text/plain; charset=utf-8")
            self.wfile.write(out)
            return

        sz = os.path.getsize(self.firmware_path)
        self._common_headers(200, sz, "application/octet-stream")
        try:
            with open(self.firmware_path, "rb") as f:
                while True:
                    chunk = f.read(1024 * 1024)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
        except BrokenPipeError:
            pass
        except Exception as e:
            out = f"Internal error: {e}".encode("utf-8", "ignore")
            self._common_headers(500, len(out), "text/plain; charset=utf-8")
            self.wfile.write(out)

    def do_HEAD(self):
        path = self.path.split("?")[0]
        if path == self.download_route:
            self._serve_head()
        else:
            self._common_headers(404, 0, "text/plain; charset=utf-8")

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == self.download_route:
            self._serve_get()
        else:
            self._common_headers(404, 0, "text/plain; charset=utf-8")

    def log_message(self, fmt, *args):
        # 靜音
        pass

class FileServerThread(threading.Thread):
    def __init__(self, host: str, port: int, firmware_path: str, route: str,
                 content_filename: str, require_verify: bool, expected_verify: str):
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self.firmware_path = firmware_path
        self.route = route
        self.content_filename = content_filename
        self.require_verify = require_verify
        self.expected_verify = expected_verify
        self.httpd = None

    def run(self):
        FirmwareDownloadHandler.firmware_path = self.firmware_path
        FirmwareDownloadHandler.download_route = self.route
        FirmwareDownloadHandler.content_filename = self.content_filename
        FirmwareDownloadHandler.require_verify = self.require_verify
        FirmwareDownloadHandler.expected_verify = self.expected_verify
        self.httpd = ThreadingHTTPServer((self.host, self.port), FirmwareDownloadHandler)
        try:
            self.httpd.serve_forever()
        except Exception:
            pass

    def stop(self):
        try:
            if self.httpd:
                self.httpd.shutdown()
        except Exception:
            pass

# ========== 下發執行緒 ==========
class SyncWorker(QThread):
    one_result = Signal(str, int, str)  # ip[:port], status, msg
    progress = Signal(int, int)
    all_done = Signal()

    def __init__(self, targets, cfg, parent=None):
        super().__init__(parent)
        self.targets = targets  # list of (ip, port)
        self.cfg = cfg
        self._stop_flag = False

    def stop(self):
        self._stop_flag = True

    def post_sync(self, ip, port):
        url = f"http://{ip}:{port}/cmd/sync"
        body = {
            "action": "sw_upgrade",
            "filename": self.cfg["filename"],
            "path": self.cfg["download_url"],
            "version": self.cfg["version"],
            "size": self.cfg["size"],
            "hash": self.cfg["md5"],
        }
        headers = {
            "Content-Type": "application/json",
            "company-id": self.cfg["company_id"],
            "token": self.cfg["token"],
            "response": self.cfg["response_val"],
        }
        try:
            r = requests.post(url, json=body, headers=headers, timeout=15)
            ok = 200 <= r.status_code < 300
            msg = (r.text or "").strip()
            if not msg:
                msg = "Success" if ok else "No content"
            return r.status_code, msg[:500]
        except Exception as e:
            return -1, str(e)[:500]

    def run(self):
        total = len(self.targets)
        done = 0
        with ThreadPoolExecutor(max_workers=self.cfg["threads"]) as pool:
            futures = [pool.submit(self.post_sync, ip, port) for (ip, port) in self.targets]
            for (ip, port), fut in zip(self.targets, as_completed(futures)):
                if self._stop_flag:
                    break
                status, msg = fut.result()
                self.one_result.emit(f"{ip}:{port}", status, msg)
                done += 1
                self.progress.emit(done, total)
        self.all_done.emit()

# ========== 主視窗 ==========
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_TITLE)
        self.resize(1200, 750)

        self.server_thread = None
        self.server_running = False

        self._build_ui()

    def _build_ui(self):
        root = QSplitter(Qt.Horizontal)
        self.setCentralWidget(root)

        # ===== 左：檔案伺服器 =====
        left = QWidget(); left_l = QVBoxLayout(left)

        grp_srv = QGroupBox("檔案伺服器（提供 /api/cmd/download）")
        f = QFormLayout(grp_srv)

        self.le_bind = QLineEdit()
        ips = local_ipv4_list()
        self.le_bind.setText(ips[0] if ips else "0.0.0.0")

        self.le_srv_port = QLineEdit(str(DEFAULT_FILESERVER_PORT))
        self.le_route = QLineEdit(DEFAULT_DOWNLOAD_PATH)

        self.le_fw = QLineEdit()
        self.le_fw.setPlaceholderText("選擇韌體檔（.pkg/.bin/.img）")
        btn_fw = QPushButton("選擇檔案")
        btn_fw.clicked.connect(self.on_pick_fw)
        fw_row = QHBoxLayout()
        fw_row.addWidget(self.le_fw, 1)
        fw_row.addWidget(btn_fw)

        self.le_content_filename = QLineEdit(DEFAULT_FILENAME)
        self.cb_require_verify = QCheckBox("啟用 verify 驗證（不符則 403）")
        self.le_expected_verify = QLineEdit()
        self.le_expected_verify.setPlaceholderText("填入管理中心產出的 verify 原字串（基地台會照此驗證）")

        self.lbl_fw_info = QLabel("MD5: -   Size: -")

        self.btn_srv_toggle = QPushButton("啟動伺服器")
        self.btn_srv_toggle.clicked.connect(self.on_toggle_server)

        f.addRow("綁定 IP（0.0.0.0=全部）：", self.le_bind)
        f.addRow("Port：", self.le_srv_port)
        f.addRow("下載路徑：", self.le_route)
        f.addRow("韌體檔案：", fw_row)
        f.addRow("回應檔名（Content-Disposition）：", self.le_content_filename)
        f.addRow(self.cb_require_verify)
        f.addRow("期望 verify：", self.le_expected_verify)
        f.addRow(self.lbl_fw_info)
        f.addRow(self.btn_srv_toggle)

        left_l.addWidget(grp_srv)

        grp_dlurl = QGroupBox("下載網址（給設備用）")
        v_dl = QVBoxLayout(grp_dlurl)
        self.le_verify = QLineEdit()
        self.le_verify.setPlaceholderText("verify 參數（可留空；若有啟用驗證則需一致）")
        self.le_preview_url = QLineEdit(); self.le_preview_url.setReadOnly(True)
        btn_gen_url = QPushButton("生成下載網址")
        btn_gen_url.clicked.connect(self.on_gen_url)
        btn_test_url = QPushButton("測試 URL（HEAD/GET）")
        btn_test_url.clicked.connect(self.on_test_url)
        self.lbl_url_test = QLabel("-")
        v_dl.addWidget(QLabel("verify 參數（可選）："))
        v_dl.addWidget(self.le_verify)
        v_dl.addWidget(btn_gen_url)
        v_dl.addWidget(QLabel("下載網址預覽："))
        v_dl.addWidget(self.le_preview_url)
        v_dl.addWidget(btn_test_url)
        v_dl.addWidget(self.lbl_url_test)

        left_l.addWidget(grp_dlurl)
        left_l.addStretch(1)

        # ===== 右：/cmd/sync 下發 =====
        right = QWidget(); right_l = QVBoxLayout(right)

        grp_sync = QGroupBox("批次觸發設備升級（/cmd/sync）")
        f2 = QFormLayout(grp_sync)

        self.te_ips = QTextEdit()
        self.te_ips.setPlaceholderText("每行一台設備，可用 ip 或 ip:port（例如 192.168.200.7:8080）")

        self.le_device_port = QLineEdit(str(DEFAULT_DEVICE_PORT))

        self.le_company = QLineEdit(DEFAULT_COMPANY_ID)
        self.le_token = QLineEdit(DEFAULT_TOKEN)
        self.le_response = QLineEdit(DEFAULT_RESPONSE)

        self.le_filename = QLineEdit(DEFAULT_FILENAME)
        self.le_version = QLineEdit(DEFAULT_VERSION)

        self.le_download_url = QLineEdit()
        self.le_download_url.setPlaceholderText("例如：http://<你的IP>:8000/api/cmd/download?verify=xxxxx")

        self.sb_threads = QSpinBox(); self.sb_threads.setRange(1, 256); self.sb_threads.setValue(DEFAULT_THREADS)

        self.pb = QProgressBar()
        self.btn_start = QPushButton("開始下發"); self.btn_stop = QPushButton("停止"); self.btn_stop.setEnabled(False)

        f2.addRow("設備清單：", self.te_ips)
        f2.addRow("預設設備 Port：", self.le_device_port)
        f2.addRow("company-id：", self.le_company)
        f2.addRow("token：", self.le_token)
        f2.addRow("response：", self.le_response)
        f2.addRow("filename：", self.le_filename)
        f2.addRow("version：", self.le_version)
        f2.addRow("下載網址（path）：", self.le_download_url)
        f2.addRow("同時執行數：", self.sb_threads)
        f2.addRow("進度：", self.pb)

        right_l.addWidget(grp_sync)

        self.tbl = QTableWidget(0, 3)
        self.tbl.setHorizontalHeaderLabels(["IP:Port", "狀態碼", "訊息（截斷）"])
        self.tbl.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tbl.setEditTriggers(QAbstractItemView.NoEditTriggers)

        ctrl = QHBoxLayout()
        ctrl.addWidget(self.btn_start)
        ctrl.addWidget(self.btn_stop)
        right_l.addLayout(ctrl)
        right_l.addWidget(self.tbl, 1)

        self.btn_start.clicked.connect(self.on_start)
        self.btn_stop.clicked.connect(self.on_stop)

        root.addWidget(left)
        root.addWidget(right)
        root.setSizes([560, 640])

    # ===== 檔案伺服器 =====
    def on_pick_fw(self):
        f, _ = QFileDialog.getOpenFileName(self, "選擇韌體檔", "", "韌體檔 (*.pkg *.bin *.img);;所有檔案 (*.*)")
        if not f:
            return
        self.le_fw.setText(f)
        try:
            md5, size = file_md5_and_size(f)
            self.lbl_fw_info.setText(f"MD5: {md5}   Size: {size}")
        except Exception:
            self.lbl_fw_info.setText("MD5: -   Size: -")

    def on_toggle_server(self):
        if not self.server_running:
            fw = self.le_fw.text().strip()
            if not fw or not os.path.isfile(fw):
                QMessageBox.warning(self, "提醒", "請先選擇有效的韌體檔。")
                return
            bind = self.le_bind.text().strip() or "0.0.0.0"
            if not is_ipv4(bind):
                QMessageBox.warning(self, "提醒", "綁定 IP 格式不正確。")
                return
            try:
                port = int(self.le_srv_port.text().strip() or DEFAULT_FILESERVER_PORT)
            except Exception:
                port = DEFAULT_FILESERVER_PORT
            route = normalize_path(self.le_route.text().strip() or DEFAULT_DOWNLOAD_PATH)
            filename_hdr = self.le_content_filename.text().strip() or os.path.basename(fw) or DEFAULT_FILENAME
            require_verify = self.cb_require_verify.isChecked()
            expected_verify = self.le_expected_verify.text().strip()

            try:
                self.server_thread = FileServerThread(
                    bind, port, fw, route, filename_hdr, require_verify, expected_verify
                )
                self.server_thread.start()
                self.server_running = True
                self.btn_srv_toggle.setText("停止伺服器")
                QMessageBox.information(self, "成功", f"檔案伺服器已啟動：{bind}:{port}{route}\n驗證 verify：{'開啟' if require_verify else '關閉'}")
            except Exception as e:
                QMessageBox.critical(self, "錯誤", f"啟動伺服器失敗：{e}")
        else:
            try:
                if self.server_thread:
                    self.server_thread.stop()
                self.server_running = False
                self.btn_srv_toggle.setText("啟動伺服器")
                QMessageBox.information(self, "成功", "檔案伺服器已停止。")
            except Exception as e:
                QMessageBox.warning(self, "提醒", f"停止伺服器時發生例外：{e}")

    def on_gen_url(self):
        bind = self.le_bind.text().strip() or "0.0.0.0"
        try:
            port = int(self.le_srv_port.text().strip() or DEFAULT_FILESERVER_PORT)
        except Exception:
            port = DEFAULT_FILESERVER_PORT
        route = normalize_path(self.le_route.text().strip() or DEFAULT_DOWNLOAD_PATH)
        verify = self.le_verify.text().strip()

        base = f"http://{bind}:{port}{route}"
        url = f"{base}?verify={verify}" if verify else base
        self.le_preview_url.setText(url)
        self.le_download_url.setText(url)

    def on_test_url(self):
        url = self.le_preview_url.text().strip()
        if not url:
            self.lbl_url_test.setText("尚未產生 URL")
            return
        try:
            r1 = requests.head(url, timeout=5)
            r2 = requests.get(url, stream=True, timeout=5)
            clen = r2.headers.get("Content-Length", "?")
            disp = r2.headers.get("Content-Disposition", "")
            self.lbl_url_test.setText(f"HEAD {r1.status_code} / GET {r2.status_code} / Length {clen} / {disp}")
            r2.close()
        except Exception as e:
            self.lbl_url_test.setText(f"URL 測試失敗：{e}")

    # ===== /cmd/sync 下發 =====
    def gather_targets(self):
        targets = []
        try:
            default_port = int(self.le_device_port.text().strip() or DEFAULT_DEVICE_PORT)
        except Exception:
            default_port = DEFAULT_DEVICE_PORT

        for line in self.te_ips.toPlainText().splitlines():
            line = line.strip()
            if not line:
                continue
            ip, port = parse_ip_port(line, default_port)
            if ip:
                targets.append((ip, port))
        return targets

    def on_start(self):
        url = self.le_download_url.text().strip()
        if not url:
            QMessageBox.warning(self, "提醒", "請先生成或輸入下載網址（path）。")
            return

        fw = self.le_fw.text().strip()
        if not fw or not os.path.isfile(fw):
            QMessageBox.warning(self, "提醒", "請先於左側選擇有效的韌體檔並啟動伺服器。")
            return
        try:
            md5, size = file_md5_and_size(fw)  # 確保 hash/size 與實檔一致
        except Exception as e:
            QMessageBox.warning(self, "提醒", f"計算 MD5/Size 失敗：{e}")
            return

        targets = self.gather_targets()
        if not targets:
            QMessageBox.warning(self, "提醒", "請輸入至少一台設備（支援 ip 或 ip:port）。")
            return

        cfg = {
            "company_id": self.le_company.text().strip() or DEFAULT_COMPANY_ID,
            "token": self.le_token.text().strip() or DEFAULT_TOKEN,
            "response_val": self.le_response.text().strip() or DEFAULT_RESPONSE,
            "filename": self.le_filename.text().strip() or os.path.basename(fw) or DEFAULT_FILENAME,
            "version": self.le_version.text().strip() or DEFAULT_VERSION,
            "download_url": url,
            "size": size,
            "md5": md5,
            "threads": int(self.sb_threads.value()),
        }

        self.tbl.setRowCount(0)
        self.pb.setMaximum(len(targets))
        self.pb.setValue(0)
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)

        self.worker = SyncWorker(targets, cfg)
        self.worker.one_result.connect(self.on_one_result)
        self.worker.progress.connect(self.on_progress)
        self.worker.all_done.connect(self.on_all_done)
        self.worker.start()

    def on_stop(self):
        try:
            if hasattr(self, "worker") and self.worker.isRunning():
                self.worker.stop()
        except Exception:
            pass
        self.btn_stop.setEnabled(False)

    @Slot(str, int, str)
    def on_one_result(self, ipport, status, msg):
        r = self.tbl.rowCount()
        self.tbl.insertRow(r)
        self.tbl.setItem(r, 0, QTableWidgetItem(ipport))
        self.tbl.setItem(r, 1, QTableWidgetItem(str(status)))
        self.tbl.setItem(r, 2, QTableWidgetItem(msg or ""))

    @Slot(int, int)
    def on_progress(self, done, total):
        self.pb.setValue(done)

    @Slot()
    def on_all_done(self):
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        QMessageBox.information(self, "完成", "所有設備已完成下發。")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setApplicationName(APP_TITLE)
    win = MainWindow()
    win.showMaximized()
    sys.exit(app.exec())
