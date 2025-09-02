# -*- coding: utf-8 -*-
"""
Web 更新操作攔截分析器 (HTTP Proxy + GUI)
v3:
- Listen 預設改 127.0.0.1，降低防火牆干擾
- 保留 CONNECT(HTTPS) 直通；僅攔截/解析明文 HTTP
- 新增「匯出 PAC」：只讓指定子網(預設 192.168.200.0/24) 的 HTTP 走代理，其餘 DIRECT
"""

import asyncio
import datetime
import io
import json
import os
import queue
import re
import sys
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple, List

from PySide6.QtCore import Qt, QTimer, Signal, QObject
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QTableWidget, QTableWidgetItem, QHeaderView, QCheckBox,
    QFileDialog, QMessageBox, QTextEdit, QGroupBox, QSplitter
)

APP_NAME = "Web 更新操作攔截分析器"
DEFAULT_LISTEN_HOST = "127.0.0.1"  # v3: 只綁回環，較不會被防火牆擋
DEFAULT_LISTEN_PORT = 8088

BASE_DIR = os.path.dirname(os.path.abspath(sys.argv[0]))
LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

MAX_HEADER_SUMMARY_LEN = 200
JSON_CT_RE = re.compile(r"application/(?:json|.*\+json)", re.I)
FORM_CT_RE = re.compile(r"multipart/form-data", re.I)
URLENC_CT_RE = re.compile(r"application/x-www-form-urlencoded", re.I)


@dataclass
class RequestRecord:
    ts: float
    method: str
    scheme: str
    host: str
    port: int
    path: str
    query: str
    http_version: str
    req_headers: Dict[str, str]
    req_body_raw: bytes = b""
    req_json: Optional[dict] = None
    req_form_fields: Dict[str, str] = field(default_factory=dict)
    req_form_files: Dict[str, Dict[str, str]] = field(default_factory=dict)
    status_code: Optional[int] = None
    resp_headers: Dict[str, str] = field(default_factory=dict)
    resp_len: Optional[int] = None
    content_type: str = ""

    def to_row(self) -> List[str]:
        t = datetime.datetime.fromtimestamp(self.ts).strftime("%H:%M:%S")
        hdr_keys = []
        for k in ["company-id", "token", "authorization", "cookie"]:
            v = self.req_headers.get(k, "")
            if v:
                if len(v) > 40:
                    v = v[:37] + "..."
                hdr_keys.append(f"{k}:{v}")
        hdr_summary = " | ".join(hdr_keys)[:MAX_HEADER_SUMMARY_LEN]

        payload_summary = ""
        if self.req_json is not None:
            keys = []
            for k in ["action", "filename", "path", "room", "room_id"]:
                if k in self.req_json:
                    keys.append(f"{k}={self.req_json[k]}")
            if not keys:
                js = json.dumps(self.req_json, ensure_ascii=False)
                payload_summary = js[:80] + ("..." if len(js) > 80 else "")
            else:
                payload_summary = ", ".join(keys)
        elif self.req_form_fields or self.req_form_files:
            ss = []
            if self.req_form_fields:
                for k, v in self.req_form_fields.items():
                    if len(v) > 40: v = v[:37] + "..."
                    ss.append(f"{k}={v}")
            if self.req_form_files:
                for k, meta in self.req_form_files.items():
                    fn = meta.get("filename", "")
                    ss.append(f"{k}(file)={fn}")
            payload_summary = " | ".join(ss)[:120]
        else:
            if self.query:
                qs = urllib.parse.parse_qs(self.query, keep_blank_values=True)
                for k in ["verify", "token"]:
                    if k in qs:
                        v = qs[k][0]
                        if len(v) > 40: v = v[:37] + "..."
                        payload_summary = f"{k}={v}"
                        break

        return [
            t,
            self.method,
            f"{self.host}:{self.port}",
            self.path or "/",
            (self.query[:40] + "...") if len(self.query) > 40 else self.query,
            str(self.status_code or ""),
            (self.content_type[:40] + "...") if len(self.content_type) > 40 else self.content_type,
            (payload_summary[:80] + "...") if len(payload_summary) > 80 else payload_summary,
            hdr_summary
        ]


class HTTPProxyServer:
    """
    簡易 HTTP 代理：
    - 攔截/解析/轉送明文 HTTP
    - 支援 CONNECT 直通（HTTPS tunnel），不做 MITM
    """
    def __init__(self, host: str, port: int, log_queue: queue.Queue,
                 only_interesting: bool = True, ip_filter: str = "", path_filter: str = ""):
        self.host = host
        self.port = port
        self.log_queue = log_queue
        self.only_interesting = only_interesting
        self.ip_filter = ip_filter.strip()
        self.path_filter = path_filter.strip()

    def _match_filters(self, rec: RequestRecord) -> bool:
        ok = True
        if self.ip_filter:
            ok = (self.ip_filter in rec.host)
        if ok and self.path_filter:
            ok = (self.path_filter in rec.path)
        if ok and self.only_interesting:
            ct = rec.req_headers.get("content-type", "")
            interesting = bool(JSON_CT_RE.search(ct) or FORM_CT_RE.search(ct) or URLENC_CT_RE.search(ct))
            if ("/cmd/sync" in rec.path) or ("/monitor" in rec.path) or ("/api/cmd/download" in rec.path):
                interesting = True
            ok = interesting
        return ok

    async def _handle_connect(self, writer: asyncio.StreamWriter, host: str, port: int,
                              client_reader: asyncio.StreamReader):
        try:
            upstream_reader, upstream_writer = await asyncio.open_connection(host, port)
        except Exception:
            try:
                writer.write(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                await writer.drain()
            finally:
                writer.close(); await writer.wait_closed()
            return

        writer.write(b"HTTP/1.1 200 Connection Established\r\nProxy-agent: SimpleProxy/3.0\r\n\r\n")
        await writer.drain()

        async def pipe(reader, w):
            try:
                while True:
                    data = await reader.read(65536)
                    if not data:
                        break
                    w.write(data)
                    await w.drain()
            except Exception:
                pass

        task1 = asyncio.create_task(pipe(client_reader, upstream_writer))
        task2 = asyncio.create_task(pipe(upstream_reader, writer))
        await asyncio.wait([task1, task2], return_when=asyncio.FIRST_COMPLETED)
        try:
            upstream_writer.close(); await upstream_writer.wait_closed()
        except Exception:
            pass
        try:
            writer.close(); await writer.wait_closed()
        except Exception:
            pass

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            header_bytes = await reader.readuntil(b"\r\n\r\n")
        except Exception:
            writer.close()
            try: await writer.wait_closed()
            except Exception: pass
            return

        try:
            request_line, headers = self._parse_headers(header_bytes)
        except Exception:
            writer.close()
            try: await writer.wait_closed()
            except Exception: pass
            return

        method, target, http_version = request_line

        if method.upper() == "CONNECT":
            host, port = target.split(":") if ":" in target else (target, "443")
            try: port = int(port)
            except: port = 443
            await self._handle_connect(writer, host, port, reader)
            return

        try:
            host, port, path, scheme, query = self._resolve_target(target, headers)
        except Exception:
            try:
                writer.write(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
                await writer.drain()
            finally:
                writer.close(); await writer.wait_closed()
            return

        body = b""
        content_length = int(headers.get("content-length", "0") or "0")
        if content_length > 0:
            try:
                body = await reader.readexactly(content_length)
            except Exception:
                body = b""

        upstream_request_line = f"{method} {path if query=='' else path + '?' + query} {http_version}\r\n"
        if "proxy-connection" in headers:
            headers.pop("proxy-connection", None)
        headers["connection"] = "close"
        hdr_out = self._build_header_bytes(headers)

        req_headers_lower = {k.lower(): v for k, v in headers.items()}
        rec = RequestRecord(
            ts=time.time(), method=method.upper(), scheme=scheme,
            host=host, port=port, path=path, query=query, http_version=http_version,
            req_headers=req_headers_lower, req_body_raw=body
        )
        self._parse_request_payload(rec)
        should_log = self._match_filters(rec)

        total_resp_len = 0
        status_code = None
        resp_headers = {}
        content_type = ""
        try:
            reader_u, writer_u = await asyncio.open_connection(host, port)
            writer_u.write(upstream_request_line.encode("utf-8") + hdr_out + b"\r\n" + body)
            await writer_u.drain()

            resp_header_bytes = await reader_u.readuntil(b"\r\n\r\n")
            status_line, resp_headers = self._parse_response_headers(resp_header_bytes)
            status_code = status_line[1]
            content_type = resp_headers.get("content-type", "")

            writer.write(resp_header_bytes); await writer.drain()

            while True:
                chunk = await reader_u.read(65536)
                if not chunk: break
                total_resp_len += len(chunk)
                writer.write(chunk); await writer.drain()

            writer_u.close(); await writer_u.wait_closed()
        except Exception:
            try:
                writer.write(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                await writer.drain()
            except Exception:
                pass
        finally:
            try:
                writer.close(); await writer.wait_closed()
            except Exception:
                pass

        rec.status_code = status_code
        rec.resp_headers = {k.lower(): v for k, v in resp_headers.items()}
        rec.resp_len = total_resp_len
        rec.content_type = content_type

        if should_log:
            self.log_queue.put(rec)

    def _parse_headers(self, raw: bytes) -> Tuple[Tuple[str, str, str], Dict[str, str]]:
        buf = raw.decode("iso-8859-1")
        lines = buf.split("\r\n")
        req_line = lines[0]
        parts = req_line.split()
        if len(parts) < 3: raise ValueError("Bad request line")
        method, target, http_ver = parts[0], parts[1], parts[2]
        headers = {}
        for line in lines[1:]:
            if not line: break
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
        return (method, target, http_ver), headers

    def _parse_response_headers(self, raw: bytes) -> Tuple[Tuple[str, int, str], Dict[str, str]]:
        buf = raw.decode("iso-8859-1")
        lines = buf.split("\r\n")
        status_line = lines[0]
        m = re.match(r"HTTP/(\d\.\d)\s+(\d{3})\s+(.*)", status_line)
        if not m: raise ValueError("Bad status line")
        http_ver, code, reason = m.group(1), int(m.group(2)), m.group(3)
        headers = {}
        for line in lines[1:]:
            if not line: break
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
        return (http_ver, code, reason), headers

    def _resolve_target(self, target: str, headers: Dict[str, str]) -> Tuple[str, int, str, str, str]:
        scheme = "http"; host = ""; port = 80; path = "/"; query = ""
        if target.startswith("http://") or target.startswith("https://"):
            u = urllib.parse.urlsplit(target)
            scheme = u.scheme
            host = u.hostname or ""
            port = u.port or (443 if scheme == "https" else 80)
            path = u.path or "/"
            query = u.query or ""
        else:
            host_hdr = headers.get("host", "")
            if not host_hdr: raise ValueError("No Host header")
            if ":" in host_hdr:
                host, p = host_hdr.rsplit(":", 1)
                try: port = int(p)
                except: port = 80
            else:
                host = host_hdr; port = 80
            if "?" in target: path, query = target.split("?", 1)
            else: path = target; query = ""
        return host, port, path, scheme, query

    def _build_header_bytes(self, headers: Dict[str, str]) -> bytes:
        out = io.StringIO()
        for k, v in headers.items():
            out.write(f"{k.capitalize()}: {v}\r\n")
        return out.getvalue().encode("iso-8859-1")

    def _parse_request_payload(self, rec: RequestRecord):
        ct = rec.req_headers.get("content-type", "")
        body = rec.req_body_raw or b""
        if not body: return
        if JSON_CT_RE.search(ct):
            try: rec.req_json = json.loads(body.decode("utf-8", errors="ignore"))
            except Exception: pass
            return
        if URLENC_CT_RE.search(ct):
            try:
                s = body.decode("utf-8", errors="ignore")
                kv = urllib.parse.parse_qs(s, keep_blank_values=True)
                for k, vs in kv.items(): rec.req_form_fields[k] = vs[0] if vs else ""
            except Exception: pass
            return
        if FORM_CT_RE.search(ct):
            m = re.search(r'boundary="?([^";]+)"?', ct, re.I)
            if not m: return
            boundary = m.group(1).encode()
            parts = body.split(b"--" + boundary)
            for part in parts:
                if not part or part in (b"--\r\n", b"--"): continue
                part = part.lstrip(b"\r\n")
                if part.endswith(b"\r\n"): part = part[:-2]
                header_seg, _, data_seg = part.partition(b"\r\n\r\n")
                hdr_text = header_seg.decode("iso-8859-1", errors="ignore")
                disp = re.search(r'Content-Disposition:\s*form-data;\s*(.*)', hdr_text, re.I)
                if not disp: continue
                disp_params = disp.group(1)
                name_m = re.search(r'name="([^"]+)"', disp_params)
                fname_m = re.search(r'filename="([^"]*)"', disp_params)
                name = name_m.group(1) if name_m else ""
                ctype_m = re.search(r'Content-Type:\s*([^\r\n]+)', hdr_text, re.I)
                ctype = ctype_m.group(1).strip() if ctype_m else ""
                if fname_m and fname_m.group(1):
                    fn = fname_m.group(1); size = str(len(data_seg))
                    rec.req_form_files[name] = {"filename": fn, "content_type": ctype, "size": size}
                else:
                    try: val = data_seg.decode("utf-8", errors="ignore")
                    except Exception: val = ""
                    rec.req_form_fields[name] = val.strip()


class LogCollector(QObject):
    new_record = Signal(object)


def cidr_to_netmask(cidr: str) -> Tuple[str, str]:
    """return (network, netmask) from '192.168.200.0/24'"""
    try:
        ip, bits = cidr.split("/")
        bits = int(bits)
        mask = (0xffffffff << (32 - bits)) & 0xffffffff
        netmask = ".".join(str((mask >> (8 * i)) & 0xff) for i in [3,2,1,0])
        # 簡單取網路位址
        octs_ip = [int(p) for p in ip.split(".")]
        octs_mk = [int(p) for p in netmask.split(".")]
        network = ".".join(str(octs_ip[i] & octs_mk[i]) for i in range(4))
        return network, netmask
    except Exception:
        return "192.168.200.0", "255.255.255.0"


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.setMinimumSize(1120, 720)
        ico_path = os.path.join(BASE_DIR, "main.ico")
        if os.path.exists(ico_path): self.setWindowIcon(QIcon(ico_path))

        self.proxy: Optional[HTTPProxyServer] = None
        self.log_queue: queue.Queue = queue.Queue()
        self.records: List[RequestRecord] = []

        self._build_ui()
        self._wire_events()

        self.timer = QTimer(self); self.timer.setInterval(200)
        self.timer.timeout.connect(self._drain_queue); self.timer.start()

        self.showMaximized()

    def _build_ui(self):
        layout = QVBoxLayout(self)

        ctrl_box = QGroupBox("代理設定 / 控制")
        ctrl_lay = QHBoxLayout(ctrl_box)
        self.listen_host_edit = QLineEdit(DEFAULT_LISTEN_HOST)
        self.listen_port_edit = QLineEdit(str(DEFAULT_LISTEN_PORT))
        self.only_interesting_cb = QCheckBox("只記錄更新相關/JSON/表單"); self.only_interesting_cb.setChecked(True)
        self.ip_filter_edit = QLineEdit(); self.ip_filter_edit.setPlaceholderText("主機/IP 篩選（可空）例：192.168.200.")
        self.path_filter_edit = QLineEdit(); self.path_filter_edit.setPlaceholderText("路徑關鍵字（可空）例：/cmd/sync")
        self.start_btn = QPushButton("啟動攔截"); self.stop_btn = QPushButton("停止"); self.stop_btn.setEnabled(False)
        ctrl_lay.addWidget(QLabel("Listen")); ctrl_lay.addWidget(self.listen_host_edit)
        ctrl_lay.addWidget(QLabel(":")); ctrl_lay.addWidget(self.listen_port_edit)
        ctrl_lay.addWidget(self.only_interesting_cb)
        ctrl_lay.addWidget(self.ip_filter_edit, 1); ctrl_lay.addWidget(self.path_filter_edit, 1)
        ctrl_lay.addWidget(self.start_btn); ctrl_lay.addWidget(self.stop_btn)
        layout.addWidget(ctrl_box)

        pac_box = QGroupBox("PAC（只讓指定子網的 HTTP 經代理，其餘 DIRECT）")
        pac_lay = QHBoxLayout(pac_box)
        self.pac_subnets_edit = QLineEdit("192.168.200.0/24")  # 可用逗號分隔多個
        self.export_pac_btn = QPushButton("匯出 PAC")
        pac_lay.addWidget(QLabel("子網(逗號分隔CIDR)："))
        pac_lay.addWidget(self.pac_subnets_edit, 1)
        pac_lay.addWidget(self.export_pac_btn)
        layout.addWidget(pac_box)

        hint = QLabel("建議使用 PAC：系統→Proxy→『使用設定指令碼』載入本工具匯出的 .pac，只讓 192.168.200.0/24 的 HTTP 走 127.0.0.1:8088。")
        hint.setStyleSheet("color:#888;")
        layout.addWidget(hint)

        spl = QSplitter(Qt.Vertical); layout.addWidget(spl, 1)

        self.table = QTableWidget(0, 9)
        self.table.setHorizontalHeaderLabels(["時間","方法","主機:Port","路徑","Query","狀態","Content-Type","Payload 摘要","關鍵標頭"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setEditTriggers(self.table.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(self.table.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setColumnWidth(0, 80); self.table.setColumnWidth(1, 70); self.table.setColumnWidth(2, 170)
        self.table.setColumnWidth(3, 250); self.table.setColumnWidth(4, 200); self.table.setColumnWidth(5, 60)
        self.table.setColumnWidth(6, 140); self.table.setColumnWidth(7, 280); self.table.setColumnWidth(8, 220)
        spl.addWidget(self.table)

        bottom = QWidget(); b_lay = QVBoxLayout(bottom)
        btns = QHBoxLayout()
        self.export_csv_btn = QPushButton("匯出 CSV")
        self.export_jsonl_btn = QPushButton("匯出 JSONL")
        self.blueprint_btn = QPushButton("匯出更新藍圖（JSON）")
        self.clear_btn = QPushButton("清空列表")
        btns.addWidget(self.export_csv_btn); btns.addWidget(self.export_jsonl_btn); btns.addWidget(self.blueprint_btn)
        btns.addStretch(1); btns.addWidget(self.clear_btn)
        b_lay.addLayout(btns)

        self.detail = QTextEdit(); self.detail.setReadOnly(True)
        self.detail.setStyleSheet("font-family: Consolas, monospace;")
        b_lay.addWidget(self.detail, 1)
        spl.addWidget(bottom); spl.setSizes([520, 300])

    def _wire_events(self):
        self.start_btn.clicked.connect(self.on_start)
        self.stop_btn.clicked.connect(self.on_stop)
        self.table.itemSelectionChanged.connect(self.on_select_row)
        self.export_csv_btn.clicked.connect(self.on_export_csv)
        self.export_jsonl_btn.clicked.connect(self.on_export_jsonl)
        self.blueprint_btn.clicked.connect(self.on_export_blueprint)
        self.clear_btn.clicked.connect(self.on_clear)
        self.export_pac_btn.clicked.connect(self.on_export_pac)

    def on_start(self):
        host = self.listen_host_edit.text().strip() or DEFAULT_LISTEN_HOST
        try: port = int(self.listen_port_edit.text().strip())
        except:
            QMessageBox.warning(self, "錯誤", "Port 必須是數字"); return

        self.proxy = HTTPProxyServer(
            host, port, self.log_queue,
            only_interesting=self.only_interesting_cb.isChecked(),
            ip_filter=self.ip_filter_edit.text(),
            path_filter=self.path_filter_edit.text()
        )
        def runner():
            try:
                loop = asyncio.new_event_loop(); asyncio.set_event_loop(loop)
                server_coro = asyncio.start_server(self.proxy.handle_client, host, port)
                server = loop.run_until_complete(server_coro)
                addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
                print(f"[i] Listening on {addrs}")
                loop.run_forever()
            except Exception as e:
                print("[!] Proxy server stopped:", e)
        t = threading.Thread(target=runner, daemon=True); t.start()

        self.start_btn.setEnabled(False); self.stop_btn.setEnabled(True)
        QMessageBox.information(self, "已啟動",
            f"代理已啟動：{host}:{port}\n"
            f"建議：使用『PAC 設定指令碼』而非手動代理，先按『匯出 PAC』，再到 Windows Proxy 載入。")

    def on_stop(self):
        self.start_btn.setEnabled(True); self.stop_btn.setEnabled(False)
        QMessageBox.information(self, "已停止", "攔截停止（關閉程式將釋放連接）。")

    def _drain_queue(self):
        updated = False
        while True:
            try: rec = self.log_queue.get_nowait()
            except queue.Empty: break
            self.records.append(rec); self._append_row(rec); updated = True
        if updated and self.table.rowCount() > 0 and not self.table.selectedItems():
            self.table.selectRow(self.table.rowCount() - 1)

    def _append_row(self, rec: RequestRecord):
        r = self.table.rowCount(); self.table.insertRow(r)
        for c, txt in enumerate(rec.to_row()):
            item = QTableWidgetItem(txt)
            if c == 5:
                try:
                    code = int(txt)
                    if code >= 400: item.setForeground(Qt.red)
                except: pass
            self.table.setItem(r, c, item)

    def on_select_row(self):
        rows = self.table.selectionModel().selectedRows()
        if not rows: return
        r = rows[0].row()
        if r < 0 or r >= len(self.records): return
        rec = self.records[r]
        self.detail.setPlainText(self._format_detail(rec))

    def _format_detail(self, rec: RequestRecord) -> str:
        lines = []
        lines.append(f"時間: {datetime.datetime.fromtimestamp(rec.ts)}")
        lines.append(f"方法: {rec.method}")
        full_url = f"{rec.scheme}://{rec.host}:{rec.port}{rec.path}{('?'+rec.query) if rec.query else ''}"
        lines.append(f"URL : {full_url}")
        lines.append(f"HTTP: {rec.http_version}\n")
        lines.append("[Request Headers]")
        for k, v in rec.req_headers.items(): lines.append(f"{k}: {v}")
        lines.append("")
        if rec.req_json is not None:
            lines.append("[Request JSON]"); lines.append(json.dumps(rec.req_json, ensure_ascii=False, indent=2))
        elif rec.req_form_fields or rec.req_form_files:
            lines.append("[Request Form Fields]")
            for k, v in rec.req_form_fields.items(): lines.append(f"{k} = {v}")
            if rec.req_form_files:
                lines.append("[Request Form Files]")
                for k, meta in rec.req_form_files.items():
                    lines.append(f"{k}: filename={meta.get('filename')}, content_type={meta.get('content_type')}, size={meta.get('size')}")
        elif rec.req_body_raw:
            sniff = rec.req_body_raw[:400]
            try: sniff_txt = sniff.decode("utf-8", errors="ignore")
            except: sniff_txt = str(sniff)
            lines.append("[Request Body Sniff]"); lines.append(sniff_txt + ("..." if len(rec.req_body_raw) > 400 else ""))

        lines.append(""); lines.append(f"狀態: {rec.status_code}")
        lines.append(f"回應 Content-Type: {rec.content_type}")
        lines.append(f"回應長度: {rec.resp_len}\n")
        lines.append("[Response Headers]")
        for k, v in rec.resp_headers.items(): lines.append(f"{k}: {v}")
        return "\n".join(lines)

    def on_export_csv(self):
        if not self.records:
            QMessageBox.information(self, "提示", "目前沒有資料"); return
        path, _ = QFileDialog.getSaveFileName(self, "匯出 CSV", os.path.join(LOG_DIR, "capture.csv"), "CSV (*.csv)")
        if not path: return
        import csv
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerow(["time","method","host_port","path","query","status","content_type","payload_summary","key_headers"])
            for rec in self.records: writer.writerow(rec.to_row())
        QMessageBox.information(self, "完成", f"已匯出：{path}")

    def on_export_jsonl(self):
        if not self.records:
            QMessageBox.information(self, "提示", "目前沒有資料"); return
        path, _ = QFileDialog.getSaveFileName(self, "匯出 JSONL", os.path.join(LOG_DIR, "capture.jsonl"), "JSONL (*.jsonl)")
        if not path: return
        with open(path, "w", encoding="utf-8") as f:
            for rec in self.records:
                obj = {
                    "ts": rec.ts,
                    "time": datetime.datetime.fromtimestamp(rec.ts).isoformat(),
                    "method": rec.method,
                    "scheme": rec.scheme,
                    "host": rec.host,
                    "port": rec.port,
                    "path": rec.path,
                    "query": rec.query,
                    "http_version": rec.http_version,
                    "req_headers": rec.req_headers,
                    "req_json": rec.req_json,
                    "req_form_fields": rec.req_form_fields,
                    "req_form_files": rec.req_form_files,
                    "status_code": rec.status_code,
                    "resp_headers": rec.resp_headers,
                    "resp_len": rec.resp_len,
                    "content_type": rec.content_type
                }
                f.write(json.dumps(obj, ensure_ascii=False) + "\n")
        QMessageBox.information(self, "完成", f"已匯出：{path}")

    def on_export_blueprint(self):
        if not self.records:
            QMessageBox.information(self, "提示", "目前沒有資料"); return
        endpoints: Dict[Tuple[str, str], Dict] = {}
        header_counts: Dict[str, int] = {}
        tokens = set(); verifies = set()

        for rec in self.records:
            key = (rec.method, rec.path)
            ep = endpoints.setdefault(key, {"method": rec.method, "path": rec.path, "samples": []})
            ep["samples"].append({
                "query": rec.query,
                "headers": rec.req_headers,
                "json": rec.req_json,
                "form_fields": rec.req_form_fields,
                "form_files": rec.req_form_files
            })
            for hk in ["company-id","token","authorization","cookie","content-type"]:
                v = rec.req_headers.get(hk)
                if v: header_counts[hk] = header_counts.get(hk, 0) + 1
            if "token" in rec.req_headers: tokens.add(rec.req_headers["token"])
            if rec.query:
                qs = urllib.parse.parse_qs(rec.query, keep_blank_values=True)
                if "verify" in qs: verifies.add(qs["verify"][0])

        common_headers = [k for k, cnt in header_counts.items() if cnt >= max(1, int(len(self.records) * 0.3))]
        blueprint = {
            "generated_at": datetime.datetime.now().isoformat(),
            "notes": "此藍圖彙整你在 Web 後台執行更新時的 API 使用方式，供後續做自動化 GUI 更新工具參考。",
            "endpoints": [],
            "common_headers": common_headers,
            "tokens_collected": list(tokens),
            "verify_samples": list(verifies)
        }
        for (_, _), ep in endpoints.items():
            best = None
            for s in ep["samples"]:
                j = s["json"] or {}; ff = s["form_fields"] or {}
                if ("action" in j) or ("filename" in j) or ("path" in j) or ("filename" in ff) or ("path" in ff):
                    best = s; break
            if not best and ep["samples"]: best = ep["samples"][0]
            blueprint["endpoints"].append({
                "method": ep["method"],
                "path": ep["path"],
                "sample_query": (best or {}).get("query", ""),
                "sample_headers_subset": {k: v for k, v in ((best or {}).get("headers", {})).items()
                                          if k in ["company-id","token","authorization","cookie","content-type"]},
                "sample_json": (best or {}).get("json"),
                "sample_form_fields": (best or {}).get("form_fields"),
                "sample_form_files": (best or {}).get("form_files")
            })

        fn = os.path.join(LOG_DIR, f"upgrade_blueprint_{int(time.time())}.json")
        with open(fn, "w", encoding="utf-8") as f:
            json.dump(blueprint, f, ensure_ascii=False, indent=2)
        QMessageBox.information(self, "完成", f"已輸出更新藍圖：\n{fn}")

    def on_export_pac(self):
        # 依目前 listen host/port 與子網輸出 PAC
        host = self.listen_host_edit.text().strip() or DEFAULT_LISTEN_HOST
        try:
            port = int(self.listen_port_edit.text().strip())
        except:
            QMessageBox.warning(self, "錯誤", "Port 必須是數字")
            return

        raw = self.pac_subnets_edit.text().strip()
        cidrs = [c.strip() for c in raw.split(",") if c.strip()]
        lines = []
        lines.append("function FindProxyForURL(url, host) {")
        lines.append('  if (url.slice(0,7) == "http://") {')
        for c in cidrs:
            net, mask = cidr_to_netmask(c)
            lines.append(f'    if (isInNet(host, "{net}", "{mask}")) return "PROXY {host}:{port}";')
        lines.append('  }')
        lines.append('  return "DIRECT";')
        lines.append("}")
        pac_text = "\n".join(lines)
        fn = os.path.join(LOG_DIR, f"update_proxy_{port}.pac")
        with open(fn, "w", encoding="utf-8") as f:
            f.write(pac_text)
        QMessageBox.information(
            self, "PAC 已匯出",
            f"路徑：{fn}\n\nWindows → 設定 → 網路與網際網路 → Proxy → 使用設定指令碼 → URL 指向：\nfile:///{fn.replace(os.sep, '/')}\n"
            "套用後：只有指定子網的 HTTP 會經代理，其餘全直連。"
        )

    def on_clear(self):
        self.records.clear()
        self.table.setRowCount(0)
        self.detail.clear()


def main():
    app = QApplication(sys.argv)
    ico_path = os.path.join(BASE_DIR, "main.ico")
    if os.path.exists(ico_path): app.setWindowIcon(QIcon(ico_path))
    win = MainWindow(); win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
