# -*- coding: utf-8 -*-
"""
SIP 封包分析 GUI（避免 pyshark 與 asyncio 衝突的穩定版）
- 以 tshark 串流分析 SIP 封包
- 追蹤 Call-ID 狀態，標記一側掛斷但另一側未結束的異常
作者：DT/ChatGPT
"""

import sys
import os
import csv
import json
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, List

from PySide6.QtCore import Qt, QTimer, QProcess, Signal, QObject, QAbstractTableModel, QModelIndex
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QComboBox, QLineEdit, QFileDialog, QTableView,
    QSpinBox, QGroupBox, QFormLayout, QMessageBox, QCheckBox
)

# 若未加入 PATH，可在此指定 tshark 路徑
TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"  # 例：r"C:\Program Files\Wireshark\tshark.exe"

# tshark 欄位：不要改順序（解析時靠 index）
TSHARK_FIELDS = [
    "frame.time_epoch",   # 0
    "ip.src",             # 1
    "ip.dst",             # 2
    "udp.srcport",        # 3
    "udp.dstport",        # 4
    "sip.Call-ID",        # 5
    "sip.Method",         # 6 (INVITE/BYE/CANCEL/ACK/..)
    "sip.Status-Code",    # 7 (200/486/..)
    "sip.CSeq.method"     # 8 (INVITE/BYE/.. 對應 CSeq)
]

@dataclass
class DialogEvent:
    ts: float
    src: str
    dst: str
    sport: str
    dport: str
    call_id: str
    method: str
    status: str
    cseq_method: str

@dataclass
class DialogState:
    call_id: str
    first_ts: float = 0.0
    last_ts: float = 0.0
    caller: Optional[str] = None  # 以第一個 INVITE 來源做 caller 粗略判定
    callee: Optional[str] = None
    established: bool = False     # 是否已建立（例如看到 200 對 INVITE + ACK）
    bye_sent_ts: Optional[float] = None
    bye_from: Optional[str] = None
    bye_confirmed: bool = False   # 是否收到 200 對 BYE
    anomaly: Optional[str] = None # 記錄異常描述
    history: List[str] = field(default_factory=list)  # 記錄事件軌跡

class DialogTableModel(QAbstractTableModel):
    HEADERS = ["Call-ID", "Caller", "Callee", "建立", "BYE來源", "BYE確認", "異常", "起始時間", "最後時間"]

    def __init__(self, dialogs: Dict[str, DialogState]):
        super().__init__()
        self._dialogs = dialogs
        self._keys_cache = []

    def refresh(self):
        self.beginResetModel()
        self._keys_cache = sorted(self._dialogs.keys(), key=lambda k: self._dialogs[k].first_ts)
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return len(self._keys_cache)

    def columnCount(self, parent=QModelIndex()):
        return len(self.HEADERS)

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid() or role not in (Qt.DisplayRole, Qt.ToolTipRole):
            return None
        d: DialogState = self._dialogs[self._keys_cache[index.row()]]
        col = index.column()
        if col == 0:  # Call-ID
            val = d.call_id
        elif col == 1:
            val = d.caller or ""
        elif col == 2:
            val = d.callee or ""
        elif col == 3:
            val = "是" if d.established else "否"
        elif col == 4:
            val = d.bye_from or ""
        elif col == 5:
            val = "是" if d.bye_confirmed else "否"
        elif col == 6:
            val = d.anomaly or ""
        elif col == 7:
            val = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(d.first_ts)) if d.first_ts else ""
        elif col == 8:
            val = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(d.last_ts)) if d.last_ts else ""
        else:
            val = ""
        if role == Qt.ToolTipRole:
            return "\n".join(d.history[-20:])
        return val

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role != Qt.DisplayRole:
            return None
        if orientation == Qt.Horizontal:
            return self.HEADERS[section]
        return str(section + 1)

class TsharkReader(QObject):
    new_event = Signal(object)  # DialogEvent
    finished = Signal(int)      # exit code

    def __init__(self, parent=None):
        super().__init__(parent)
        self.proc = QProcess(self)
        self.proc.setProcessChannelMode(QProcess.MergedChannels)
        self.proc.readyReadStandardOutput.connect(self._read_stdout)
        self.proc.finished.connect(self._finished)
        self._buffer = b""
        self._is_file_mode = False

    def start_live(self, iface: str, bpf: str):
        self._is_file_mode = False
        args = [
            "-l",                      # line buffered
            "-n",                      # no name resolve
            "-i", iface,
            "-f", bpf,
            "-Y", "sip",
            "-T", "fields",
            "-E", "header=n",
            "-E", "occurrence=f",
            "-E", "separator=\t",
        ]
        for f in TSHARK_FIELDS:
            args += ["-e", f]
        self._start_process(args)

    def start_file(self, pcap_path: str):
        self._is_file_mode = True
        args = [
            "-l",
            "-n",
            "-r", pcap_path,
            "-Y", "sip",
            "-T", "fields",
            "-E", "header=n",
            "-E", "occurrence=f",
            "-E", "separator=\t",
        ]
        for f in TSHARK_FIELDS:
            args += ["-e", f]
        self._start_process(args)

    def _start_process(self, args):
        self._buffer = b""
        self.proc.start(TSHARK_PATH, args)

    def stop(self):
        if self.proc.state() != QProcess.NotRunning:
            self.proc.kill()

    def _finished(self, code, _status):
        self.finished.emit(code)

    def _read_stdout(self):
        self._buffer += self.proc.readAllStandardOutput().data()
        lines = self._buffer.split(b"\n")
        self._buffer = lines[-1]  # incomplete
        for line in lines[:-1]:
            if not line.strip():
                continue
            try:
                parts = line.decode(errors="replace").split("\t")
                # 保障長度
                while len(parts) < len(TSHARK_FIELDS):
                    parts.append("")
                evt = DialogEvent(
                    ts=float(parts[0]) if parts[0] else 0.0,
                    src=parts[1],
                    dst=parts[2],
                    sport=parts[3],
                    dport=parts[4],
                    call_id=parts[5],
                    method=parts[6],
                    status=parts[7],
                    cseq_method=parts[8],
                )
                self.new_event.emit(evt)
            except Exception:
                # 忽略解析錯誤但不中斷
                continue

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SIP 封包分析器（單側掛斷偵測）")
        self.resize(1100, 700)

        # 狀態管理
        self.dialogs: Dict[str, DialogState] = {}
        self.model = DialogTableModel(self.dialogs)

        # 控制列
        top_box = QGroupBox("擷取設定")
        top_form = QFormLayout()

        self.iface_combo = QComboBox()
        self.refresh_btn = QPushButton("重新載入介面")
        h_if = QHBoxLayout()
        h_if.addWidget(self.iface_combo, 1)
        h_if.addWidget(self.refresh_btn)
        w_if = QWidget(); w_if.setLayout(h_if)

        self.bpf_edit = QLineEdit('udp port 5060')
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 60)
        self.timeout_spin.setValue(3)
        self.timeout_spin.setSuffix(" 秒 (BYE 等待 200 OK)")

        self.show_active_only = QCheckBox("只顯示有異常/未確認的通話")
        self.show_active_only.setChecked(False)

        top_form.addRow("介面", w_if)
        top_form.addRow("BPF 過濾", self.bpf_edit)
        top_form.addRow("BYE 確認逾時", self.timeout_spin)
        top_form.addRow("", self.show_active_only)
        top_box.setLayout(top_form)

        # 按鈕列
        self.start_btn = QPushButton("開始擷取")
        self.stop_btn = QPushButton("停止")
        self.load_btn = QPushButton("載入 pcap/pcapng")
        self.export_btn = QPushButton("匯出 CSV")
        self.clear_btn = QPushButton("清空列表")
        btn_row = QHBoxLayout()
        for b in (self.start_btn, self.stop_btn, self.load_btn, self.export_btn, self.clear_btn):
            btn_row.addWidget(b)
        btn_row.addStretch(1)

        # 表格
        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setSortingEnabled(False)
        self.table.setSelectionBehavior(QTableView.SelectRows)
        self.table.setAlternatingRowColors(True)

        # 佈局
        root = QWidget()
        lay = QVBoxLayout(root)
        lay.addWidget(top_box)
        lay.addLayout(btn_row)
        lay.addWidget(self.table, 1)
        self.setCentralWidget(root)

        # Tshark reader
        self.reader = TsharkReader(self)
        self.reader.new_event.connect(self.on_new_event)
        self.reader.finished.connect(self.on_reader_finished)

        # Timer：定期檢查 BYE 未確認的逾時
        self.check_timer = QTimer(self)
        self.check_timer.setInterval(500)  # 0.5s
        self.check_timer.timeout.connect(self.check_timeouts)

        # 信號連接
        self.refresh_btn.clicked.connect(self.load_interfaces)
        self.start_btn.clicked.connect(self.start_capture)
        self.stop_btn.clicked.connect(self.stop_capture)
        self.load_btn.clicked.connect(self.load_file)
        self.export_btn.clicked.connect(self.export_csv)
        self.clear_btn.clicked.connect(self.clear_all)
        self.show_active_only.toggled.connect(lambda _: self.model.refresh())

        # 啟動時載入介面
        self.load_interfaces()

    def load_interfaces(self):
        # 取得介面列表：tshark -D
        proc = QProcess(self)
        proc.start(TSHARK_PATH, ["-D"])
        if not proc.waitForFinished(4000):
            QMessageBox.critical(self, "錯誤", "無法執行 tshark，請確認已安裝並設定 PATH 或在程式中設定 TSHARK_PATH。")
            return
        out = proc.readAllStandardOutput().data().decode(errors="replace").strip().splitlines()
        self.iface_combo.clear()
        # 每行格式類似：1. \Device\NPF_{GUID} (描述)
        for line in out:
            line = line.strip()
            if not line:
                continue
            # 取最前面的介面序號（tshark 接受序號）
            num = line.split(".", 1)[0].strip()
            self.iface_combo.addItem(line, num)

    def start_capture(self):
        if self.reader.proc.state() != QProcess.NotRunning:
            QMessageBox.information(self, "提示", "擷取已在進行中。")
            return
        iface_num = self.iface_combo.currentData()
        bpf = self.bpf_edit.text().strip() or "udp port 5060"
        self.reader.start_live(str(iface_num), bpf)
        self.check_timer.start()
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

    def stop_capture(self):
        self.reader.stop()
        self.check_timer.stop()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def load_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "選擇 pcap/pcapng 檔案", "", "PCAP Files (*.pcap *.pcapng);;All Files (*.*)")
        if not path:
            return
        self.reader.start_file(path)
        self.check_timer.start()

    def export_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "匯出 CSV", "sip_dialogs.csv", "CSV (*.csv)")
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                w = csv.writer(f)
                w.writerow(self.model.HEADERS)
                for k in sorted(self.dialogs.keys(), key=lambda k: self.dialogs[k].first_ts):
                    d = self.dialogs[k]
                    if self.show_active_only.isChecked():
                        if d.bye_sent_ts and not d.bye_confirmed or d.anomaly:
                            pass
                        else:
                            continue
                    w.writerow([
                        d.call_id,
                        d.caller or "",
                        d.callee or "",
                        "是" if d.established else "否",
                        d.bye_from or "",
                        "是" if d.bye_confirmed else "否",
                        d.anomaly or "",
                        time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(d.first_ts)) if d.first_ts else "",
                        time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(d.last_ts)) if d.last_ts else "",
                    ])
            QMessageBox.information(self, "完成", f"已匯出：{path}")
        except Exception as e:
            QMessageBox.critical(self, "錯誤", f"匯出失敗：{e}")

    def clear_all(self):
        self.dialogs.clear()
        self.model.refresh()

    def on_reader_finished(self, code: int):
        self.check_timer.stop()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def on_new_event(self, evt: DialogEvent):
        if not evt.call_id:
            return
        d = self.dialogs.get(evt.call_id)
        if not d:
            d = DialogState(call_id=evt.call_id, first_ts=evt.ts or time.time())
            self.dialogs[evt.call_id] = d

        d.last_ts = evt.ts or time.time()

        # 記錄簡易足跡
        tag = evt.method or (f"{evt.status}" if evt.status else "")
        d.history.append(f"{evt.ts:.3f} {evt.src}:{evt.sport} -> {evt.dst}:{evt.dport} {evt.call_id} {tag} CSeq:{evt.cseq_method}")

        # 粗略建立 caller/callee
        if (evt.method == "INVITE" or evt.cseq_method == "INVITE") and not d.caller:
            d.caller = evt.src
            d.callee = evt.dst

        # 建立狀態：看到 200 對 INVITE + ACK（簡化）
        if evt.cseq_method == "INVITE":
            if evt.status == "200":
                # 看到 200 INVITE，等 ACK 再標 established；這裡簡化：直接標已建立（多數情況足夠）
                d.established = True
        if evt.method == "ACK":
            d.established = True

        # BYE 邏輯
        if evt.method == "BYE" or evt.cseq_method == "BYE":
            d.bye_sent_ts = evt.ts or time.time()
            d.bye_from = evt.src
            d.bye_confirmed = False
            d.anomaly = None  # 重新等待

        # 200 OK for BYE
        if (evt.status == "200") and (evt.cseq_method == "BYE"):
            d.bye_confirmed = True
            d.anomaly = None

        self.model.refresh()

    def check_timeouts(self):
        now = time.time()
        wait_sec = self.timeout_spin.value()
        changed = False
        for d in self.dialogs.values():
            # 只對有送出 BYE 但尚未確認的對話檢查逾時
            if d.bye_sent_ts and not d.bye_confirmed:
                if now - d.bye_sent_ts > wait_sec:
                    if not d.anomaly:
                        d.anomaly = f"BYE 已送出超過 {wait_sec}s 未收到 200 OK（疑似單側掛斷）"
                        changed = True
        if changed:
            self.model.refresh()

def main():
    # 改用 PySide6，避免 PyQt5 的 sip 警告
    app = QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
