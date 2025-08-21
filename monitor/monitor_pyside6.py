import sys
import os
import re
import csv
import json
import ipaddress
from datetime import datetime
import pandas as pd
import requests

from concurrent.futures import ThreadPoolExecutor, as_completed

# ====== PySide6 ======
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QFileDialog, QLineEdit, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView, QCheckBox,
    QMessageBox, QAbstractItemView, QProgressBar, QListWidget, QListWidgetItem,
    QDialog, QSizePolicy, QGroupBox, QSplitter, QStatusBar, QFrame, QGridLayout
)
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QIcon, QPalette, QColor

# =========================
# 常數
# =========================
DEFAULT_DEV_PORT = 3377
BTN_H = 34
FIXED_COLUMNS = ["選取", "設備類型", "名稱", "IP", "房號"]
DEPLOY_MAX_WORKERS = 50
APP_PASSWORD = os.environ.get("MONITOR_PASSWORD", "tonnet1983")
DEPLOY_BTN_H = 64

# =========================
# 工具
# =========================
def get_icon_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "main.ico")

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
            "選取": False
        })

    if not devices:
        return None

    df = pd.DataFrame(devices).drop_duplicates(subset="IP")
    cols = ["選取", "設備類型", "名稱", "IP", "房號"]
    result = [{k: rec.get(k, "") for k in cols} for rec in df.to_dict(orient="records")]
    return result

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

    ip_set = set()
    device_list = []
    for sheet in xls.sheet_names:
        df = pd.read_excel(file_path, sheet_name=sheet, header=None, dtype=str)
        for _, row in df.iterrows():
            for cell in row:
                if is_nullish(cell):
                    continue
                ip = str(cell).replace(" ", "").strip()
                if is_valid_ip(ip) and ip not in ip_set:
                    device_list.append({"選取": False, "設備類型": "", "名稱": "", "IP": ip, "房號": ""})
                    ip_set.add(ip)
    return device_list

# =========================
# UI：表格
# =========================
class DeviceTable(QTableWidget):
    def __init__(self, parent=None, columns=None):
        super().__init__(0, 0, parent)
        self.columns = list(columns or [])
        if not self.columns:
            self.columns = list(FIXED_COLUMNS)
        if "選取" in self.columns:
            self.columns = ["選取"] + [c for c in self.columns if c != "選取"]
        else:
            self.columns = ["選取"] + self.columns

        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.verticalHeader().setVisible(False)
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.verticalHeader().setDefaultSectionSize(30)

        # 永遠依內容調整欄寬
        header = self.horizontalHeader()
        header.setStretchLastSection(True)
        header.setMinimumSectionSize(60)
        self._apply_headers()
        for c in range(len(self.columns)):
            header.setSectionResizeMode(c, QHeaderView.ResizeToContents)

        self.setStyleSheet("""
            QTableWidget {
                gridline-color: #e5e7eb;
                selection-background-color: #dbeafe;
                selection-color: #111827;
                alternate-background-color: #fafafa;
                background-color: white;
                border: 1px solid #e5e7eb;
                border-radius: 6px;
            }
            QHeaderView::section {
                background: #f3f4f6;
                padding: 8px;
                border: 0px solid #e5e7eb;
                border-right: 1px solid #e5e7eb;
                font-weight: 600;
            }
            QTableWidget::item { padding: 6px; }
            QCheckBox::indicator { width: 20px; height: 20px; }
        """)

        self.cellClicked.connect(self.on_cell_clicked)

    def _apply_headers(self):
        self.setColumnCount(len(self.columns))
        self.setHorizontalHeaderLabels(self.columns)

    def _checkbox_at(self, row):
        w = self.cellWidget(row, 0)
        return w.findChild(QCheckBox) if w else None

    def set_row_checked(self, row, checked):
        cb = self._checkbox_at(row)
        if cb:
            cb.setChecked(checked)

    def on_cell_clicked(self, row, col):
        if col != 0:
            cb = self._checkbox_at(row)
            if cb:
                cb.setChecked(not cb.isChecked())

    def keyPressEvent(self, e):
        if e.key() == Qt.Key_Space:
            rows = sorted(set(i.row() for i in self.selectedIndexes()))
            if rows:
                checks = []
                for r in rows:
                    cb = self._checkbox_at(r)
                    checks.append(cb.isChecked() if cb else False)
                target = not (sum(checks) > len(checks)/2)
                for r in rows:
                    self.set_row_checked(r, target)
                e.accept()
                return
        super().keyPressEvent(e)

    def get_selected_devices(self):
        res = []
        for r in range(self.rowCount()):
            cb = self._checkbox_at(r)
            if cb and cb.isChecked():
                item = {}
                for c, key in enumerate(self.columns):
                    if key == "選取":
                        continue
                    it = self.item(r, c)
                    item[key] = it.text() if it else ""
                res.append(item)
        return res

    def filter(self, keyword):
        kw = (keyword or "").lower()
        for r in range(self.rowCount()):
            txt = []
            for c in range(self.columnCount()):
                it = self.item(r, c)
                if it:
                    txt.append(it.text().lower())
            self.setRowHidden(r, kw not in " ".join(txt))

    def select_all(self, checked: bool, only_visible=True):
        for r in range(self.rowCount()):
            if only_visible and self.isRowHidden(r):
                continue
            self.set_row_checked(r, checked)

    def populate(self, devices):
        self.setSortingEnabled(False)
        self.setUpdatesEnabled(False)
        self.clearContents()

        n = len(devices or [])
        self.setRowCount(n)
        if n == 0:
            self.setUpdatesEnabled(True)
            self.setSortingEnabled(True)
            return

        self._apply_headers()

        for r, d in enumerate(devices):
            for c, key in enumerate(self.columns):
                if key == "選取":
                    cb = QCheckBox()
                    cb.setChecked(bool(d.get("選取", False)))
                    w = QWidget()
                    lay = QHBoxLayout(w)
                    lay.setContentsMargins(0, 0, 0, 0)
                    lay.addWidget(cb, alignment=Qt.AlignCenter)
                    self.setCellWidget(r, c, w)
                else:
                    val = str(d.get(key, ""))
                    self.setItem(r, c, QTableWidgetItem(val))

        # 每次填充後再觸發一次自動欄寬
        header = self.horizontalHeader()
        for c in range(self.columnCount()):
            header.setSectionResizeMode(c, QHeaderView.ResizeToContents)

        self.setUpdatesEnabled(True)
        self.setSortingEnabled(True)

    def get_checked_row_indexes(self):
        rows = []
        for r in range(self.rowCount()):
            cb = self._checkbox_at(r)
            if cb and cb.isChecked():
                rows.append(r)
        return rows

# =========================
# Worker
# =========================
class DeployWorker(QThread):
    one_done = Signal(dict)
    progress = Signal(int, int)
    all_done = Signal()

    def __init__(self, targets, public_src, private_codes, all_by_room, timeout=6, max_workers=DEPLOY_MAX_WORKERS, parent=None):
        super().__init__(parent)
        self.targets = targets
        self.public_src = public_src or []
        self.private_codes = private_codes or []
        self.all_by_room = all_by_room or {}
        self.timeout = timeout
        self.max_workers = max(1, int(max_workers))

    def _voip_entry_from_item(self, item):
        room = (item.get("房號") or "").strip()
        ip = (item.get("IP") or "").strip()
        name = str(item.get("名稱") or "").strip()
        url = f"sip:{room}@{ip}:5060"
        return {"type": "voip", "name": name, "url": url}

    def _public_fixed(self):
        out = []
        for d in self.public_src:
            t = str(d.get("type", "")).lower()
            if t == "rtsp":
                name = str(d.get("名稱") or d.get("name") or "").strip()
                url = str(d.get("url") or "").strip()
                if name and url:
                    out.append({"type": "rtsp", "name": name, "url": url})
            else:
                if d.get("房號") and d.get("IP"):
                    out.append(self._voip_entry_from_item(d))
        return out

    def _private_for_target(self, target_room: str):
        if not target_room or len(target_room) < 3:
            return [], []
        base = target_room[:-2] if len(target_room) >= 2 else target_room
        found_list, missing_list = [], []
        for code in self.private_codes:
            code = str(code).zfill(2)
            room = base + code
            item = self.all_by_room.get(room)
            if item and item.get("IP") and item.get("房號"):
                found_list.append(self._voip_entry_from_item(item))
            else:
                missing_list.append(room)
        return found_list, missing_list

    def _try_post(self, url, payload):
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        resp = requests.post(
            url,
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers=headers,
            timeout=self.timeout
        )
        return resp

    def _do_one(self, ip, room, payload, missing):
        url = f"http://{ip}:{DEFAULT_DEV_PORT}/monitor"
        clear_mode = not payload.get("private") and not payload.get("public")

        attempts = [payload]
        if clear_mode:
            attempts.append({"private": None, "public": None})
            attempts.append({})

        last_detail = ""
        last_code = None
        last_status = "失敗"

        for idx, pay in enumerate(attempts, 1):
            try:
                resp = self._try_post(url, pay)
                last_code = resp.status_code
                if last_code == 200:
                    last_status = "成功"
                    last_detail = "OK"
                    break
                elif last_code == 400:
                    last_detail = f"Bad Request（參數錯誤，嘗試#{idx}）"
                elif last_code == 500:
                    last_detail = f"Internal Error（伺服器錯誤，嘗試#{idx}）"
                else:
                    last_detail = f"HTTP {last_code}（嘗試#{idx}）"
            except requests.exceptions.ConnectTimeout:
                last_detail = f"連線逾時（嘗試#{idx}）"
            except requests.exceptions.ReadTimeout:
                last_detail = f"讀取逾時（嘗試#{idx}）"
            except requests.exceptions.ConnectionError as e:
                last_detail = f"連線錯誤：{e}（嘗試#{idx}）"
            except Exception as e:
                last_detail = f"例外：{e}（嘗試#{idx}）"

        if missing:
            miss_str = ",".join(missing)
            last_detail = (last_detail + f"；缺少私區來源: {miss_str}") if last_detail else f"缺少私區來源: {miss_str}"

        return {"ip": ip, "room": room, "status": last_status, "detail": last_detail, "code": last_code}

    def run(self):
        total = len(self.targets)
        done = 0
        public_fixed_global = self._public_fixed()

        tasks = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            for dev in self.targets:
                ip = (dev.get("IP") or "").strip()
                room = (dev.get("房號") or "").strip()
                private_list, missing = self._private_for_target(room)
                payload = {"private": private_list, "public": public_fixed_global}
                tasks.append(pool.submit(self._do_one, ip, room, payload, missing))

            for fut in as_completed(tasks):
                info = fut.result()
                self.one_done.emit(info)
                done += 1
                self.progress.emit(done, total)

        self.all_done.emit()

# =========================
# 密碼對話框（含避免雙重觸發扣次）
# =========================
class PasswordDialog(QDialog):
    def __init__(self, expected_password, parent=None):
        super().__init__(parent)
        self.expected = str(expected_password)
        self.tries_left = 3
        self._checking = False  # 防止重入/重複扣次
        self.setWindowTitle("密碼驗證")
        self.setModal(True)
        lay = QVBoxLayout(self)
        self.label = QLabel("請輸入密碼")
        lay.addWidget(self.label)
        self.edit = QLineEdit()
        self.edit.setEchoMode(QLineEdit.Password)
        self.edit.setPlaceholderText("請輸入密碼")
        self.edit.setToolTip("輸入啟動此工具的密碼")
        self.edit.setClearButtonEnabled(True)

        self.btn_ok = QPushButton("確定")
        self.btn_ok.setAutoDefault(True)
        self.btn_ok.setDefault(True)
        # Enter 統一視為按下「確定」按鈕
        self.edit.returnPressed.connect(self.btn_ok.click)

        lay.addWidget(self.edit)
        row = QHBoxLayout()
        self.btn_ok.clicked.connect(self.try_accept)
        self.btn_cancel = QPushButton("取消")
        self.btn_cancel.clicked.connect(self.reject)
        row.addStretch()
        row.addWidget(self.btn_ok)
        row.addWidget(self.btn_cancel)
        lay.addLayout(row)
        self.setFixedWidth(360)

    def try_accept(self):
        if self._checking:
            return
        self._checking = True
        try:
            text = self.edit.text()
            if text == self.expected:
                self.accept()
                return
            self.tries_left -= 1
            if self.tries_left <= 0:
                QMessageBox.critical(self, "密碼錯誤", "嘗試次數已用完，程式將關閉。")
                self.reject()
                return
            QMessageBox.warning(self, "密碼錯誤", f"密碼不正確，還可再嘗試 {self.tries_left} 次。")
            self.edit.clear()
            self.edit.setFocus()
        finally:
            self._checking = False

# =========================
# 主視窗
# =========================
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("監視列表下發工具V1.0_By Dean")
        self.resize(1320, 900)

        icon_path = get_icon_path()
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

        self.devices = []
        self.public_devices = []
        self.to_be_sent_devices = []
        self.original_order = []
        self.worker = None

        self._build_ui()
        self.setStatusBar(QStatusBar())
        self.statusBar().showMessage("就緒")

    @staticmethod
    def apply_clean_light_theme(app: QApplication):
        app.setStyle("Fusion")
        palette = QPalette()
        bg = QColor("#ffffff")
        base = QColor("#ffffff")
        alt = QColor("#fafafa")
        text = QColor("#111827")
        disabled = QColor("#9ca3af")
        btn = QColor("#f9fafb")
        highlight = QColor("#3ee749d9")
        htext = QColor("#ffffff")
        placeholder = QColor("#9ca3af")

        palette.setColor(QPalette.Window, bg)
        palette.setColor(QPalette.WindowText, text)
        palette.setColor(QPalette.Base, base)
        palette.setColor(QPalette.AlternateBase, alt)
        palette.setColor(QPalette.Text, text)
        palette.setColor(QPalette.Button, btn)
        palette.setColor(QPalette.ButtonText, text)
        palette.setColor(QPalette.Disabled, QPalette.Text, disabled)
        palette.setColor(QPalette.Highlight, highlight)
        palette.setColor(QPalette.HighlightedText, htext)
        palette.setColor(QPalette.PlaceholderText, placeholder)
        app.setPalette(palette)

        app.setStyleSheet("""
            QWidget { font-size: 14px; }
            QGroupBox {
                font-weight: 600;
                border: 1px solid #e5e7eb;
                border-radius: 8px;
                margin-top: 12px;
                background: #ffffff;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 4px 6px;
                background: #ffffff;
            }
            QPushButton {
                padding: 6px 12px;
                border: 1px solid #d1d5db;
                border-radius: 8px;
                background: #f9fafb;
            }
            QPushButton:hover { background: #f3f4f6; }
            QPushButton:pressed { background: #e5e7eb; }
            QLineEdit {
                padding: 6px 10px;
                border: 1px solid #d1d5db;
                border-radius: 6px;
                background: #ffffff;
            }
            QProgressBar {
                border: 1px solid #e5e7eb;
                border-radius: 6px;
                text-align: center;
                height: 20px;
            }
            QProgressBar::chunk { background-color: #3b82f6; }  /* 全域預設（藍色） */
            QStatusBar {
                background: #ffffff;
                border-top: 1px solid #e5e7eb;
            }
        """)

    def _unify_btn_height(self, *btns):
        for b in btns:
            if isinstance(b, QPushButton):
                b.setFixedHeight(BTN_H)

    # ---------- UI ----------
    def _build_ui(self):
        root = QWidget()
        root_lay = QVBoxLayout(root)
        root_lay.setContentsMargins(10, 10, 10, 10)
        root_lay.setSpacing(10)

        split = QSplitter(Qt.Horizontal)
        split.setChildrenCollapsible(False)

        # 左：全部設備
        left = QWidget()
        left_l = QVBoxLayout(left)
        left_l.setSpacing(8)

        gb_all = QGroupBox("全部設備")
        gb_all_l = QVBoxLayout(gb_all)
        gb_all_l.setSpacing(8)

        # ===== 工具列（Grid：搜尋｜手動IP｜按鈕區） =====
        tool = QWidget()
        grid = QGridLayout(tool)
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setHorizontalSpacing(8)
        grid.setVerticalSpacing(6)

        lbl_search = QLabel("搜尋")
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("欲搜尋的內容")
        self.search_edit.setClearButtonEnabled(True)
        self.search_edit.textChanged.connect(self.search_devices)

        lbl_addip = QLabel("手動新增 IP")
        self.manual_ip = QLineEdit()
        self.manual_ip.setPlaceholderText("例：192.168.200.4")
        self.manual_ip.setClearButtonEnabled(True)
        self.manual_ip.returnPressed.connect(self.add_manual_ip)

        btn_add = QPushButton("新增 IP")
        btn_add.clicked.connect(self.add_manual_ip)
        btn_import = QPushButton("匯入 Excel")
        btn_import.clicked.connect(self.import_excel)

        for w in (self.search_edit, self.manual_ip, btn_add, btn_import):
            if isinstance(w, (QLineEdit, QPushButton)):
                w.setFixedHeight(BTN_H)

        grid.addWidget(lbl_search,   0, 0)
        grid.addWidget(lbl_addip,    0, 1)
        grid.addWidget(QWidget(),    0, 2)  # 佔位
        grid.addWidget(self.search_edit, 1, 0)
        grid.addWidget(self.manual_ip,  1, 1)

        btn_bar = QWidget()
        h = QHBoxLayout(btn_bar)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(8)
        h.addWidget(btn_add)
        h.addWidget(btn_import)
        h.addStretch()
        grid.addWidget(btn_bar, 1, 2)

        grid.setColumnStretch(0, 45)
        grid.setColumnStretch(1, 45)
        grid.setColumnStretch(2, 10)

        gb_all_l.addWidget(tool)

        self.table = DeviceTable(columns=FIXED_COLUMNS)
        gb_all_l.addWidget(self.table)

        ops = QHBoxLayout()
        btn_pub = QPushButton("加入 → 公區")
        btn_pub.clicked.connect(self.add_to_public)
        btn_send = QPushButton("加入 → 待下發")
        btn_send.clicked.connect(self.add_to_send)
        ops.addWidget(btn_pub)
        ops.addWidget(btn_send)
        ops.addStretch()
        btn_all = QPushButton("全選")
        btn_all.clicked.connect(lambda: self.table.select_all(True, True))
        btn_none = QPushButton("取消全選")
        btn_none.clicked.connect(lambda: self.table.select_all(False, True))
        ops.addWidget(btn_all)
        ops.addWidget(btn_none)
        self._unify_btn_height(btn_pub, btn_send, btn_all, btn_none)
        gb_all_l.addLayout(ops)

        left_l.addWidget(gb_all)
        split.addWidget(left)

        # 右：上下分割
        right = QSplitter(Qt.Vertical)
        right.setChildrenCollapsible(False)

        # 右上：待下發
        top_w = QWidget()
        top_l = QVBoxLayout(top_w); top_l.setSpacing(8)
        gb_send = QGroupBox("待下發設備（僅室內機 / 管理台）")
        gb_send_l = QVBoxLayout(gb_send)
        self.send_table = DeviceTable(columns=FIXED_COLUMNS)
        self.send_table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        gb_send_l.addWidget(self.send_table)
        send_ops = QHBoxLayout()
        btn_del_send = QPushButton("刪除選取"); btn_del_send.clicked.connect(self.delete_selected_send)
        btn_send_all = QPushButton("全選"); btn_send_all.clicked.connect(lambda: self.send_table.select_all(True, True))
        btn_send_none = QPushButton("取消全選"); btn_send_none.clicked.connect(lambda: self.send_table.select_all(False, True))
        send_ops.addWidget(btn_del_send); send_ops.addStretch(); send_ops.addWidget(btn_send_all); send_ops.addWidget(btn_send_none)
        self._unify_btn_height(btn_del_send, btn_send_all, btn_send_none)
        gb_send_l.addLayout(send_ops)
        top_l.addWidget(gb_send)
        right.addWidget(top_w)

        # 右中：公區 + RTSP
        mid_w = QWidget()
        mid_l = QVBoxLayout(mid_w); mid_l.setSpacing(8)
        gb_pub = QGroupBox("公區設備（禁止加入室內機/小門口機/管理台）")
        gb_pub_l = QVBoxLayout(gb_pub)
        self.public_table = DeviceTable(columns=FIXED_COLUMNS)
        self.public_table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        gb_pub_l.addWidget(self.public_table)

        pub_ops = QHBoxLayout()
        btn_del_pub = QPushButton("刪除選取"); btn_del_pub.clicked.connect(self.delete_selected_public)
        btn_pub_all = QPushButton("全選"); btn_pub_all.clicked.connect(lambda: self.public_table.select_all(True, True))
        btn_pub_none = QPushButton("取消全選"); btn_pub_none.clicked.connect(lambda: self.public_table.select_all(False, True))
        pub_ops.addWidget(btn_del_pub); pub_ops.addStretch(); pub_ops.addWidget(btn_pub_all); pub_ops.addWidget(btn_pub_none)
        self._unify_btn_height(btn_del_pub, btn_pub_all, btn_pub_none)
        gb_pub_l.addLayout(pub_ops)

        rtsp_row = QHBoxLayout()
        lbl_rtsp = QLabel("手動新增設備")
        self.rtsp_name = QLineEdit(); self.rtsp_name.setPlaceholderText("設備名稱"); self.rtsp_name.setClearButtonEnabled(True)
        self.rtsp_url  = QLineEdit(); self.rtsp_url.setPlaceholderText("RTSP URL（例：rtsp://192.168.1.50:554/stream1）"); self.rtsp_url.setClearButtonEnabled(True)
        btn_add_rtsp = QPushButton("加入公區 (RTSP)"); btn_add_rtsp.clicked.connect(self.add_public_rtsp)
        for w in (self.rtsp_name, self.rtsp_url, btn_add_rtsp):
            w.setFixedHeight(BTN_H)
        rtsp_row.addWidget(lbl_rtsp)
        rtsp_row.addWidget(self.rtsp_name)
        rtsp_row.addWidget(self.rtsp_url, 2)
        rtsp_row.addWidget(btn_add_rtsp)
        gb_pub_l.addLayout(rtsp_row)

        mid_l.addWidget(gb_pub)
        right.addWidget(mid_w)

        # 右下：私區 + 下發/匯出
        bottom_w = QWidget()
        bottom_l = QVBoxLayout(bottom_w); bottom_l.setSpacing(8)
        gb_priv = QGroupBox("私區小門口機（可多選 02–10或留空）")
        gb_priv_l = QVBoxLayout(gb_priv)

        priv_line = QHBoxLayout()

        # 左側：碼表
        left_priv = QVBoxLayout()
        left_priv.addWidget(QLabel("小門口機設備號"))
        self.private_list = QListWidget()
        self.private_list.setSelectionMode(QAbstractItemView.MultiSelection)
        for i in range(2, 11):
            self.private_list.addItem(QListWidgetItem(f"{i:02d}"))
        self.private_list.setMaximumHeight(130)
        self.private_list.setMaximumWidth(200)
        self.private_list.itemSelectionChanged.connect(self._update_private_selected_text)
        left_priv.addWidget(self.private_list)
        priv_line.addLayout(left_priv)

        # 右側
        right_col = QVBoxLayout(); right_col.setSpacing(10)

        sel_line = QHBoxLayout()
        sel_line.addWidget(QLabel("目前選擇："))
        self.private_selected_text = QLineEdit()
        self.private_selected_text.setReadOnly(True)
        self.private_selected_text.setPlaceholderText("（尚未選擇）")
        sel_line.addWidget(self.private_selected_text, 1)
        right_col.addLayout(sel_line)

        btn_row = QHBoxLayout()
        self.deploy_btn = QPushButton("下發監視列表")
        self.deploy_btn.clicked.connect(self.deploy_monitor_list)
        self.deploy_btn.setMinimumHeight(DEPLOY_BTN_H)
        self.deploy_btn.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        self.export_btn = QPushButton("匯出執行結果")
        self.export_btn.clicked.connect(self.export_results)
        self.export_btn.setMinimumHeight(DEPLOY_BTN_H)
        self.export_btn.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        btn_row.addWidget(self.deploy_btn)
        btn_row.addWidget(self.export_btn)
        right_col.addLayout(btn_row)

        pr_line = QHBoxLayout()
        pr_line.addWidget(QLabel("進度"))
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)

        # ==== 單一進度條：綠色漸層樣式（只影響 self.progress）====
        self.progress.setStyleSheet("""
            QProgressBar {
                border: 1px solid #e5e7eb;
                border-radius: 6px;
                text-align: center;
                height: 20px;
                background-color: #f0fdf4; /* 未填滿底色：綠系淺色 */
            }
            QProgressBar::chunk {
                border-radius: 6px;
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                            stop:0 #86efac,   /* green-300 */
                                            stop:1 #22c55e);  /* green-500 */
            }
        """)
        # =====================================================

        pr_line.addWidget(self.progress, 1)
        right_col.addLayout(pr_line)

        priv_line.addLayout(right_col, 1)
        gb_priv_l.addLayout(priv_line)
        bottom_l.addWidget(gb_priv)
        right.addWidget(bottom_w)

        split.addWidget(right)
        split.setStretchFactor(0, 5)
        split.setStretchFactor(1, 6)
        root_lay.addWidget(split, 1)

        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setFrameShadow(QFrame.Sunken)
        root_lay.addWidget(sep)

        gb_res = QGroupBox("下發結果")
        gb_res_l = QVBoxLayout(gb_res)
        self.result_table = QTableWidget(0, 4)
        self.result_table.setHorizontalHeaderLabels(["目標IP", "房號", "狀態", "詳細"])
        rh = self.result_table.horizontalHeader()
        for c in range(4):
            rh.setSectionResizeMode(c, QHeaderView.ResizeToContents)
        rh.setStretchLastSection(True)
        self.result_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.result_table.setAlternatingRowColors(True)
        self.result_table.verticalHeader().setVisible(False)
        self.result_table.setStyleSheet("""
            QTableWidget {
                gridline-color: #e5e7eb;
                selection-background-color: #d1fae5;
                selection-color: #065f46;
                background-color: white;
                border: 1px solid #e5e7eb;
                border-radius: 6px;
            }
            QHeaderView::section {
                background: #f3f4f6;
                padding: 8px;
                border: 0px solid #e5e7eb;
                border-right: 1px solid #e5e7eb;
                font-weight: 600;
            }
        """)
        gb_res_l.addWidget(self.result_table)
        root_lay.addWidget(gb_res, 1)

        self.setCentralWidget(root)

    # ---------- 資料操作 ----------
    def import_excel(self):
        path, _ = QFileDialog.getOpenFileName(self, "匯入 Excel", "", "Excel Files (*.xls *.xlsx)")
        if not path:
            return
        try:
            devices = load_excel_and_parse_devices(path)
            self.devices = devices.copy()
            self.original_order = devices.copy()
            self.table.populate(self.devices)
            self.statusBar().showMessage(f"匯入成功，共 {len(devices)} 筆")
            self.search_devices()
        except Exception as e:
            self.statusBar().showMessage(f"匯入失敗: {e}")

    def add_manual_ip(self):
        ip = self.manual_ip.text().strip()
        if not is_valid_ip(ip):
            QMessageBox.warning(self, "格式錯誤", "請輸入正確的 IPv4 位址，例如 192.168.200.4")
            return
        rec = {k: "" for k in FIXED_COLUMNS}
        rec["IP"] = ip
        rec["選取"] = False
        rec["_manual"] = True
        for d in (self.devices + self.public_devices + self.to_be_sent_devices):
            if d.get("IP", "") == ip and ip != "":
                QMessageBox.information(self, "已存在", "此 IP 已在清單中")
                return
        self.devices.append(rec)
        self.original_order.append(rec)
        self.table.populate(self.devices)
        self.manual_ip.clear()
        self.statusBar().showMessage("手動新增成功")
        self.search_devices()

    def add_public_rtsp(self):
        name = self.rtsp_name.text().strip()
        url = self.rtsp_url.text().strip()
        if not name:
            QMessageBox.warning(self, "缺少名稱", "請輸入設備名稱")
            return
        if not url.lower().startswith("rtsp://"):
            QMessageBox.warning(self, "URL 格式錯誤", "RTSP URL 需以 rtsp:// 開頭")
            return
        item = {
            "選取": False,
            "設備類型": "RTSP",
            "名稱": name,
            "IP": "",
            "房號": "",
            "type": "rtsp",
            "url": url
        }
        self.public_devices.append(item)
        self.public_table.populate(self.public_devices)
        self.rtsp_name.clear()
        self.rtsp_url.clear()
        self.statusBar().showMessage("已新增 RTSP 公區設備")

    def search_devices(self):
        self.table.filter(self.search_edit.text())

    def clear_all(self):
        self.devices = []
        self.public_devices = []
        self.to_be_sent_devices = []
        self.table.populate([])
        self.public_table.populate([])
        self.send_table.populate([])
        self.original_order = []
        self.progress.setValue(0)
        self.result_table.setRowCount(0)
        self.statusBar().showMessage("已清除所有資料")

    @staticmethod
    def _unique_extend(dst_list, add_list):
        added = set(d.get("IP", "") for d in dst_list if d.get("IP"))
        new_items = []
        for d in add_list:
            ip = d.get("IP", "")
            if ip and ip in added:
                continue
            new_items.append(d)
            if ip:
                added.add(ip)
        dst_list.extend(new_items)
        return new_items

    def _find_in_list_by_ip(self, ip, data_list):
        for d in data_list:
            if d.get("IP", "") == ip:
                return d
        return None

    def _take_selected_from_main(self):
        picked = []
        basic = self.table.get_selected_devices()
        if not basic:
            QMessageBox.information(self, "未選擇", "請至少勾選一個設備")
            return []
        for b in basic:
            ip = b.get("IP", "")
            src = self._find_in_list_by_ip(ip, self.devices)
            picked.append(src.copy() if src else b)
        return picked

    def _remove_from_main_by_ips(self, ips):
        self.devices = [d for d in self.devices if d.get("IP", "") not in ips]
        self.table.populate(self.devices)

    def sort_by_original_order(self, device_list):
        ip_to_dev = {d.get('IP', ''): d for d in device_list}
        sorted_list = []
        for od in self.original_order:
            ip = od.get('IP', '')
            if ip in ip_to_dev:
                sorted_list.append(ip_to_dev[ip])
        for ip, d in ip_to_dev.items():
            if not any(od.get('IP', '') == ip for od in self.original_order):
                sorted_list.append(d)
        return sorted_list

    def _allowed_for_send(self, rec):
        if rec.get("_manual"):
            return True
        t = str(rec.get("設備類型") or "")
        return ("室內" in t) or ("室內機" in t) or ("管理台" in t) or ("管理臺" in t)

    def _allowed_for_public(self, rec):
        t = str(rec.get("設備類型") or "")
        forbid = ("室內" in t) or ("室內機" in t) or ("小門口" in t) or ("小門口機" in t) or ("管理台" in t) or ("管理臺" in t)
        return not forbid

    def add_to_public(self):
        sel = self._take_selected_from_main()
        if not sel:
            return
        allowed = [d for d in sel if self._allowed_for_public(d)]
        blocked = [d for d in sel if d not in allowed]
        if blocked:
            bips = ", ".join([d.get("名稱","") or "(無IP)" for d in blocked][:5])
            QMessageBox.information(self, "選擇設備類型錯誤",
                                    f"以下設備類型為『室內機/小門口機/管理台』，不可加入公區：\n{bips}"
                                    + ("\n…等" if len(blocked) > 5 else ""))
        if not allowed:
            return
        new_items = self._unique_extend(self.public_devices, allowed)
        if not new_items:
            QMessageBox.information(self, "重複", "勾選設備都已在公區清單中"); return
        self.public_table.populate(self.public_devices)
        self._remove_from_main_by_ips([d.get("IP","") for d in new_items if d.get("IP")])
        self.statusBar().showMessage(f"已加入 {len(new_items)} 筆到公區清單")
        self.search_edit.clear()
        self.table.filter("")

    def add_to_send(self):
        sel = self._take_selected_from_main()
        if not sel:
            return
        allowed = [d for d in sel if self._allowed_for_send(d)]
        blocked = [d for d in sel if d not in allowed]
        if blocked:
            bips = ", ".join([d.get("名稱","") or "(無IP)" for d in blocked][:5])
            QMessageBox.information(self, "選擇設備類型錯誤",
                                    f"以下設備類型非『室內機/管理台』且非手動建立，不可下發：\n{bips}"
                                    + ("\n…等" if len(blocked) > 5 else ""))
        if not allowed:
            return
        new_items = self._unique_extend(self.to_be_sent_devices, allowed)
        if not new_items:
            QMessageBox.information(self, "重複", "勾選設備都已在待下發清單中"); return
        self.send_table.populate(self.to_be_sent_devices)
        self._remove_from_main_by_ips([d.get("IP","") for d in new_items if d.get("IP")])
        self.statusBar().showMessage(f"已加入 {len(new_items)} 筆到待下發")
        self.search_edit.clear()
        self.table.filter("")

    def _delete_from_table(self, data_list, table):
        rows = table.get_checked_row_indexes()
        if not rows:
            rows = sorted(set(i.row() for i in table.selectedIndexes()))
        rows = sorted(set(rows), reverse=True)
        if not rows:
            QMessageBox.information(self, "未選擇", "請在清單的『選取』欄勾選要刪除的設備")
            return

        restored = []
        for r in rows:
            if r < 0 or r >= len(data_list):
                continue
            d = data_list[r]
            if d.get("IP"):
                restored.append(d)
            del data_list[r]
            table.removeRow(r)

        main_ips = set(d.get("IP","") for d in self.devices)
        for d in restored:
            if d.get("IP","") not in main_ips:
                self.devices.append(d)

        self.devices = self.sort_by_original_order(self.devices)
        self.table.populate(self.devices)
        self.public_table.populate(self.public_devices)
        self.send_table.populate(self.to_be_sent_devices)
        self.statusBar().showMessage("已刪除並回到主清單")

    def delete_selected_public(self):
        self._delete_from_table(self.public_devices, self.public_table)

    def delete_selected_send(self):
        self._delete_from_table(self.to_be_sent_devices, self.send_table)

    def _update_private_selected_text(self):
        codes = [it.text() for it in self.private_list.selectedItems()]
        self.private_selected_text.setText(", ".join(sorted(codes)) if codes else "")

    # ---------- 下發 ----------
    def _clear_results(self):
        self.result_table.setRowCount(0); self.progress.setValue(0)

    def _append_result(self, ip, room, status, detail):
        r = self.result_table.rowCount()
        self.result_table.insertRow(r)
        self.result_table.setItem(r, 0, QTableWidgetItem(ip))
        self.result_table.setItem(r, 1, QTableWidgetItem(room))
        self.result_table.setItem(r, 2, QTableWidgetItem(status))
        self.result_table.setItem(r, 3, QTableWidgetItem(detail))
        self.result_table.scrollToBottom()

    def _build_all_by_room(self):
        by_room = {}
        for d in self.original_order:
            room = (d.get("房號") or "").strip()
            ip = (d.get("IP") or "").strip()
            if room and ip:
                by_room[room] = d
        return by_room

    def _preview_public_and_private(self):
        names = []
        for d in self.public_devices:
            name = str(d.get("名稱") or d.get("name") or "").strip()
            if name:
                names.append(name)
        pub_text = "\n".join(names) if names else "(空)"

        private_codes = [it.text() for it in self.private_list.selectedItems()]
        priv_text = ", ".join(sorted(private_codes)) if private_codes else "(空)"

        targets = len(self.to_be_sent_devices)
        msg = f"即將下發監視列表\n\n目標台數：{targets}\n\n【公區】\n{pub_text}\n\n【私區】\n{priv_text}\n\n是否繼續？"
        return msg

    def _on_worker_one_done(self, info: dict):
        self._append_result(info.get("ip",""), info.get("room",""), info.get("status",""), info.get("detail",""))

    def _on_worker_progress(self, done: int, total: int):
        self.progress.setValue(int(done * 100 / max(total, 1)))

    def _on_worker_all_done(self):
        self.deploy_btn.setEnabled(True)
        self.statusBar().showMessage("下發完成。")

    def deploy_monitor_list(self):
        if not self.to_be_sent_devices:
            QMessageBox.information(self, "無目標", "請先將設備加入『待下發』清單。")
            return

        preview = self._preview_public_and_private()

        # === 手動中文對話框：確定(&Y) / 取消(&N)，同時支援快捷鍵 Y / N ===
        msg = QMessageBox(self)
        msg.setWindowTitle("下發確認")
        msg.setText(preview)
        msg.setIcon(QMessageBox.Question)
        btn_yes = msg.addButton("確定(&Y)", QMessageBox.AcceptRole)
        btn_no  = msg.addButton("取消(&N)", QMessageBox.RejectRole)
        btn_yes.setShortcut(Qt.Key_Y)
        btn_no.setShortcut(Qt.Key_N)
        msg.setDefaultButton(btn_no)
        msg.exec()

        if msg.clickedButton() is not btn_yes:
            return

        private_codes = [it.text() for it in self.private_list.selectedItems()]

        self._clear_results()
        self.deploy_btn.setEnabled(False)
        self.statusBar().showMessage("開始下發……")

        all_by_room = self._build_all_by_room()

        self.worker = DeployWorker(
            targets=self.to_be_sent_devices,
            public_src=self.public_devices,
            private_codes=private_codes,
            all_by_room=all_by_room,
            timeout=6,
            max_workers=DEPLOY_MAX_WORKERS
        )
        self.worker.one_done.connect(self._on_worker_one_done)
        self.worker.progress.connect(self._on_worker_progress)
        self.worker.all_done.connect(self._on_worker_all_done)
        self.worker.start()

    # ---------- 匯出執行結果 ----------
    def export_results(self):
        rows = self.result_table.rowCount()
        if rows == 0:
            QMessageBox.information(self, "無資料", "目前沒有可匯出的執行結果。")
            return
        default_name = f"執行結果_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        path, _ = QFileDialog.getSaveFileName(self, "匯出執行結果", default_name, "CSV Files (*.csv)")
        if not path:
            return
        headers = [self.result_table.horizontalHeaderItem(i).text() for i in range(self.result_table.columnCount())]
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            for r in range(rows):
                row = []
                for c in range(self.result_table.columnCount()):
                    it = self.result_table.item(r, c)
                    row.append(it.text() if it else "")
                writer.writerow(row)
        self.statusBar().showMessage(f"已匯出：{os.path.basename(path)}")

# =========================
# 進入點
# =========================
if __name__ == "__main__":
    import warnings
    warnings.filterwarnings("ignore")

    app = QApplication(sys.argv)
    MainWindow.apply_clean_light_theme(app)

    icon = get_icon_path()
    if os.path.exists(icon):
        app.setWindowIcon(QIcon(icon))

    dlg = PasswordDialog(APP_PASSWORD)
    if dlg.exec() != QDialog.Accepted:
        sys.exit(0)

    win = MainWindow()
    # 預設以最大化開啟主視窗
    win.showMaximized()
    sys.exit(app.exec())
