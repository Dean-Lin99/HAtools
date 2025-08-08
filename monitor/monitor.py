import sys
import os
import re
import json
import ipaddress
import pandas as pd
import requests

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QFileDialog, QLineEdit, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView, QCheckBox,
    QMessageBox, QAbstractItemView, QProgressBar, QListWidget, QListWidgetItem
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QIcon

DEFAULT_DEV_PORT = 3377  # 固定裝置 Port

# =========================
# 公用工具
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
            parts.append(s)  # 保留前導 0
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
            "名稱": name,         # 名稱：完全使用匯入後的名稱，不做加工
            "IP": ip,
            "房號": room_no,
            "選取": False
        })

    if not devices:
        return None

    # 去重 IP
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

    # 備援：只抓 IP
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
                    device_list.append({"選取": False, "IP": ip})
                    ip_set.add(ip)
    return device_list

# =========================
# UI：表格（好點的勾選）
# =========================
class DeviceTable(QTableWidget):
    def __init__(self, parent=None):
        super().__init__(0, 0, parent)
        self.data_keys = []
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.verticalHeader().setVisible(False)
        self.setAlternatingRowColors(True)
        self.setStyleSheet("""
            QCheckBox::indicator { width: 22px; height: 22px; }
            QTableWidget::item { padding: 6px; }
        """)
        self.cellClicked.connect(self.on_cell_clicked)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)

    def set_columns_and_data(self, devices):
        self.setRowCount(0)
        if not devices:
            self.setColumnCount(0)
            self.setHorizontalHeaderLabels([])
            self.data_keys = []
            return
        keys = list(devices[0].keys())
        for d in devices:
            for k in d.keys():
                if k not in keys:
                    keys.append(k)
        self.data_keys = keys
        self.setColumnCount(len(keys))
        self.setHorizontalHeaderLabels(keys)

    def _checkbox_at(self, row):
        if not self.data_keys or self.data_keys[0] != "選取":
            return None
        w = self.cellWidget(row, 0)
        return w.findChild(QCheckBox) if w else None

    def set_row_checked(self, row, checked):
        cb = self._checkbox_at(row)
        if cb:
            cb.setChecked(checked)

    def on_cell_clicked(self, row, col):
        if self.data_keys and self.data_keys[0] == "選取" and col != 0:
            cb = self._checkbox_at(row)
            if cb:
                cb.setChecked(not cb.isChecked())

    def keyPressEvent(self, e):
        if e.key() == Qt.Key_Space and self.data_keys and self.data_keys[0] == "選取":
            rows = sorted(set(i.row() for i in self.selectedIndexes()))
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
        if self.data_keys and self.data_keys[0] == "選取":
            res = []
            for r in range(self.rowCount()):
                cb = self._checkbox_at(r)
                if cb and cb.isChecked():
                    item = {k: self.item(r, i).text() if self.item(r, i) else "" for i, k in enumerate(self.data_keys) if k != "選取"}
                    res.append(item)
            return res
        else:
            res = []
            for r in range(self.rowCount()):
                item = {k: self.item(r, i).text() if self.item(r, i) else "" for i, k in enumerate(self.data_keys)}
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
        if not self.data_keys or self.data_keys[0] != "選取":
            return
        for r in range(self.rowCount()):
            if only_visible and self.isRowHidden(r):
                continue
            self.set_row_checked(r, checked)

    def populate(self, devices):
        self.set_columns_and_data(devices)
        if not devices:
            return
        for d in devices:
            r = self.rowCount()
            self.insertRow(r)
            for c, key in enumerate(self.data_keys):
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

# =========================
# 下發 Worker（QThread）
# =========================
class DeployWorker(QThread):
    one_done = pyqtSignal(dict)    # {'ip','room','status','detail','code'}
    progress = pyqtSignal(int, int)  # done,total
    all_done = pyqtSignal()

    def __init__(self, targets, public_src, private_codes, all_by_room, timeout=6, parent=None):
        super().__init__(parent)
        self.targets = targets                 # 目標室內機清單（每台要 POST）
        self.public_src = public_src or []     # 公區來源（直接用其房號/IP/名稱）
        self.private_codes = private_codes or []  # ['02','03',...]
        self.all_by_room = all_by_room or {}   # {房號: 設備dict}
        self.timeout = timeout

    def _voip_entry_from_item(self, item):
        # 名稱必須使用匯入的名稱，不做任何加工
        room = (item.get("房號") or "").strip()
        ip = (item.get("IP") or "").strip()
        name = str(item.get("名稱") or "").strip()
        url = f"sip:{room}@{ip}:5060"
        return {"type": "voip", "name": name, "url": url}

    def _private_for_target(self, target_room: str):
        """依 target 房號底碼 + private_codes 去 all_by_room 找私區設備"""
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

    def _public_fixed(self):
        # 公區名稱嚴格使用匯入「公區來源清單」內的名稱，不做任何 fallback
        return [self._voip_entry_from_item(d) for d in self.public_src if d.get("房號") and d.get("IP")]

    def run(self):
        total = len(self.targets)
        done = 0
        headers = {"Content-Type": "application/json"}
        public_fixed_global = self._public_fixed()  # 公區是固定清單（可為空）

        for dev in self.targets:
            ip = (dev.get("IP") or "").strip()
            room = (dev.get("房號") or "").strip()

            private_list, missing = self._private_for_target(room)  # 依每台目標計算（可為空）
            payload = {"private": private_list, "public": public_fixed_global}

            url = f"http://{ip}:{DEFAULT_DEV_PORT}/monitor"
            status = "失敗"
            detail = ""
            code = None
            try:
                resp = requests.post(
                    url,
                    data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                    headers=headers,
                    timeout=self.timeout
                )
                code = resp.status_code
                if code == 200:
                    status = "成功"
                    if not private_list and not public_fixed_global:
                        detail = "OK（送出空監視列表：已清空設備設定）"
                    else:
                        detail = "OK"
                elif code == 400:
                    detail = "Bad Request（參數錯誤）"
                elif code == 500:
                    detail = "Internal Error（伺服器錯誤）"
                else:
                    detail = f"HTTP {code}"
            except requests.exceptions.ConnectTimeout:
                detail = "連線逾時"
            except requests.exceptions.ReadTimeout:
                detail = "讀取逾時"
            except requests.exceptions.ConnectionError as e:
                detail = f"連線錯誤：{e}"
            except Exception as e:
                detail = f"例外：{e}"

            if missing:
                miss_str = ",".join(missing)
                detail = (detail + f"；缺少私區來源: {miss_str}") if detail else f"缺少私區來源: {miss_str}"

            self.one_done.emit({"ip": ip, "room": room, "status": status, "detail": detail, "code": code})
            done += 1
            self.progress.emit(done, total)

        self.all_done.emit()

# =========================
# 主視窗
# =========================
class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("監視列表下發工具_V1.0_By Dean")
        self.resize(1180, 1020)
        icon_path = get_icon_path()
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

        self.devices = []             # 主清單（匯入 + 手動）
        self.public_devices = []      # 公區來源（手動從主清單加入）
        self.to_be_sent_devices = []  # 目標室內機（手動從主清單加入）
        self.original_order = []      # 原始排序（僅使用匯入後的原始資料，確保名稱以匯入為準）
        self.worker = None

        self.init_ui()

    # ---------- UI ----------
    def init_ui(self):
        layout = QVBoxLayout(self)

        # 匯入 & 基本操作
        top = QHBoxLayout()
        self.import_btn = QPushButton("匯入Excel"); self.import_btn.clicked.connect(self.import_excel); top.addWidget(self.import_btn)
        top.addWidget(QLabel("手動輸入IP:"))
        self.manual_ip = QLineEdit(); self.manual_ip.setPlaceholderText("192.168.1.10"); self.manual_ip.returnPressed.connect(self.add_manual_ip); top.addWidget(self.manual_ip)
        btn_add = QPushButton("新增"); btn_add.clicked.connect(self.add_manual_ip); top.addWidget(btn_add)
        top.addStretch()
        btn_all = QPushButton("全選"); btn_all.clicked.connect(lambda: self.table.select_all(True, True)); top.addWidget(btn_all)
        btn_none = QPushButton("全不選"); btn_none.clicked.connect(lambda: self.table.select_all(False, True)); top.addWidget(btn_none)
        btn_clear = QPushButton("清除資料"); btn_clear.clicked.connect(self.clear_all); top.addWidget(btn_clear)
        layout.addLayout(top)

        # 搜尋
        prm = QHBoxLayout()
        prm.addWidget(QLabel("搜尋:"))
        self.search_edit = QLineEdit(); self.search_edit.textChanged.connect(self.search_devices); prm.addWidget(self.search_edit)
        layout.addLayout(prm)

        # 主清單
        layout.addWidget(QLabel("全部設備清單（點整列切換勾選；可框選多列後按空白鍵批次切換）"))
        self.table = DeviceTable()
        layout.addWidget(self.table)

        # 加入公區 / 加入待下發
        ops = QHBoxLayout()
        btn_pub = QPushButton("加入公區"); btn_pub.clicked.connect(self.add_to_public); ops.addWidget(btn_pub)
        btn_send = QPushButton("加入待下發"); btn_send.clicked.connect(self.add_to_send); ops.addWidget(btn_send)
        ops.addStretch()
        layout.addLayout(ops)

        # 公區來源
        layout.addWidget(QLabel("公區來源清單（可刪除，刪除後回主清單並恢復原排序）"))
        self.public_table = DeviceTable()
        self.public_table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        layout.addWidget(self.public_table)
        pub_ops = QHBoxLayout()
        btn_del_pub = QPushButton("刪除選取公區來源"); btn_del_pub.clicked.connect(self.delete_selected_public); pub_ops.addWidget(btn_del_pub)
        pub_ops.addStretch(); layout.addLayout(pub_ops)

        # 待下發目標
        layout.addWidget(QLabel("待下發目標清單（可刪除，刪除後回主清單並恢復原排序）"))
        self.send_table = DeviceTable()
        self.send_table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        layout.addWidget(self.send_table)
        send_ops = QHBoxLayout()
        btn_del_send = QPushButton("刪除選取目標"); btn_del_send.clicked.connect(self.delete_selected_send); send_ops.addWidget(btn_del_send)
        send_ops.addStretch(); layout.addLayout(send_ops)

        # 私區 02–10 選擇（可為空）
        priv_h = QHBoxLayout()
        priv_h.addWidget(QLabel("私區小門口機(可多選 02–10；可留空)："))
        self.private_list = QListWidget()
        self.private_list.setSelectionMode(QAbstractItemView.MultiSelection)
        for i in range(2, 11):
            self.private_list.addItem(QListWidgetItem(f"{i:02d}"))
        self.private_list.setMaximumHeight(80)
        self.private_list.setMaximumWidth(150)
        priv_h.addWidget(self.private_list)
        priv_h.addStretch()
        self.deploy_btn = QPushButton("下發監視列表")
        self.deploy_btn.clicked.connect(self.deploy_monitor_list)
        priv_h.addWidget(self.deploy_btn)
        layout.addLayout(priv_h)

        # 進度 + 結果
        pr = QHBoxLayout()
        pr.addWidget(QLabel("進度：")); self.progress = QProgressBar(); self.progress.setRange(0, 100); pr.addWidget(self.progress)
        layout.addLayout(pr)

        layout.addWidget(QLabel("下發結果"))
        self.result_table = QTableWidget(0, 4)
        self.result_table.setHorizontalHeaderLabels(["目標IP", "房號", "狀態", "詳細"])
        self.result_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.result_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        layout.addWidget(self.result_table)

        self.status_label = QLabel(); self.status_label.setWordWrap(True); layout.addWidget(self.status_label)

    # ---------- 資料操作 ----------
    def import_excel(self):
        path, _ = QFileDialog.getOpenFileName(self, "匯入 Excel", "", "Excel Files (*.xls *.xlsx)")
        if not path:
            return
        try:
            devices = load_excel_and_parse_devices(path)
            self.devices = devices.copy()
            self.original_order = devices.copy()   # 記錄原排序與原始名稱
            self.table.populate(self.devices)
            self.status_label.setText(f"匯入成功，共 {len(devices)} 筆")
            self.search_devices()
        except Exception as e:
            self.status_label.setText(f"匯入失敗: {e}")

    def add_manual_ip(self):
        ip = self.manual_ip.text().strip()
        if not is_valid_ip(ip):
            QMessageBox.warning(self, "格式錯誤", "請輸入正確的IPv4位址")
            return
        keys = self.table.data_keys or ["選取", "設備類型", "名稱", "IP", "房號"]
        rec = {k: "" for k in keys}
        rec["IP"] = ip; rec["選取"] = False
        for d in (self.devices + self.public_devices + self.to_be_sent_devices):
            if d.get("IP", "") == ip:
                QMessageBox.information(self, "已存在", "此IP已在清單中")
                return
        self.devices.append(rec)
        self.original_order.append(rec)  # 手動新增也追進原排序尾巴
        self.table.populate(self.devices)
        self.manual_ip.clear()
        self.status_label.setText("手動新增成功")
        self.search_devices()

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
        self.status_label.setText("已清除所有資料")

    @staticmethod
    def _unique_extend(dst_list, add_list):
        added = set(d.get("IP", "") for d in dst_list)
        new_items = [d for d in add_list if d.get("IP", "") not in added]
        dst_list.extend(new_items)
        return new_items

    def _take_selected_from_main(self):
        sel = self.table.get_selected_devices()
        if not sel:
            QMessageBox.information(self, "未選擇", "請至少勾選一個設備")
            return []
        return sel

    def _remove_from_main_by_ips(self, ips):
        self.devices = [d for d in self.devices if d.get("IP", "") not in ips]
        self.table.populate(self.devices)

    def sort_by_original_order(self, device_list):
        """依 original_order 的 IP 順序排序；不存在 original_order 的放最後"""
        ip_to_dev = {d.get('IP', ''): d for d in device_list}
        sorted_list = []
        for od in self.original_order:
            ip = od.get('IP', '')
            if ip in ip_to_dev:
                sorted_list.append(ip_to_dev[ip])
        # 附加新進、原序中沒有的
        for ip, d in ip_to_dev.items():
            if not any(od.get('IP', '') == ip for od in self.original_order):
                sorted_list.append(d)
        return sorted_list

    # ---- 加入各清單 ----
    def add_to_public(self):
        sel = self._take_selected_from_main()
        if not sel: return
        new_items = self._unique_extend(self.public_devices, sel)
        if not new_items:
            QMessageBox.information(self, "重複", "勾選設備都已在公區清單中"); return
        self.public_table.populate(self.public_devices)
        self._remove_from_main_by_ips([d.get("IP","") for d in new_items])
        self.status_label.setText(f"已加入 {len(new_items)} 筆到公區來源")

    def add_to_send(self):
        sel = self._take_selected_from_main()
        if not sel: return
        new_items = self._unique_extend(self.to_be_sent_devices, sel)
        if not new_items:
            QMessageBox.information(self, "重複", "勾選設備都已在待下發清單中"); return
        self.send_table.populate(self.to_be_sent_devices)
        self._remove_from_main_by_ips([d.get("IP","") for d in new_items])
        self.status_label.setText(f"已加入 {len(new_items)} 筆到待下發")

    # ---- 刪除回主清單（恢復原排序）----
    def _delete_from_table(self, data_list, table):
        rows = sorted(set(i.row() for i in table.selectedIndexes()), reverse=True)
        if not rows:
            QMessageBox.information(self, "未選擇", "請選取要刪除的設備")
            return
        restored = []
        for r in rows:
            d = data_list[r]
            restored.append(d)
            del data_list[r]
            table.removeRow(r)
        main_ips = set(d.get("IP","") for d in self.devices)
        for d in restored:
            if d.get("IP","") not in main_ips:
                self.devices.append(d)
        # 回主清單後按原排序還原
        self.devices = self.sort_by_original_order(self.devices)
        self.table.populate(self.devices)
        self.status_label.setText("已刪除並回到主清單（順序已還原）")

    def delete_selected_public(self):
        self._delete_from_table(self.public_devices, self.public_table)

    def delete_selected_send(self):
        self._delete_from_table(self.to_be_sent_devices, self.send_table)

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

    def _build_all_by_room(self):
        """
        建立 {房號: record} 索引。
        **只使用 original_order（匯入時的原始資料）**，確保名稱完全以匯入為準，
        避免被後續加入/刪除時的物件覆寫。
        """
        by_room = {}
        for d in self.original_order:
            room = (d.get("房號") or "").strip()
            ip = (d.get("IP") or "").strip()
            if room and ip:
                by_room[room] = d
        return by_room

    def deploy_monitor_list(self):
        if not self.to_be_sent_devices:
            QMessageBox.information(self, "無目標", "請先加入『待下發』清單。")
            return

        # 公區可空、私區可空（空就送空陣列以清空設備）
        private_codes = [it.text() for it in self.private_list.selectedItems()]

        self._clear_results()
        self.deploy_btn.setEnabled(False)
        self.status_label.setText("開始下發……")

        all_by_room = self._build_all_by_room()

        self.worker = DeployWorker(
            targets=self.to_be_sent_devices,
            public_src=self.public_devices,
            private_codes=private_codes,
            all_by_room=all_by_room,
            timeout=6
        )
        self.worker.one_done.connect(lambda info: self._append_result(info.get("ip",""), info.get("room",""), info.get("status",""), info.get("detail","")))
        self.worker.progress.connect(lambda done, total: self.progress.setValue(int(done*100/max(total,1))))
        self.worker.all_done.connect(lambda: (self.deploy_btn.setEnabled(True), self.status_label.setText("下發完成。")))
        self.worker.start()

# =========================
# 進入點
# =========================
if __name__ == "__main__":
    import warnings
    warnings.filterwarnings("ignore")

    app = QApplication(sys.argv)
    icon = get_icon_path()
    if os.path.exists(icon):
        app.setWindowIcon(QIcon(icon))
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())
