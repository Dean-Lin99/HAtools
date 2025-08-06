import sys
import os
import pandas as pd
import ipaddress
import re
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QFileDialog, QLineEdit, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView, QCheckBox,
    QMessageBox, QAbstractItemView
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon

def get_icon_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "main.ico")

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
        valid = sum(is_valid_ip(cell) for cell in df.iloc[:, col])
        if valid >= 2:
            return col
    return None

def is_first_column_serial(col, min_length=5):
    """
    判斷第一欄是否為流水號（有一段連號即可），min_length可調整
    """
    numbers = []
    for val in col:
        try:
            v = int(str(val).strip())
            numbers.append(v)
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
    room_no_parts = []
    for i in range(type_col_idx):
        if skip_first_col and i == 0:
            continue  # 只跳過第0欄（僅當判斷為流水號時）
        val = row[i]
        if pd.isnull(val):
            continue
        val_str = str(val).strip()
        if re.fullmatch(r'\d+', val_str):
            room_no_parts.append(val_str)
    return ''.join(room_no_parts)

def process_one_sheet(df_raw, is_sticker_sheet=False):
    ip_col_idx = find_ip_col_index(df_raw)
    if ip_col_idx is None or ip_col_idx < 2:
        return None
    devtype_col_idx = ip_col_idx - 2   # 設備類型
    name_col_idx = ip_col_idx - 1      # 名稱
    # 只判斷第一欄是否為流水號
    skip_first_col = is_first_column_serial(df_raw.iloc[:, 0], min_length=5)
    device_list = []
    for idx, row in df_raw.iterrows():
        ip = str(row[ip_col_idx]).replace(" ", "").strip()
        if not is_valid_ip(ip):
            continue
        dev_type = str(row[devtype_col_idx]).strip() if devtype_col_idx >= 0 else ""
        if "管理中心" in dev_type:
            continue
        name = str(row[name_col_idx]).strip() if name_col_idx >= 0 else ""
        room_no = extract_room_no_from_row(row, devtype_col_idx, skip_first_col)
        device_list.append({
            '設備類型': dev_type,
            '名稱': name,
            'IP': ip,
            '房號': room_no
        })
    df = pd.DataFrame(device_list)
    df = df.drop_duplicates(subset="IP")
    records = df.to_dict(orient="records")
    for rec in records:
        rec["選取"] = False
    cols = ["選取", "設備類型", "名稱", "IP", "房號"]
    final_list = []
    for rec in records:
        item = {k: rec.get(k, "") for k in cols}
        final_list.append(item)
    return final_list

def load_excel_and_parse_devices(file_path):
    xls = pd.ExcelFile(file_path)
    # 優先處理「貼紙印製」sheet
    if "貼紙印製" in xls.sheet_names:
        df_raw = pd.read_excel(file_path, sheet_name="貼紙印製", header=None, dtype=str)
        result = process_one_sheet(df_raw, is_sticker_sheet=True)
        if result is not None:
            return result
    # 沒有貼紙印製才輪詢其他 sheet
    for sheet_name in xls.sheet_names:
        if sheet_name == "貼紙印製":
            continue
        df_raw = pd.read_excel(file_path, sheet_name=sheet_name, header=None, dtype=str)
        result = process_one_sheet(df_raw, is_sticker_sheet=False)
        if result is not None:
            return result
    # 如果都找不到結構化IP欄，只做單純全檔IP掃描
    ip_set = set()
    device_list = []
    for sheet_name in xls.sheet_names:
        df = pd.read_excel(file_path, sheet_name=sheet_name, header=None, dtype=str)
        for idx, row in df.iterrows():
            for cell in row:
                if pd.isnull(cell):
                    continue
                ip = str(cell).replace(" ", "").strip()
                if is_valid_ip(ip) and ip not in ip_set:
                    device_list.append({
                        'IP': ip,
                        '選取': False
                    })
                    ip_set.add(ip)
    cols = ["選取", "IP"]
    final_list = []
    for rec in device_list:
        item = {k: rec.get(k, "") for k in cols}
        final_list.append(item)
    return final_list

class DeviceTable(QTableWidget):
    def __init__(self, parent=None):
        super().__init__(0, 0, parent)
        self.data_keys = []

    def set_columns_and_data(self, devices):
        self.setRowCount(0)
        if not devices:
            self.setColumnCount(0)
            self.setHorizontalHeaderLabels([])
            self.data_keys = []
            return
        keys = list(devices[0].keys())
        for dev in devices:
            for k in dev.keys():
                if k not in keys:
                    keys.append(k)
        self.data_keys = keys
        self.setColumnCount(len(keys))
        self.setHorizontalHeaderLabels(keys)
        for dev in devices:
            row = self.rowCount()
            self.insertRow(row)
            for col, key in enumerate(self.data_keys):
                if key == '選取':
                    cb = QCheckBox()
                    self.setCellWidget(row, col, cb)
                else:
                    val = str(dev.get(key, ""))
                    self.setItem(row, col, QTableWidgetItem(val))

    def get_selected_devices(self):
        if self.data_keys and self.data_keys[0] == '選取':
            result = []
            for row in range(self.rowCount()):
                cb = self.cellWidget(row, 0)
                if cb and cb.isChecked():
                    item_data = {k: self.item(row, i).text() if self.item(row, i) else '' for i, k in enumerate(self.data_keys) if k != '選取'}
                    result.append(item_data)
            return result
        else:
            result = []
            for row in range(self.rowCount()):
                item_data = {k: self.item(row, i).text() if self.item(row, i) else '' for i, k in enumerate(self.data_keys)}
                result.append(item_data)
            return result

    def filter(self, keyword):
        keyword = keyword.lower()
        for row in range(self.rowCount()):
            text = ""
            for col in range(self.columnCount()):
                item = self.item(row, col)
                if item:
                    text += item.text().lower()
            self.setRowHidden(row, keyword not in text)

    def select_all(self, checked: bool):
        if not self.data_keys or self.data_keys[0] != '選取':
            return
        for row in range(self.rowCount()):
            cb = self.cellWidget(row, 0)
            if cb:
                cb.setChecked(checked)

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("設備清單管理工具")
        self.resize(1050, 550)
        icon_path = get_icon_path()
        self.setWindowIcon(QIcon(icon_path))
        self.devices = []
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        hbox = QHBoxLayout()
        self.import_btn = QPushButton("匯入Excel")
        self.import_btn.clicked.connect(self.import_excel)
        hbox.addWidget(self.import_btn)
        hbox.addWidget(QLabel("手動輸入IP:"))
        self.manual_ip_edit = QLineEdit()
        self.manual_ip_edit.setPlaceholderText("192.168.1.10")
        self.manual_ip_edit.returnPressed.connect(self.add_manual_ip)
        hbox.addWidget(self.manual_ip_edit)
        self.manual_add_btn = QPushButton("新增")
        self.manual_add_btn.clicked.connect(self.add_manual_ip)
        hbox.addWidget(self.manual_add_btn)
        hbox.addStretch()
        self.select_all_btn = QPushButton("全選")
        self.select_all_btn.clicked.connect(self.select_all_filtered)
        hbox.addWidget(self.select_all_btn)
        self.deselect_all_btn = QPushButton("全不選")
        self.deselect_all_btn.clicked.connect(self.deselect_all_filtered)
        hbox.addWidget(self.deselect_all_btn)
        self.clear_btn = QPushButton("清除資料")
        self.clear_btn.clicked.connect(self.clear_all_data)
        hbox.addWidget(self.clear_btn)
        layout.addLayout(hbox)

        search_hbox = QHBoxLayout()
        search_hbox.addWidget(QLabel("搜尋:"))
        self.search_edit = QLineEdit()
        self.search_edit.textChanged.connect(self.search_devices)
        search_hbox.addWidget(self.search_edit)
        layout.addLayout(search_hbox)

        self.table = DeviceTable()
        layout.addWidget(self.table)

        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

    def import_excel(self):
        path, _ = QFileDialog.getOpenFileName(self, "匯入 Excel", "", "Excel Files (*.xls *.xlsx)")
        if not path:
            return
        try:
            devices = load_excel_and_parse_devices(path)
            self.devices = devices
            self.table.set_columns_and_data(devices)
            self.status_label.setText(f"匯入成功，共 {len(devices)} 筆設備")
            self.search_devices()
        except Exception as e:
            self.status_label.setText(f"匯入失敗: {e}")

    def add_manual_ip(self):
        ip = self.manual_ip_edit.text().strip()
        if not is_valid_ip(ip):
            QMessageBox.warning(self, "格式錯誤", "請輸入正確的IPv4位址")
            return
        keys = self.table.data_keys or ["選取", "IP"]
        rec = {k: "" for k in keys}
        rec["IP"] = ip
        if "選取" in rec:
            rec["選取"] = False
        self.devices.append(rec)
        self.table.set_columns_and_data(self.devices)
        self.manual_ip_edit.clear()
        self.status_label.setText("手動新增成功")
        self.search_devices()

    def search_devices(self):
        keyword = self.search_edit.text()
        self.table.filter(keyword)

    def select_all_filtered(self):
        self.table.select_all(True)

    def deselect_all_filtered(self):
        self.table.select_all(False)

    def clear_all_data(self):
        self.devices = []
        self.table.set_columns_and_data([])
        self.manual_ip_edit.clear()
        self.search_edit.clear()
        self.status_label.setText("已清除所有資料")

if __name__ == "__main__":
    import warnings
    warnings.filterwarnings("ignore")
    app = QApplication(sys.argv)
    icon_path = get_icon_path()
    app.setWindowIcon(QIcon(icon_path))
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())
