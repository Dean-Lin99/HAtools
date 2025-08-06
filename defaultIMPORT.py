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
        ipstr = str(s).strip()
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

def extract_room_no_from_row(row, ip_col_idx):
    """
    房號：設備類型前所有格，格首連續數字直接取出，其他跳過。保留前導零。
    例如 066號 -> 066, 01樓->01, 01 -> 01, 97區->97
    """
    room_no_parts = []
    for i in range(1, ip_col_idx - 2):
        val = row[i]
        if pd.isnull(val):
            continue
        val_str = str(val).strip()
        # 取開頭連續數字
        m = re.match(r'^(\d+)', val_str)
        if m:
            room_no_parts.append(m.group(1))
    return ''.join(room_no_parts)

def load_excel_and_parse_devices(file_path):
    xls = pd.ExcelFile(file_path)
    sheet = "貼紙印製" if "貼紙印製" in xls.sheet_names else xls.sheet_names[0]
    df_raw = pd.read_excel(file_path, sheet_name=sheet, header=None, dtype=str)
    ip_col_idx = find_ip_col_index(df_raw)
    if ip_col_idx is None or ip_col_idx < 2:
        raise Exception("找不到有效IPv4欄位")
    device_list = []
    for idx, row in df_raw.iterrows():
        ip = str(row[ip_col_idx]).strip()
        if not is_valid_ip(ip):
            continue
        dev_type = str(row[ip_col_idx - 2]).strip() if ip_col_idx - 2 >= 0 else ""
        if "管理中心" in dev_type:
            continue
        name = str(row[ip_col_idx - 1]).strip() if ip_col_idx - 1 >= 0 else ""
        room_no = extract_room_no_from_row(row, ip_col_idx)
        device_list.append({
            'dev_type': dev_type,
            'name': name,
            'ip': ip,
            'room_no': room_no
        })
    df = pd.DataFrame(device_list)
    df = df.drop_duplicates(subset="ip")
    return df.to_dict(orient="records")

class DeviceTable(QTableWidget):
    def __init__(self, parent=None):
        super().__init__(0, 5, parent)
        self.setHorizontalHeaderLabels(['選取', '設備類型', '名稱', 'IP', '房號'])
        self.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)

    def load_devices(self, devices):
        self.setRowCount(0)
        for dev in devices:
            row = self.rowCount()
            self.insertRow(row)
            cb = QCheckBox()
            self.setCellWidget(row, 0, cb)
            self.setItem(row, 1, QTableWidgetItem(str(dev.get('dev_type', ''))))
            self.setItem(row, 2, QTableWidgetItem(str(dev.get('name', ''))))
            self.setItem(row, 3, QTableWidgetItem(str(dev['ip'])))
            self.setItem(row, 4, QTableWidgetItem(str(dev.get('room_no', ''))))

    def get_selected_devices(self):
        result = []
        for row in range(self.rowCount()):
            cb = self.cellWidget(row, 0)
            if cb.isChecked():
                ip = self.item(row, 3).text()
                dev_type = self.item(row, 1).text()
                name = self.item(row, 2).text()
                room_no = self.item(row, 4).text()
                result.append({'ip': ip, 'dev_type': dev_type, 'name': name, 'room_no': room_no})
        return result

    def filter(self, keyword):
        keyword = keyword.lower()
        for row in range(self.rowCount()):
            text = (
                self.item(row, 1).text() + self.item(row, 2).text() +
                self.item(row, 3).text() + self.item(row, 4).text()
            ).lower()
            self.setRowHidden(row, keyword not in text)

    def select_all(self, checked: bool):
        for row in range(self.rowCount()):
            if not self.isRowHidden(row):
                cb = self.cellWidget(row, 0)
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
            self.table.load_devices(devices)
            self.status_label.setText(f"匯入成功，共 {len(devices)} 筆設備")
            self.search_devices()
        except Exception as e:
            self.status_label.setText(f"匯入失敗: {e}")

    def add_manual_ip(self):
        ip = self.manual_ip_edit.text().strip()
        if not is_valid_ip(ip):
            QMessageBox.warning(self, "格式錯誤", "請輸入正確的IPv4位址")
            return
        for d in self.devices:
            if d['ip'] == ip:
                QMessageBox.information(self, "已存在", "此IP已在清單中")
                return
        self.devices.append({'ip': ip, 'name': '', 'dev_type': '', 'room_no': ''})
        self.table.load_devices(self.devices)
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
        self.table.load_devices([])
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
