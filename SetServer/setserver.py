import sys
import os
import pandas as pd
import requests
import ipaddress
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QFileDialog, QLineEdit, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView, QCheckBox,
    QMessageBox, QAbstractItemView
)
from PyQt5.QtCore import Qt

DEVICE_PORT = 3377

# ========== Excel 智能解析與過濾 ==========

def is_valid_ip(s, name=""):
    try:
        ipstr = str(s).strip()
        name = str(name).lower()
        for badword in ["mask", "遮罩", "gateway", "網關", "gw", "router", "default gateway"]:
            if badword in name:
                return False
        ip = ipaddress.ip_address(ipstr)
        if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_reserved or ip.is_link_local:
            return False
        if ipstr.startswith("255.") or ipstr in ("0.0.0.0", "255.255.255.255"):
            return False
        if ipstr in ("255.255.255.0", "255.255.0.0", "255.0.0.0"):
            return False
        if ipstr.split(".")[-1] == "1":
            if name and any(x not in "0123456789.[] " for x in name):
                pass
            else:
                return False
        if not isinstance(ip, ipaddress.IPv4Address):
            return False
        return True
    except Exception:
        return False

def find_ip_name_type_column(df):
    for i in range(2, len(df.columns)):
        model_col = df.iloc[:, i - 2]
        name_col = df.iloc[:, i - 1]
        ip_col = df.iloc[:, i]
        valid_count = 0
        for dev_type, name, ip in zip(model_col, name_col, ip_col):
            if is_valid_ip(ip, name=name):
                valid_count += 1
        if valid_count > 3:
            return (
                pd.DataFrame({"model": model_col, "name": name_col, "ip": ip_col})
            )
    return pd.DataFrame()

def load_excel_and_parse_devices(file_path):
    xls = pd.ExcelFile(file_path)
    sheet = "貼紙印製" if "貼紙印製" in xls.sheet_names else xls.sheet_names[0]
    df_raw = pd.read_excel(file_path, sheet_name=sheet, header=None)
    df = find_ip_name_type_column(df_raw)
    if df.empty:
        raise Exception("無法辨識設備資料，請確認欄位格式")
    # 移除管理中心、空白行
    df = df[~df['model'].astype(str).str.replace(' ', '', regex=False).str.contains('管理中心')]
    df['ip'] = df['ip'].astype(str).str.strip()
    df = df[[is_valid_ip(row["ip"], row["name"]) for _, row in df.iterrows()]]
    df = df.reset_index(drop=True)
    # 去除重複IP
    df = df.drop_duplicates(subset="ip")
    # 轉成dict清單
    return df.to_dict(orient="records")

# ========== GUI 元件 ==========

class DeviceTable(QTableWidget):
    def __init__(self, parent=None):
        super().__init__(0, 4, parent)
        self.setHorizontalHeaderLabels(['選取', '型號', '名稱', 'IP'])
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
            self.setItem(row, 1, QTableWidgetItem(str(dev.get('model', ''))))
            self.setItem(row, 2, QTableWidgetItem(str(dev.get('name', ''))))
            self.setItem(row, 3, QTableWidgetItem(str(dev['ip'])))
    
    def get_selected_devices(self):
        result = []
        for row in range(self.rowCount()):
            cb = self.cellWidget(row, 0)
            if cb.isChecked():
                ip = self.item(row, 3).text()
                model = self.item(row, 1).text()
                name = self.item(row, 2).text()
                result.append({'ip': ip, 'model': model, 'name': name})
        return result
    
    def filter(self, keyword):
        keyword = keyword.lower()
        for row in range(self.rowCount()):
            text = (
                self.item(row, 1).text() + self.item(row, 2).text() + self.item(row, 3).text()
            ).lower()
            self.setRowHidden(row, keyword not in text)

    def select_all(self, checked:bool):
        for row in range(self.rowCount()):
            cb = self.cellWidget(row, 0)
            cb.setChecked(checked)

# ========== 主視窗 ==========

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("設備回報位址設定工具")
        self.resize(880, 540)
        self.devices = []
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)

        # 匯入 & 手動輸入區
        hbox = QHBoxLayout()
        self.import_btn = QPushButton("匯入Excel")
        self.import_btn.clicked.connect(self.import_excel)
        hbox.addWidget(self.import_btn)
        hbox.addWidget(QLabel("手動輸入IP:"))
        self.manual_ip_edit = QLineEdit()
        self.manual_ip_edit.setPlaceholderText("192.168.1.10")
        hbox.addWidget(self.manual_ip_edit)
        self.manual_add_btn = QPushButton("新增")
        self.manual_add_btn.clicked.connect(self.add_manual_ip)
        hbox.addWidget(self.manual_add_btn)
        hbox.addStretch()
        self.select_all_btn = QPushButton("全選")
        self.select_all_btn.clicked.connect(lambda: self.table.select_all(True))
        hbox.addWidget(self.select_all_btn)
        self.deselect_all_btn = QPushButton("全不選")
        self.deselect_all_btn.clicked.connect(lambda: self.table.select_all(False))
        hbox.addWidget(self.deselect_all_btn)
        layout.addLayout(hbox)

        # 搜尋區
        search_hbox = QHBoxLayout()
        search_hbox.addWidget(QLabel("搜尋:"))
        self.search_edit = QLineEdit()
        self.search_edit.textChanged.connect(self.search_devices)
        search_hbox.addWidget(self.search_edit)
        layout.addLayout(search_hbox)

        # 設備清單表格
        self.table = DeviceTable()
        layout.addWidget(self.table)

        # 伺服器位址設定區
        server_hbox = QHBoxLayout()
        server_hbox.addWidget(QLabel("Server IP:"))
        self.server_ip_edit = QLineEdit()
        self.server_ip_edit.setPlaceholderText("後台 Server IP，例如 192.168.200.3")
        server_hbox.addWidget(self.server_ip_edit)
        self.send_btn = QPushButton("發送設定")
        self.send_btn.clicked.connect(self.send_config)
        server_hbox.addWidget(self.send_btn)
        layout.addLayout(server_hbox)

        # 狀態/報表區
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
        self.devices.append({'ip': ip, 'name': '', 'model': ''})
        self.table.load_devices(self.devices)
        self.manual_ip_edit.clear()
        self.status_label.setText("手動新增成功")

    def search_devices(self):
        keyword = self.search_edit.text()
        self.table.filter(keyword)

    def send_config(self):
        server_ip = self.server_ip_edit.text().strip()
        if not is_valid_ip(server_ip):
            QMessageBox.warning(self, "格式錯誤", "請輸入正確的 Server IP")
            return
        selected = self.table.get_selected_devices()
        if not selected:
            QMessageBox.warning(self, "未選取", "請至少選取一台設備")
            return

        ok, fail = [], []
        for dev in selected:
            url = f"http://{dev['ip']}:{DEVICE_PORT}/set/server"
            data = { "url": f"http://{server_ip}:8000" }
            try:
                r = requests.post(url, json=data, timeout=3)
                if r.status_code == 200:
                    ok.append(dev['ip'])
                else:
                    fail.append(f"{dev['ip']} (狀態:{r.status_code})")
            except Exception as e:
                fail.append(f"{dev['ip']} (錯誤:{str(e).splitlines()[-1]})")
        result = f"成功：{len(ok)} 台\n" + ("、".join(ok) if ok else "")
        result += f"\n失敗：{len(fail)} 台\n" + ("\n".join(fail) if fail else "")
        self.status_label.setText(result)

if __name__ == "__main__":
    import warnings
    warnings.filterwarnings("ignore")
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())
