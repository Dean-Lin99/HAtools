import sys
import os
import pandas as pd
import ipaddress
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QFileDialog, QLineEdit, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView, QCheckBox,
    QMessageBox, QAbstractItemView, QListWidget, QListWidgetItem
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon

def get_icon_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "main.ico")

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
            return pd.DataFrame({"model": model_col, "name": name_col, "ip": ip_col})
    return pd.DataFrame()

def load_excel_and_parse_devices(file_path):
    xls = pd.ExcelFile(file_path)
    sheet = "貼紙印製" if "貼紙印製" in xls.sheet_names else xls.sheet_names[0]
    df_raw = pd.read_excel(file_path, sheet_name=sheet, header=None)
    df = find_ip_name_type_column(df_raw)
    if df.empty:
        raise Exception("無法辨識設備資料，請確認欄位格式")
    df = df[~df['model'].astype(str).str.replace(' ', '', regex=False).str.contains('管理中心')]
    df['ip'] = df['ip'].astype(str).str.strip()
    df = df[[is_valid_ip(row["ip"], row["name"]) for _, row in df.iterrows()]]
    df = df.reset_index(drop=True)
    df = df.drop_duplicates(subset="ip")
    return df.to_dict(orient="records")

class DeviceTable(QTableWidget):
    def __init__(self, parent=None, selectable=True):
        super().__init__(0, 4, parent)
        self.setHorizontalHeaderLabels(['選取', '設備類型', '名稱', 'IP'])
        self.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.selectable = selectable

    def load_devices(self, devices, check_all=False):
        self.setRowCount(0)
        for dev in devices:
            row = self.rowCount()
            self.insertRow(row)
            if self.selectable:
                cb = QCheckBox()
                if check_all:
                    cb.setChecked(True)
                self.setCellWidget(row, 0, cb)
            else:
                self.setItem(row, 0, QTableWidgetItem(""))
            self.setItem(row, 1, QTableWidgetItem(str(dev.get('model', ''))))
            self.setItem(row, 2, QTableWidgetItem(str(dev.get('name', ''))))
            self.setItem(row, 3, QTableWidgetItem(str(dev['ip'])))

    def get_selected_devices(self):
        result = []
        for row in range(self.rowCount()):
            if self.selectable:
                cb = self.cellWidget(row, 0)
                if cb and cb.isChecked():
                    ip = self.item(row, 3).text()
                    model = self.item(row, 1).text()
                    name = self.item(row, 2).text()
                    result.append({'ip': ip, 'model': model, 'name': name})
            else:
                ip = self.item(row, 3).text()
                model = self.item(row, 1).text()
                name = self.item(row, 2).text()
                result.append({'ip': ip, 'model': model, 'name': name})
        return result

    def remove_rows_by_ips(self, ip_list):
        for row in reversed(range(self.rowCount())):
            ip = self.item(row, 3).text()
            if ip in ip_list:
                self.removeRow(row)

    def filter(self, keyword):
        keyword = keyword.lower()
        for row in range(self.rowCount()):
            text = (
                self.item(row, 1).text() + self.item(row, 2).text() + self.item(row, 3).text()
            ).lower()
            self.setRowHidden(row, keyword not in text)

    def select_all(self, checked:bool):
        if not self.selectable:
            return
        for row in range(self.rowCount()):
            if not self.isRowHidden(row):
                cb = self.cellWidget(row, 0)
                cb.setChecked(checked)

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("設備清單管理工具")
        self.resize(950, 950)
        icon_path = get_icon_path()
        self.setWindowIcon(QIcon(icon_path))
        self.devices = []
        self.to_be_sent_devices = []
        self.public_devices = []
        self.original_order = []
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)

        # === 全部設備清單 ===
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
        self.select_all_btn.clicked.connect(lambda: self.table.select_all(True))
        hbox.addWidget(self.select_all_btn)
        self.deselect_all_btn = QPushButton("全不選")
        self.deselect_all_btn.clicked.connect(lambda: self.table.select_all(False))
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

        layout.addWidget(QLabel("全部設備清單（勾選後選擇要加入公區或待下發）"))
        self.table = DeviceTable(selectable=True)
        layout.addWidget(self.table)

        add_hbox = QHBoxLayout()
        self.add_to_public_btn = QPushButton("加入公區")
        self.add_to_public_btn.clicked.connect(self.add_to_public)
        add_hbox.addWidget(self.add_to_public_btn)
        self.add_to_send_btn = QPushButton("加入待下發")
        self.add_to_send_btn.clicked.connect(self.add_to_send)
        add_hbox.addWidget(self.add_to_send_btn)
        add_hbox.addStretch()
        layout.addLayout(add_hbox)

        # === 待下發設備清單 ===
        layout.addWidget(QLabel("待下發設備清單（可刪除，刪除後自動回到主清單）"))
        self.send_table = DeviceTable(selectable=True)
        self.send_table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        layout.addWidget(self.send_table)

        del_send_hbox = QHBoxLayout()
        self.delete_send_btn = QPushButton("刪除選取待下發設備")
        self.delete_send_btn.clicked.connect(self.delete_selected_send_device)
        del_send_hbox.addWidget(self.delete_send_btn)
        del_send_hbox.addStretch()
        layout.addLayout(del_send_hbox)

        # === 公區設備清單 ===
        layout.addWidget(QLabel("公區設備清單（可刪除，刪除後自動回到主清單）"))
        self.public_table = DeviceTable(selectable=True)
        self.public_table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        layout.addWidget(self.public_table)

        del_public_hbox = QHBoxLayout()
        self.delete_public_btn = QPushButton("刪除選取公區設備")
        self.delete_public_btn.clicked.connect(self.delete_selected_public_device)
        del_public_hbox.addWidget(self.delete_public_btn)
        del_public_hbox.addStretch()
        layout.addLayout(del_public_hbox)

        # ---- 私區+下發功能（多選 02~10）----
        private_hbox = QHBoxLayout()
        private_hbox.addWidget(QLabel("私區小門口機(可多選):"))

        self.private_list = QListWidget()
        self.private_list.setSelectionMode(QAbstractItemView.MultiSelection)
        for i in range(2, 11):
            item = QListWidgetItem(f"{i:02d}")
            self.private_list.addItem(item)
        self.private_list.setMaximumHeight(80)
        self.private_list.setMaximumWidth(150)
        private_hbox.addWidget(self.private_list)

        private_hbox.addStretch()
        self.deploy_btn = QPushButton("下發監視列表")
        self.deploy_btn.clicked.connect(self.deploy_monitor_list)
        private_hbox.addWidget(self.deploy_btn)
        layout.addLayout(private_hbox)

        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

    def import_excel(self):
        path, _ = QFileDialog.getOpenFileName(self, "匯入 Excel", "", "Excel Files (*.xls *.xlsx)")
        if not path:
            return
        try:
            devices = load_excel_and_parse_devices(path)
            self.devices = devices.copy()
            self.original_order = devices.copy()
            self.table.load_devices(self.devices)
            self.status_label.setText(f"匯入成功，共 {len(devices)} 筆設備")
            self.search_devices()
        except Exception as e:
            self.status_label.setText(f"匯入失敗: {e}")

    def add_manual_ip(self):
        ip = self.manual_ip_edit.text().strip()
        if not is_valid_ip(ip):
            QMessageBox.warning(self, "格式錯誤", "請輸入正確的IPv4位址")
            return
        for d in (self.devices + self.to_be_sent_devices + self.public_devices):
            if d['ip'] == ip:
                QMessageBox.information(self, "已存在", "此IP已在清單中")
                return
        dev = {'ip': ip, 'name': '', 'model': ''}
        self.devices.append(dev)
        self.original_order.append(dev)
        self.table.load_devices(self.devices)
        self.manual_ip_edit.clear()
        self.status_label.setText("手動新增成功")
        self.search_devices()

    def search_devices(self):
        keyword = self.search_edit.text()
        self.table.filter(keyword)

    def clear_all_data(self):
        self.devices = []
        self.table.load_devices([])
        self.to_be_sent_devices = []
        self.send_table.load_devices([])
        self.public_devices = []
        self.public_table.load_devices([])
        self.original_order = []
        self.manual_ip_edit.clear()
        self.search_edit.clear()
        self.status_label.setText("已清除所有資料")

    def add_to_send(self):
        selected = self.table.get_selected_devices()
        if not selected:
            QMessageBox.information(self, "未選擇", "請至少勾選一個設備")
            return
        added_ips = set([d['ip'] for d in self.to_be_sent_devices])
        new_items = [d for d in selected if d['ip'] not in added_ips]
        if not new_items:
            QMessageBox.information(self, "重複", "勾選設備都已在待下發列表中")
            return
        self.to_be_sent_devices.extend(new_items)
        self.send_table.load_devices(self.to_be_sent_devices)
        remove_ips = [d['ip'] for d in new_items]
        self.devices = [d for d in self.devices if d['ip'] not in remove_ips]
        self.table.load_devices(self.devices)
        self.status_label.setText(f"已加入{len(new_items)}筆設備到待下發清單")

    def add_to_public(self):
        selected = self.table.get_selected_devices()
        if not selected:
            QMessageBox.information(self, "未選擇", "請至少勾選一個設備")
            return
        added_ips = set([d['ip'] for d in self.public_devices])
        new_items = [d for d in selected if d['ip'] not in added_ips]
        if not new_items:
            QMessageBox.information(self, "重複", "勾選設備都已在公區清單中")
            return
        self.public_devices.extend(new_items)
        self.public_table.load_devices(self.public_devices)
        remove_ips = [d['ip'] for d in new_items]
        self.devices = [d for d in self.devices if d['ip'] not in remove_ips]
        self.table.load_devices(self.devices)
        self.status_label.setText(f"已加入{len(new_items)}筆設備到公區設備清單")

    def delete_selected_send_device(self):
        rows = sorted(set(idx.row() for idx in self.send_table.selectedIndexes()), reverse=True)
        if not rows:
            QMessageBox.information(self, "未選擇", "請選取要刪除的設備")
            return
        restored = []
        for row in rows:
            dev = self.to_be_sent_devices[row]
            restored.append(dev)
            del self.to_be_sent_devices[row]
            self.send_table.removeRow(row)
        main_ips = set([d['ip'] for d in self.devices])
        for d in restored:
            if d['ip'] not in main_ips:
                self.devices.append(d)
        self.devices = self.sort_by_original_order(self.devices)
        self.table.load_devices(self.devices)
        self.status_label.setText("已刪除並回復到主清單（順序已還原）。")

    def delete_selected_public_device(self):
        rows = sorted(set(idx.row() for idx in self.public_table.selectedIndexes()), reverse=True)
        if not rows:
            QMessageBox.information(self, "未選擇", "請選取要刪除的設備")
            return
        restored = []
        for row in rows:
            dev = self.public_devices[row]
            restored.append(dev)
            del self.public_devices[row]
            self.public_table.removeRow(row)
        main_ips = set([d['ip'] for d in self.devices])
        for d in restored:
            if d['ip'] not in main_ips:
                self.devices.append(d)
        self.devices = self.sort_by_original_order(self.devices)
        self.table.load_devices(self.devices)
        self.status_label.setText("已刪除並回復到主清單（順序已還原）。")

    def sort_by_original_order(self, device_list):
        ip_to_dev = {d['ip']: d for d in device_list}
        sorted_list = []
        for od in self.original_order:
            if od['ip'] in ip_to_dev:
                sorted_list.append(ip_to_dev[od['ip']])
        return sorted_list

    def deploy_monitor_list(self):
        public_devices = self.public_devices
        private_selected = [item.text() for item in self.private_list.selectedItems()]
        info = f"下發監視列表:\n\n"
        info += "公區設備：\n"
        if public_devices:
            for dev in public_devices:
                info += f"- [{dev['model']}] {dev['name']} ({dev['ip']})\n"
        else:
            info += "(無)\n"
        info += "\n私區小門口機："
        if private_selected:
            info += ", ".join(private_selected)
        else:
            info += "(無)"
        info += "\n"
        QMessageBox.information(self, "下發資訊", info)
        self.status_label.setText("已下發監視列表（模擬）")

if __name__ == "__main__":
    import warnings
    warnings.filterwarnings("ignore")
    app = QApplication(sys.argv)
    icon_path = get_icon_path()
    app.setWindowIcon(QIcon(icon_path))
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())
