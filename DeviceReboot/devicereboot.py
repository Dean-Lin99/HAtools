import sys
import os
import asyncio
import hashlib
import datetime
import re

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTableWidget, QTableWidgetItem,
    QFileDialog, QMessageBox, QLineEdit, QProgressBar, QSizePolicy, QDialog, QFormLayout
)
from PyQt5.QtCore import Qt, pyqtSignal, QObject, QThread
from PyQt5.QtGui import QIcon

import pandas as pd
import openpyxl
import aiohttp

PORT = 3377
MAX_CONCURRENT = 100
PASSWORD = "tonnet1983"

def get_icon(filename):
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)

def is_ipv4(ip):
    if not isinstance(ip, str):
        return False
    ip = ip.strip()
    if ip.lower() in ['mask', 'gateway', 'gw', 'subnet', 'netmask']:
        return False
    blacklist = [
        '255.255.255.255', '255.255.255.0', '255.0.0.0', '0.0.0.0', '127.0.0.1', '255.255.248.0', '224.0.0.1','192.168.200.3',
    ]
    if ip in blacklist:
        return False
    if ip.startswith("255.255"):
        return False
    m = re.match(
        r"^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}$", ip
    )
    if not m:
        return False
    return True

def ip_sort_key(ip):
    return list(map(int, ip.split('.')))

def gen_token(room):
    now = datetime.datetime.now()
    remote = "remote"
    ymd = now.strftime('%Y%m%d')
    hms = now.strftime('%H%M%S')
    text = f"{remote}{ymd}{room}{hms}".lower()
    return hashlib.md5(text.encode('utf-8')).hexdigest(), now.strftime('%Y-%m-%dT%H:%M:%S+08:00')

class SignalBus(QObject):
    update_result_signal = pyqtSignal(int, str, str)
    progress_signal = pyqtSignal(int, int)
    finish_signal = pyqtSignal()

class PasswordDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("密碼驗證")
        self.setWindowIcon(QIcon(get_icon("main.ico")))
        self.setModal(True)
        self.pwd_input = QLineEdit()
        self.pwd_input.setEchoMode(QLineEdit.Password)
        layout = QFormLayout()
        layout.addRow(QLabel("請輸入密碼："), self.pwd_input)
        self.msg_label = QLabel("")
        layout.addRow(self.msg_label)
        btn_ok = QPushButton("確定")
        btn_ok.clicked.connect(self.accept)
        layout.addRow(btn_ok)
        self.setLayout(layout)
        self.result = False
        self.try_count = 0

    def accept(self):
        pwd = self.pwd_input.text()
        if pwd == PASSWORD:
            self.result = True
            self.done(1)
        else:
            self.try_count += 1
            self.msg_label.setText("密碼錯誤！" if self.try_count < 3 else "已超過最大嘗試次數。")
            self.pwd_input.clear()
            if self.try_count >= 3:
                self.result = False
                self.done(0)

class AsyncRebootThread(QThread):
    def __init__(self, ip_list, signalbus, stop_flag):
        super().__init__()
        self.ip_list = ip_list
        self.signalbus = signalbus
        self.stop_flag = stop_flag

    async def async_reboot_job(self, idx, ip, session, sem):
        async with sem:
            if self.stop_flag.is_set():
                return (idx, "取消", "")
            try:
                url_info = f"http://{ip}:{PORT}/device/info"
                try:
                    async with session.get(url_info, timeout=3) as r:
                        data = await r.json()
                        room_id = ""
                        if "data" in data and isinstance(data["data"], dict):
                            room_id = data["data"].get("room_id", "")
                except Exception:
                    return (idx, "異常", "設備離線")
                token, now_str = gen_token(room_id)
                url_reboot = f"http://{ip}:{PORT}/remote/reboot"
                payload = {
                    "token": token,
                    "room": room_id,
                    "time": now_str
                }
                try:
                    async with session.post(url_reboot, json=payload, timeout=5) as r:
                        if r.status == 200:
                            return (idx, "成功", "")
                        else:
                            return (idx, "失敗", str(r.status))
                except Exception as e:
                    return (idx, "異常", str(e))
            except Exception as e:
                return (idx, "異常", str(e))

    async def async_batch(self):
        total = len(self.ip_list)
        sem = asyncio.Semaphore(MAX_CONCURRENT)
        connector = aiohttp.TCPConnector(limit=MAX_CONCURRENT, force_close=True)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [
                self.async_reboot_job(idx, ip, session, sem)
                for idx, ip in enumerate(self.ip_list)
            ]
            done_count = 0
            for coro in asyncio.as_completed(tasks):
                idx, status, msg = await coro
                self.signalbus.update_result_signal.emit(idx, status, msg)
                done_count += 1
                self.signalbus.progress_signal.emit(done_count, total)
                if self.stop_flag.is_set():
                    break
        self.signalbus.finish_signal.emit()

    def run(self):
        asyncio.run(self.async_batch())

class RebootGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("HA設備重啟工具_V1.0_By Dean")
        self.setWindowIcon(QIcon(get_icon("main.ico")))

        screen = QApplication.primaryScreen()
        size = screen.size()
        w = int(size.width() * 0.7)
        h = int(size.height() * 0.7)
        self.resize(w, h)
        self.center_window()

        self.all_ip_list = []
        self.stop_flag = asyncio.Event()
        self.thread = None
        self.signalbus = SignalBus()

        self.init_ui()
        self.signalbus.update_result_signal.connect(self._update_result_table)
        self.signalbus.progress_signal.connect(self._update_progress)
        self.signalbus.finish_signal.connect(self._on_finish)

    def center_window(self):
        qr = self.frameGeometry()
        cp = QApplication.desktop().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())

    def init_ui(self):
        main_layout = QHBoxLayout()
        left_layout = QVBoxLayout()
        right_layout = QVBoxLayout()

        # --- 左：已匯入IP ---
        top_layout = QHBoxLayout()
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("請輸入IP (例如 192.168.200.10)")
        self.ip_input.setFixedWidth(250)
        self.ip_input.setFixedHeight(32)
        self.ip_input.returnPressed.connect(self.add_ip)
        btn_add_ip = QPushButton("加入IP")
        btn_add_ip.setFixedHeight(32)
        btn_add_ip.clicked.connect(self.add_ip)
        btn_import = QPushButton("匯入Excel")
        btn_import.setFixedHeight(32)
        btn_import.clicked.connect(self.import_excel)
        top_layout.addWidget(self.ip_input)
        top_layout.addWidget(btn_add_ip)
        top_layout.addWidget(btn_import)
        left_layout.addLayout(top_layout)

        self.ip_table = QTableWidget(0, 1)
        self.ip_table.setHorizontalHeaderLabels(["所有IP"])
        self.ip_table.setSelectionBehavior(self.ip_table.SelectRows)
        self.ip_table.setSelectionMode(self.ip_table.MultiSelection)
        left_layout.addWidget(QLabel("已匯入設備IP列表"))
        left_layout.addWidget(self.ip_table)

        select_layout = QHBoxLayout()
        btn_select_all = QPushButton("全部選取")
        btn_select_all.clicked.connect(lambda: self.ip_table.selectAll())
        btn_deselect = QPushButton("取消選取")
        btn_deselect.clicked.connect(lambda: self.ip_table.clearSelection())
        select_layout.addWidget(btn_select_all)
        select_layout.addWidget(btn_deselect)
        left_layout.addLayout(select_layout)

        btn_add_to_reboot = QPushButton("加入右側重啟列表")
        btn_add_to_reboot.setFixedWidth(550)
        btn_add_to_reboot.clicked.connect(self.add_to_reboot_list)
        left_layout.addWidget(btn_add_to_reboot)

        # --- 右：待重啟清單 ---
        self.reboot_table = QTableWidget(0, 3)
        self.reboot_table.setHorizontalHeaderLabels(["IP", "重啟狀態", "錯誤碼/訊息"])
        self.reboot_table.setSelectionBehavior(self.reboot_table.SelectRows)
        self.reboot_table.setSelectionMode(self.reboot_table.MultiSelection)
        right_layout.addWidget(QLabel("待重啟設備列表"))
        right_layout.addWidget(self.reboot_table)

        op_layout = QHBoxLayout()
        btn_remove = QPushButton("移除選取")
        btn_remove.clicked.connect(self.remove_from_reboot_list)
        btn_select_all_r = QPushButton("全部選取")
        btn_select_all_r.clicked.connect(lambda: self.reboot_table.selectAll())
        btn_deselect_r = QPushButton("取消選取")
        btn_deselect_r.clicked.connect(lambda: self.reboot_table.clearSelection())
        op_layout.addWidget(btn_remove)
        op_layout.addWidget(btn_select_all_r)
        op_layout.addWidget(btn_deselect_r)
        right_layout.addLayout(op_layout)

        exec_layout = QHBoxLayout()
        self.btn_reboot = QPushButton("執行重啟")
        self.btn_reboot.clicked.connect(self.exec_reboot)
        self.btn_cancel = QPushButton("取消執行")
        self.btn_cancel.clicked.connect(self.cancel_exec)
        self.btn_cancel.setEnabled(False)
        self.progress = QProgressBar()
        self.progress.setValue(0)
        exec_layout.addWidget(self.btn_reboot)
        exec_layout.addWidget(self.btn_cancel)
        exec_layout.addWidget(self.progress)
        right_layout.addLayout(exec_layout)

        export_layout = QHBoxLayout()
        btn_export = QPushButton("匯出執行紀錄")
        btn_export.clicked.connect(self.export_result)
        btn_clear = QPushButton("清除全部資料")
        btn_clear.clicked.connect(self.clear_all_data)
        export_layout.addWidget(btn_export)
        export_layout.addWidget(btn_clear)
        right_layout.addLayout(export_layout)

        main_layout.addLayout(left_layout, 1)
        main_layout.addLayout(right_layout, 2)
        self.setLayout(main_layout)

    def add_ip(self):
        ip = self.ip_input.text().strip()
        if is_ipv4(ip) and ip not in self.all_ip_list and ip not in self.get_reboot_list_ips():
            self.all_ip_list.append(ip)
            self.all_ip_list.sort(key=ip_sort_key)
            self.update_ip_table()
        self.ip_input.clear()

    def import_excel(self):
        path, _ = QFileDialog.getOpenFileName(self, "選擇Excel檔", "", "Excel Files (*.xlsx *.xls)")
        if not path:
            return
        try:
            # 讀全部 sheets
            all_sheets = pd.read_excel(path, header=None, dtype=str, sheet_name=None)
            target_df = None
            for sheet_name in all_sheets:
                if "貼紙印製" in sheet_name:
                    target_df = all_sheets[sheet_name]
                    break
            if target_df is None:
                target_df = list(all_sheets.values())[0]
            # 去重
            unique_ip_set = set(self.all_ip_list + self.get_reboot_list_ips())
            flat_list = target_df.values.flatten()
            for cell in flat_list:
                if pd.isna(cell):
                    continue
                ip = str(cell).strip()
                if is_ipv4(ip) and ip not in unique_ip_set:
                    unique_ip_set.add(ip)
            # 排除待重啟的ip
            self.all_ip_list = sorted(list(unique_ip_set - set(self.get_reboot_list_ips())), key=ip_sort_key)
            self.update_ip_table()
        except Exception as e:
            QMessageBox.warning(self, "匯入錯誤", f"Excel匯入失敗：{e}")

    def update_ip_table(self):
        self.all_ip_list.sort(key=ip_sort_key)
        self.ip_table.setRowCount(0)
        for ip in self.all_ip_list:
            row = self.ip_table.rowCount()
            self.ip_table.insertRow(row)
            self.ip_table.setItem(row, 0, QTableWidgetItem(ip))

    def get_reboot_list_ips(self):
        return [self.reboot_table.item(i, 0).text() for i in range(self.reboot_table.rowCount())]

    def add_to_reboot_list(self):
        selected_rows = sorted(set([i.row() for i in self.ip_table.selectedIndexes()]), reverse=True)
        new_ips = []
        for row in selected_rows:
            ip = self.all_ip_list[row]
            if ip not in self.get_reboot_list_ips():
                new_ips.append(ip)
            del self.all_ip_list[row]
        self.all_ip_list.sort(key=ip_sort_key)
        self.update_ip_table()
        # 排序右側
        all_right = self.get_reboot_list_ips() + new_ips
        all_right = sorted(set(all_right), key=ip_sort_key)
        self.reboot_table.setRowCount(0)
        for ip in all_right:
            row_r = self.reboot_table.rowCount()
            self.reboot_table.insertRow(row_r)
            self.reboot_table.setItem(row_r, 0, QTableWidgetItem(ip))
            self.reboot_table.setItem(row_r, 1, QTableWidgetItem(""))
            self.reboot_table.setItem(row_r, 2, QTableWidgetItem(""))

    def remove_from_reboot_list(self):
        selected_rows = sorted(set([i.row() for i in self.reboot_table.selectedIndexes()]), reverse=True)
        readd = []
        for row in selected_rows:
            ip = self.reboot_table.item(row, 0).text()
            if ip not in self.all_ip_list:
                readd.append(ip)
            self.reboot_table.removeRow(row)
        self.all_ip_list.extend(readd)
        self.all_ip_list = sorted(set(self.all_ip_list), key=ip_sort_key)
        self.update_ip_table()
        # 右側排序
        all_right = self.get_reboot_list_ips()
        all_right = sorted(set(all_right), key=ip_sort_key)
        self.reboot_table.setRowCount(0)
        for ip in all_right:
            row_r = self.reboot_table.rowCount()
            self.reboot_table.insertRow(row_r)
            self.reboot_table.setItem(row_r, 0, QTableWidgetItem(ip))
            self.reboot_table.setItem(row_r, 1, QTableWidgetItem(""))
            self.reboot_table.setItem(row_r, 2, QTableWidgetItem(""))

    def exec_reboot(self):
        total = self.reboot_table.rowCount()
        if total == 0:
            QMessageBox.information(self, "提示", "請先加入欲重啟的設備！")
            return
        self.btn_reboot.setEnabled(False)
        self.btn_cancel.setEnabled(True)
        self.progress.setValue(0)
        self.stop_flag.clear()
        for row in range(self.reboot_table.rowCount()):
            self.reboot_table.setItem(row, 1, QTableWidgetItem(""))
            self.reboot_table.setItem(row, 2, QTableWidgetItem(""))
        ip_list = [self.reboot_table.item(i, 0).text() for i in range(self.reboot_table.rowCount())]
        self.thread = AsyncRebootThread(ip_list, self.signalbus, self.stop_flag)
        self.thread.start()

    def cancel_exec(self):
        self.stop_flag.set()
        self.btn_cancel.setEnabled(False)

    def clear_all_data(self):
        self.all_ip_list = []
        self.update_ip_table()
        self.reboot_table.setRowCount(0)
        self.progress.setValue(0)

    def _update_result_table(self, idx, status, msg):
        self.reboot_table.setItem(idx, 1, QTableWidgetItem(status))
        self.reboot_table.setItem(idx, 2, QTableWidgetItem(msg))

    def _update_progress(self, current, total):
        value = int(current * 100 / total) if total else 0
        self.progress.setValue(value)

    def _on_finish(self):
        self.btn_reboot.setEnabled(True)
        self.btn_cancel.setEnabled(False)
        # ====== 自動分類排序，成功排最前，其它失敗/異常/取消排後 ======
        success = []
        failed = []
        for row in range(self.reboot_table.rowCount()):
            ip = self.reboot_table.item(row, 0).text()
            status = self.reboot_table.item(row, 1).text()
            errmsg = self.reboot_table.item(row, 2).text()
            row_data = (ip, status, errmsg)
            if status == "成功":
                success.append(row_data)
            else:
                failed.append(row_data)
        # 清空表格，依分類重新插入
        self.reboot_table.setRowCount(0)
        for row_data in success + failed:
            row_idx = self.reboot_table.rowCount()
            self.reboot_table.insertRow(row_idx)
            for col, val in enumerate(row_data):
                item = QTableWidgetItem(val)
                if row_data[1] == "成功":
                    item.setForeground(Qt.blue)
                elif row_data[1] not in ["", "成功"]:
                    item.setForeground(Qt.red)
                self.reboot_table.setItem(row_idx, col, item)
        QMessageBox.information(self, "完成", "重啟流程已結束。")

    def export_result(self):
        if self.reboot_table.rowCount() == 0:
            QMessageBox.information(self, "提示", "目前沒有任何紀錄可匯出。")
            return
        path, _ = QFileDialog.getSaveFileName(self, "儲存執行紀錄", "", "Excel Files (*.xlsx)")
        if not path:
            return
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "重啟紀錄"
        ws.append(["IP", "重啟狀態", "錯誤碼/訊息"])
        for row in range(self.reboot_table.rowCount()):
            ws.append([
                self.reboot_table.item(row, 0).text(),
                self.reboot_table.item(row, 1).text() if self.reboot_table.item(row, 1) else "",
                self.reboot_table.item(row, 2).text() if self.reboot_table.item(row, 2) else ""
            ])
        try:
            wb.save(path)
            QMessageBox.information(self, "完成", f"已匯出至 {path}")
        except Exception as e:
            QMessageBox.warning(self, "錯誤", f"匯出失敗：{e}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    pwd_dialog = PasswordDialog()
    if pwd_dialog.exec_() == 1 and pwd_dialog.result:
        window = RebootGUI()
        window.show()
        sys.exit(app.exec_())
    else:
        sys.exit(0)
