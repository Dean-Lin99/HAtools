import sys
import os
import asyncio
import hashlib
import datetime
import re
import threading

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
        '255.255.255.255', '255.255.255.0', '255.0.0.0', '0.0.0.0', '127.0.0.1', '255.255.248.0', '224.0.0.1', '192.168.200.3', '255.255.224.0'
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

        self.all_ip_list = []  # [{"name":..., "devtype":..., "ip":...}, ...]
        self.stop_flag = threading.Event()
        self.thread = None
        self.signalbus = SignalBus()
        self.filtered_ip_list = []  # 用於搜尋結果

        self.init_ui()
        self.signalbus.update_result_signal.connect(self._update_result_table)
        self.signalbus.progress_signal.connect(self._update_progress)
        self.signalbus.finish_signal.connect(self._on_finish)

    def center_window(self):
        frame_geom = self.frameGeometry()
        screen = QApplication.primaryScreen()
        if screen:
            center_point = screen.availableGeometry().center()
            frame_geom.moveCenter(center_point)
            self.move(frame_geom.topLeft())

    def init_ui(self):
        main_layout = QHBoxLayout()
        left_layout = QVBoxLayout()
        right_layout = QVBoxLayout()

        # --- 左：搜尋 + 已匯入IP ---
        search_layout = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("模糊搜尋設備類型、名稱、IP")
        self.search_input.textChanged.connect(self.on_search_changed)
        search_layout.addWidget(QLabel("搜尋："))
        search_layout.addWidget(self.search_input)
        left_layout.addLayout(search_layout)

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

        self.ip_table = QTableWidget(0, 3)
        self.ip_table.setHorizontalHeaderLabels(["設備類型", "名稱", "IP"])
        self.ip_table.setSelectionBehavior(self.ip_table.SelectRows)
        self.ip_table.setSelectionMode(self.ip_table.MultiSelection)
        left_layout.addWidget(QLabel("已匯入設備清單"))
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
        self.reboot_table = QTableWidget(0, 5)
        self.reboot_table.setHorizontalHeaderLabels(["設備類型", "名稱", "IP", "重啟狀態", "錯誤碼/訊息"])
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

    def on_search_changed(self, text):
        text = text.strip().lower()
        if not text:
            self.filtered_ip_list = self.all_ip_list.copy()
        else:
            self.filtered_ip_list = [
                info for info in self.all_ip_list
                if text in info.get("devtype", "").lower()
                or text in info.get("name", "").lower()
                or text in info.get("ip", "").lower()
            ]
        self.update_ip_table(filtered=True)

    def add_ip(self):
        ip = self.ip_input.text().strip()
        exist_ips = [x["ip"] for x in self.all_ip_list] + self.get_reboot_list_ips()
        if is_ipv4(ip) and ip not in exist_ips:
            self.all_ip_list.append({"name": "", "devtype": "", "ip": ip})
            self.all_ip_list.sort(key=lambda x: ip_sort_key(x["ip"]))
            self.filtered_ip_list = self.all_ip_list.copy()
            self.update_ip_table(filtered=True)
        self.ip_input.clear()

    def import_excel(self):
        path, _ = QFileDialog.getOpenFileName(self, "選擇Excel檔", "", "Excel Files (*.xlsx *.xls)")
        if not path:
            return
        try:
            all_sheets = pd.read_excel(path, header=None, dtype=str, sheet_name=None)
            target_df = None
            use_full_info = False
            # 找貼紙印製 sheet
            for sheet_name, df in all_sheets.items():
                if "貼紙印製" in sheet_name:
                    target_df = df
                    use_full_info = True
                    break
            if target_df is None:
                # 沒有「貼紙印製」時抓第一個 sheet
                target_df = list(all_sheets.values())[0]
                use_full_info = False

            # 收集資料
            ip_set = set(x["ip"] for x in self.all_ip_list)  # 現有IP，避免重覆
            result_list = []
            if use_full_info:
                # 依照每一列自動找 IP，抓左邊兩格
                for i, row in target_df.iterrows():
                    row = list(row)
                    for idx in range(len(row)):
                        cell = str(row[idx]).strip() if not pd.isna(row[idx]) else ""
                        if is_ipv4(cell):
                            ip = cell
                            name = str(row[idx - 1]).strip() if idx - 1 >= 0 else ""
                            devtype = str(row[idx - 2]).strip() if idx - 2 >= 0 else ""
                            if ip not in ip_set:
                                result_list.append({"name": name, "devtype": devtype, "ip": ip})
                                ip_set.add(ip)
                            break   # 每列只抓一組IP
            else:
                flat_list = target_df.values.flatten()
                for cell in flat_list:
                    if pd.isna(cell):
                        continue
                    ip = str(cell).strip()
                    if is_ipv4(ip) and ip not in ip_set:
                        result_list.append({"name": "", "devtype": "", "ip": ip})
                        ip_set.add(ip)

            self.all_ip_list.extend(result_list)
            self.all_ip_list = sorted(self.all_ip_list, key=lambda x: ip_sort_key(x["ip"]))
            self.filtered_ip_list = self.all_ip_list.copy()
            self.update_ip_table(filtered=True)
        except Exception as e:
            QMessageBox.warning(self, "匯入錯誤", f"Excel匯入失敗：{e}")

    def update_ip_table(self, filtered=False):
        # 三欄：設備類型、名稱、IP
        target_list = self.filtered_ip_list if filtered else self.all_ip_list
        self.ip_table.setColumnCount(3)
        self.ip_table.setHorizontalHeaderLabels(["設備類型", "名稱", "IP"])
        self.ip_table.setRowCount(0)
        for info in target_list:
            row = self.ip_table.rowCount()
            self.ip_table.insertRow(row)
            self.ip_table.setItem(row, 0, QTableWidgetItem(info.get("devtype", "")))
            self.ip_table.setItem(row, 1, QTableWidgetItem(info.get("name", "")))
            self.ip_table.setItem(row, 2, QTableWidgetItem(info.get("ip", "")))

    def get_reboot_list_ips(self):
        return [self.reboot_table.item(i, 2).text() for i in range(self.reboot_table.rowCount())]

    def add_to_reboot_list(self):
        # 只針對目前顯示（搜尋後的）做選取
        selected_rows = sorted(set([i.row() for i in self.ip_table.selectedIndexes()]), reverse=True)
        new_infos = []
        target_list = self.filtered_ip_list
        for row in selected_rows:
            info = target_list[row]
            if info["ip"] not in self.get_reboot_list_ips():
                new_infos.append(info)
            # 從 all_ip_list 刪除對應
            for idx, item in enumerate(self.all_ip_list):
                if item["ip"] == info["ip"]:
                    del self.all_ip_list[idx]
                    break
        self.all_ip_list = sorted(self.all_ip_list, key=lambda x: ip_sort_key(x["ip"]))
        self.filtered_ip_list = self.all_ip_list.copy()
        self.update_ip_table(filtered=True)
        # 排序右側
        all_right = [self._get_row_info(self.reboot_table, i) for i in range(self.reboot_table.rowCount())] + new_infos
        # 移除重複IP，只保留第一個
        seen_ip = set()
        result = []
        for info in all_right:
            if info["ip"] not in seen_ip:
                seen_ip.add(info["ip"])
                result.append(info)
        result = sorted(result, key=lambda x: ip_sort_key(x["ip"]))
        self.reboot_table.setRowCount(0)
        for info in result:
            row_r = self.reboot_table.rowCount()
            self.reboot_table.insertRow(row_r)
            self.reboot_table.setItem(row_r, 0, QTableWidgetItem(info.get("devtype", "")))
            self.reboot_table.setItem(row_r, 1, QTableWidgetItem(info.get("name", "")))
            self.reboot_table.setItem(row_r, 2, QTableWidgetItem(info.get("ip", "")))
            self.reboot_table.setItem(row_r, 3, QTableWidgetItem(""))
            self.reboot_table.setItem(row_r, 4, QTableWidgetItem(""))

    def _get_row_info(self, table, row):
        # 從 table 取出三欄資訊
        return {
            "devtype": table.item(row, 0).text() if table.item(row, 0) else "",
            "name": table.item(row, 1).text() if table.item(row, 1) else "",
            "ip": table.item(row, 2).text() if table.item(row, 2) else ""
        }

    def remove_from_reboot_list(self):
        selected_rows = sorted(set([i.row() for i in self.reboot_table.selectedIndexes()]), reverse=True)
        readd = []
        for row in selected_rows:
            info = self._get_row_info(self.reboot_table, row)
            if info["ip"] not in [x["ip"] for x in self.all_ip_list]:
                readd.append(info)
            self.reboot_table.removeRow(row)
        self.all_ip_list.extend(readd)
        self.all_ip_list = sorted(self.all_ip_list, key=lambda x: ip_sort_key(x["ip"]))
        self.filtered_ip_list = self.all_ip_list.copy()
        self.update_ip_table(filtered=True)
        # 右側排序
        all_right = [self._get_row_info(self.reboot_table, i) for i in range(self.reboot_table.rowCount())]
        seen_ip = set()
        result = []
        for info in all_right:
            if info["ip"] not in seen_ip:
                seen_ip.add(info["ip"])
                result.append(info)
        result = sorted(result, key=lambda x: ip_sort_key(x["ip"]))
        self.reboot_table.setRowCount(0)
        for info in result:
            row_r = self.reboot_table.rowCount()
            self.reboot_table.insertRow(row_r)
            self.reboot_table.setItem(row_r, 0, QTableWidgetItem(info.get("devtype", "")))
            self.reboot_table.setItem(row_r, 1, QTableWidgetItem(info.get("name", "")))
            self.reboot_table.setItem(row_r, 2, QTableWidgetItem(info.get("ip", "")))
            self.reboot_table.setItem(row_r, 3, QTableWidgetItem(""))
            self.reboot_table.setItem(row_r, 4, QTableWidgetItem(""))

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
            self.reboot_table.setItem(row, 3, QTableWidgetItem(""))
            self.reboot_table.setItem(row, 4, QTableWidgetItem(""))
        ip_list = [self.reboot_table.item(i, 2).text() for i in range(self.reboot_table.rowCount())]
        self.thread = AsyncRebootThread(ip_list, self.signalbus, self.stop_flag)
        self.thread.start()

    def cancel_exec(self):
        self.stop_flag.set()
        self.btn_cancel.setEnabled(False)

    def clear_all_data(self):
        self.all_ip_list = []
        self.filtered_ip_list = []
        self.update_ip_table(filtered=True)
        self.reboot_table.setRowCount(0)
        self.progress.setValue(0)

    def _update_result_table(self, idx, status, msg):
        self.reboot_table.setItem(idx, 3, QTableWidgetItem(status))
        self.reboot_table.setItem(idx, 4, QTableWidgetItem(msg))

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
            devtype = self.reboot_table.item(row, 0).text()
            name = self.reboot_table.item(row, 1).text()
            ip = self.reboot_table.item(row, 2).text()
            status = self.reboot_table.item(row, 3).text()
            errmsg = self.reboot_table.item(row, 4).text()
            row_data = (devtype, name, ip, status, errmsg)
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
                if row_data[3] == "成功":
                    item.setForeground(Qt.blue)
                elif row_data[3] not in ["", "成功"]:
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
        ws.append(["設備類型", "名稱", "IP", "重啟狀態", "錯誤碼/訊息"])
        for row in range(self.reboot_table.rowCount()):
            ws.append([
                self.reboot_table.item(row, 0).text(),
                self.reboot_table.item(row, 1).text(),
                self.reboot_table.item(row, 2).text(),
                self.reboot_table.item(row, 3).text() if self.reboot_table.item(row, 3) else "",
                self.reboot_table.item(row, 4).text() if self.reboot_table.item(row, 4) else ""
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
