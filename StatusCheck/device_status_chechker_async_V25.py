import sys
import os
import asyncio
import aiohttp
import ipaddress
import pandas as pd
from datetime import datetime
import warnings
warnings.filterwarnings("ignore", category=RuntimeWarning)

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QFileDialog, QMessageBox, QTableWidget, QTableWidgetItem,
    QLabel, QProgressBar, QCheckBox, QLineEdit
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, pyqtSlot
from PyQt5.QtGui import QIcon, QIntValidator

# --- 支援打包後/開發直接執行的 icon 資源路徑 ---
def resource_path(relative_path):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), relative_path)
# ------------------------------------------------

class DeviceCheckThread(QThread):
    progress_signal = pyqtSignal(int, int)
    result_signal = pyqtSignal(dict)
    done_signal = pyqtSignal(int)

    def __init__(self, rows):
        super().__init__()
        self.rows = rows
        self._is_running = True
        self._task_list = []

    def stop(self):
        self._is_running = False

    async def fetch_device_info(self, session, ip):
        for port in [8080, 80, 3377]:
            try:
                async with session.get(f"http://{ip}:{port}/device/info", timeout=1) as r:
                    if r.status == 200 and r.headers.get("Content-Type", "").startswith("application/json"):
                        return await r.json()
            except:
                continue
        return None

    async def check_single_device(self, session, row, ip_set, mac_set):
        if not self._is_running:
            return None
        index = row.get("index", "")
        type_ = row.get("type", "")
        name, ip = row["name"], row["ip"]
        status = "❌ 離線"
        dev_name = software = dev_model = dev_mac = ""
        info = await self.fetch_device_info(session, ip)
        if info:
            dev_name = info.get("dev_name", "")
            software = info.get("software", "")
            dev_model = info.get("dev_model", "")
            dev_mac = info.get("dev_mac", "")
            issues = []
            if str(name).strip() != str(dev_name).strip(): issues.append("設定異常")
            if ip in ip_set: issues.append("IP 重複")
            if dev_mac in mac_set and dev_mac: issues.append("MAC 重複")
            status = "✅ 正常" if not issues else "⚠️ " + "、".join(issues)
        else:
            status = "❌ 離線"
        ip_set.add(ip)
        if dev_mac: mac_set.add(dev_mac)
        return {
            "index": index,
            "type": type_,
            "name": name,
            "ip": ip,
            "狀態": status,
            "dev_name": dev_name,
            "software": software,
            "dev_model": dev_model,
            "dev_mac": dev_mac
        }

    async def check_devices_async(self):
        ip_set = set()
        mac_set = set()
        finished = 0
        sem = asyncio.Semaphore(100)
        self._task_list = []

        async def sem_check(row):
            if not self._is_running:
                return None
            async with sem:
                return await self.check_single_device(session, row, ip_set, mac_set)

        async with aiohttp.ClientSession() as session:
            for row in self.rows:
                task = asyncio.create_task(sem_check(row))
                self._task_list.append(task)
            try:
                for coro in asyncio.as_completed(self._task_list):
                    if not self._is_running:
                        break
                    result = await coro
                    if result is None:
                        continue
                    if result['ip'] == '192.168.200.254' and result['狀態'] == '❌ 離線':
                        continue
                    finished += 1
                    self.result_signal.emit(result)
                    self.progress_signal.emit(finished, len(self.rows)-1)
            finally:
                if not self._is_running:
                    for task in self._task_list:
                        if not task.done():
                            task.cancel()
                    await asyncio.gather(*self._task_list, return_exceptions=True)
        self.done_signal.emit(finished)

    def run(self):
        asyncio.run(self.check_devices_async())

class DeviceCheckerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        icon_path = resource_path("tonnet_icon.ico")
        print("icon 路徑:", icon_path, "存在？", os.path.exists(icon_path))
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))
        self.setWindowTitle("設備狀況收集工具_V1.0_By Dean")
        self.resize(1350, 840)

        self.original_data = pd.DataFrame()
        self.results = []
        self.result_map = {}
        self.only_show_abnormal = False
        self.only_show_normal = False
        self.check_thread = None
        self.search_text = ""

        self.init_ui()

    def init_ui(self):
        main_widget = QWidget()
        main_layout = QVBoxLayout(main_widget)

        # 搜尋列
        search_layout = QHBoxLayout()
        lbl_search = QLabel("搜尋：")
        self.le_search = QLineEdit()
        self.le_search.setPlaceholderText("可輸入設備類型、名稱、IP（模糊搜尋）")
        self.le_search.textChanged.connect(self.on_search_text_changed)
        btn_clear_search = QPushButton("清除")
        btn_clear_search.setFixedWidth(48)
        btn_clear_search.clicked.connect(self.le_search.clear)
        search_layout.addWidget(lbl_search)
        search_layout.addWidget(self.le_search)
        search_layout.addWidget(btn_clear_search)
        main_layout.addLayout(search_layout)

        # 按鈕區
        btn_layout = QHBoxLayout()
        btn_import = QPushButton("匯入 Excel")
        btn_import.clicked.connect(self.load_excel)

        self.btn_check = QPushButton("開始檢查")
        self.btn_check.clicked.connect(self.start_check)
        self.btn_stop = QPushButton("停止檢查")
        self.btn_stop.clicked.connect(self.stop_check)
        self.btn_stop.setEnabled(False)

        btn_clear = QPushButton("清除資料")
        btn_clear.clicked.connect(self.clear_data)
        btn_export = QPushButton("匯出報表")
        btn_export.clicked.connect(self.export_results)
        self.cb_abnormal = QCheckBox("僅顯示異常")
        self.cb_normal = QCheckBox("僅顯示正常")
        self.cb_abnormal.stateChanged.connect(self.on_abnormal_toggle)
        self.cb_normal.stateChanged.connect(self.on_normal_toggle)

        self.le_start = QLineEdit()
        self.le_start.setValidator(QIntValidator(1, 100000))
        self.le_start.setFixedWidth(60)
        self.le_end = QLineEdit()
        self.le_end.setValidator(QIntValidator(1, 100000))
        self.le_end.setFixedWidth(60)
        btn_clear_range = QPushButton("清除")
        btn_clear_range.setFixedWidth(48)
        btn_clear_range.clicked.connect(self.clear_range_fields)
        lbl_range = QLabel("區間檢查：從第")
        lbl_to = QLabel("到第")
        lbl_row = QLabel("行")
        self.btn_range_check = QPushButton("區間檢查")
        self.btn_range_check.clicked.connect(self.start_partial_check)

        btn_layout.addWidget(btn_import)
        btn_layout.addWidget(self.btn_check)
        btn_layout.addWidget(self.btn_stop)
        btn_layout.addWidget(btn_clear)
        btn_layout.addWidget(btn_export)
        btn_layout.addWidget(self.cb_abnormal)
        btn_layout.addWidget(self.cb_normal)
        btn_layout.addStretch()
        btn_layout.addWidget(lbl_range)
        btn_layout.addWidget(self.le_start)
        btn_layout.addWidget(lbl_to)
        btn_layout.addWidget(self.le_end)
        btn_layout.addWidget(lbl_row)
        btn_layout.addWidget(self.btn_range_check)
        btn_layout.addWidget(btn_clear_range)

        main_layout.addLayout(btn_layout)

        self.status_label = QLabel("匯入後開始檢查")
        main_layout.addWidget(self.status_label)

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        main_layout.addWidget(self.progress_bar)

        self.top_table = QTableWidget(0, 3)
        self.top_table.setHorizontalHeaderLabels(["設備類型", "出貨設備名稱", "IP"])
        self.top_table.verticalHeader().setVisible(True)
        main_layout.addWidget(QLabel("原始設備資料"))
        main_layout.addWidget(self.top_table)

        self.result_table = QTableWidget(0, 8)
        self.result_table.setHorizontalHeaderLabels([
            "設備類型", "出貨設備名稱", "IP", "狀態", "現場設備名稱", "軟體版本", "型號", "MAC"
        ])
        self.result_table.verticalHeader().setVisible(True)
        main_layout.addWidget(QLabel("現場設備狀況"))
        main_layout.addWidget(self.result_table)

        self.setCentralWidget(main_widget)

    def clear_range_fields(self):
        self.le_start.clear()
        self.le_end.clear()

    def stop_check(self):
        if self.check_thread is not None and self.check_thread.isRunning():
            self.check_thread.stop()
            self.status_label.setText("檢查已停止")
        else:
            self.status_label.setText("無檢查進行中")
        self.btn_stop.setEnabled(False)
        self.btn_check.setEnabled(True)
        self.btn_range_check.setEnabled(True)

    def is_valid_ip(self, s, name=""):
        try:
            ipstr = str(s).strip()
            name = str(name).lower()
            for badword in ["mask", "掩碼", "gateway", "網關", "gw", "router", "default gateway"]:
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

    def find_ip_name_type_column(self, df):
        for i in range(2, len(df.columns)):
            type_col = df.iloc[:, i - 2]
            name_col = df.iloc[:, i - 1]
            ip_col = df.iloc[:, i]
            valid_count = 0
            for dev_type, name, ip in zip(type_col, name_col, ip_col):
                if self.is_valid_ip(ip, name=name):
                    valid_count += 1
            if valid_count > 5:
                return pd.DataFrame({
                    "type": type_col,
                    "name": name_col,
                    "ip": ip_col
                })
        return pd.DataFrame()

    def load_excel(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "選擇 Excel 檔", "", "Excel Files (*.xlsx *.xls)")
        if not file_path:
            return
        xls = pd.ExcelFile(file_path)
        sheet = "貼紙印製" if "貼紙印製" in xls.sheet_names else xls.sheet_names[0]
        df_raw = pd.read_excel(file_path, sheet_name=sheet, header=None)
        df = self.find_ip_name_type_column(df_raw)
        if df.empty:
            QMessageBox.critical(self, "錯誤", "無法辨識設備資料，請確認欄位格式")
            return
        df = df[~df['type'].astype(str).str.replace(' ', '', regex=False).str.contains('管理中心')]
        df['ip'] = df['ip'].astype(str).str.strip()
        df = df[[self.is_valid_ip(row["ip"], row["name"]) for _, row in df.iterrows()]]
        df = df.reset_index(drop=True)
        df.insert(0, "index", range(1, len(df)+1))
        self.original_data = df[['index', 'type', 'name', 'ip']]
        self.status_label.setText(f"共匯入 {len(df)} 筆設備資料")
        self.results = []
        self.result_map = {}
        self.update_top_table()
        self.result_table.setRowCount(0)
        self.progress_bar.setValue(0)

    def update_top_table(self):
        df = self.get_filtered_top_data()
        self.top_table.setRowCount(len(df))
        for row_idx, row in df.iterrows():
            self.top_table.setItem(row_idx, 0, QTableWidgetItem(str(row["type"])))
            self.top_table.setItem(row_idx, 1, QTableWidgetItem(str(row["name"])))
            self.top_table.setItem(row_idx, 2, QTableWidgetItem(str(row["ip"])))
        self.top_table.resizeColumnsToContents()

    def get_filtered_top_data(self):
        if self.search_text.strip() and not self.original_data.empty:
            cond = self.original_data.apply(
                lambda r: self.search_text.lower() in str(r["type"]).lower()
                          or self.search_text.lower() in str(r["name"]).lower()
                          or self.search_text.lower() in str(r["ip"]).lower(),
                axis=1
            )
            return self.original_data[cond].reset_index(drop=True)
        else:
            return self.original_data

    def on_abnormal_toggle(self, state):
        if state:
            self.cb_normal.setChecked(False)
            self.only_show_abnormal = True
        else:
            self.only_show_abnormal = False
        self.update_result_table()

    def on_normal_toggle(self, state):
        if state:
            self.cb_abnormal.setChecked(False)
            self.only_show_normal = True
        else:
            self.only_show_normal = False
        self.update_result_table()

    def on_search_text_changed(self, text):
        self.search_text = text
        self.update_top_table()
        self.update_result_table()

    def update_result_table(self):
        filtered = []
        for r in self.results:
            show = True
            if self.only_show_abnormal:
                show = r["狀態"].startswith("⚠️") or r["狀態"].startswith("❌")
            elif self.only_show_normal:
                show = r["狀態"].startswith("✅")
            if show:
                filtered.append(r)
        if self.search_text.strip():
            text = self.search_text.lower()
            filtered = [r for r in filtered if
                        text in str(r.get("type", "")).lower()
                        or text in str(r["name"]).lower()
                        or text in str(r["ip"]).lower()]
        factory_rows = [r for r in filtered if r["ip"] == "192.168.200.254"]
        other_rows = [r for r in filtered if r["ip"] != "192.168.200.254"]
        other_rows = sorted(other_rows, key=lambda x: int(x.get("index", 999999)))
        sorted_filtered = factory_rows + other_rows
        self.result_table.setRowCount(len(sorted_filtered))
        for i, r in enumerate(sorted_filtered):
            self.result_table.setItem(i, 0, QTableWidgetItem(str(r.get("type", ""))))
            self.result_table.setItem(i, 1, QTableWidgetItem(str(r["name"])))
            self.result_table.setItem(i, 2, QTableWidgetItem(str(r["ip"])))
            self.result_table.setItem(i, 3, QTableWidgetItem(str(r["狀態"])))
            self.result_table.setItem(i, 4, QTableWidgetItem(str(r["dev_name"])))
            self.result_table.setItem(i, 5, QTableWidgetItem(str(r["software"])))
            self.result_table.setItem(i, 6, QTableWidgetItem(str(r["dev_model"])))
            self.result_table.setItem(i, 7, QTableWidgetItem(str(r["dev_mac"])))
        self.result_table.resizeColumnsToContents()

    def clear_data(self):
        self.original_data = pd.DataFrame()
        self.results = []
        self.result_map = {}
        self.top_table.setRowCount(0)
        self.result_table.setRowCount(0)
        self.status_label.setText("資料已清除")
        self.progress_bar.setValue(0)
        self.le_search.clear()
        self.le_start.clear()
        self.le_end.clear()
        self.btn_stop.setEnabled(False)
        self.btn_check.setEnabled(True)
        self.btn_range_check.setEnabled(True)

    def export_results(self):
        if not self.results:
            QMessageBox.warning(self, "提示", "無檢查結果可匯出")
            return
        now = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"檢查結果_{now}.xlsx"
        file_path, _ = QFileDialog.getSaveFileName(self, "匯出結果", default_filename, "Excel Files (*.xlsx)")
        if file_path:
            key_columns = ["type", "name", "ip", "狀態", "dev_name", "software", "dev_model", "dev_mac"]
            display_columns = ["設備類型", "出貨設備名稱", "ip", "狀態", "現場設備名稱", "軟體版本", "型號", "MAC"]
            factory_rows = [r for r in self.results if r["ip"] == "192.168.200.254"]
            other_rows = [r for r in self.results if r["ip"] != "192.168.200.254"]
            other_rows = sorted(other_rows, key=lambda x: int(x.get("index", 999999)))
            sorted_results = factory_rows + other_rows
            if self.search_text.strip():
                text = self.search_text.lower()
                sorted_results = [r for r in sorted_results if
                                 text in str(r.get("type", "")).lower()
                                 or text in str(r["name"]).lower()
                                 or text in str(r["ip"]).lower()]
            df = pd.DataFrame(sorted_results)[key_columns]
            df.columns = display_columns
            df.to_excel(file_path, index=False)
            QMessageBox.information(self, "完成", f"已匯出：{file_path}")

    def start_check(self):
        if self.original_data.empty:
            QMessageBox.warning(self, "提示", "請先匯入設備資料")
            return
        df = self.get_filtered_top_data()
        if df.empty:
            QMessageBox.warning(self, "提示", "找不到符合搜尋條件的設備")
            return
        self.stop_check()
        rows = list(df.to_dict(orient="records")) + [
            {"index": 0, "type": "", "name": "原廠IP設備", "ip": "192.168.200.254"}
        ]
        self.run_check(rows=rows)
        self.btn_check.setEnabled(False)
        self.btn_range_check.setEnabled(False)
        self.btn_stop.setEnabled(True)

    def start_partial_check(self):
        if self.original_data.empty:
            QMessageBox.warning(self, "提示", "請先匯入設備資料")
            return
        try:
            start = int(self.le_start.text())
            end = int(self.le_end.text())
        except ValueError:
            QMessageBox.warning(self, "提示", "請正確輸入區間行號")
            return
        if not (1 <= start <= end <= len(self.original_data)):
            QMessageBox.warning(self, "提示", f"行號範圍需為 1~{len(self.original_data)}，且開始<=結束")
            return
        self.stop_check()
        partial = self.original_data.iloc[start-1:end]
        rows = list(partial.to_dict(orient="records")) + [
            {"index": 0, "type": "", "name": "原廠IP設備", "ip": "192.168.200.254"}
        ]
        self.run_check(rows=rows)
        self.btn_check.setEnabled(False)
        self.btn_range_check.setEnabled(False)
        self.btn_stop.setEnabled(True)

    def run_check(self, rows):
        self.results = []
        self.result_map = {}
        self.result_table.setRowCount(0)
        self.progress_bar.setValue(0)
        self.check_thread = DeviceCheckThread(rows)
        self.check_thread.progress_signal.connect(self.update_progress)
        self.check_thread.result_signal.connect(self.add_result)
        self.check_thread.done_signal.connect(self.finish_check)
        self.check_thread.start()
        self.status_label.setText("檢查中...")

    @pyqtSlot(int, int)
    def update_progress(self, cur, total):
        percent = int(cur / total * 100) if total > 0 else 0
        self.progress_bar.setValue(percent)
        self.status_label.setText(f"檢查中：{cur}/{total} ({percent}%)")

    @pyqtSlot(dict)
    def add_result(self, result):
        if result is None:
            return
        key = (result.get("index", None), result["name"], result["ip"])
        self.result_map[key] = result
        self.results = list(self.result_map.values())
        self.update_result_table()

    @pyqtSlot(int)
    def finish_check(self, count):
        if self.check_thread and not self.check_thread._is_running:
            self.status_label.setText("檢查已停止")
        else:
            self.status_label.setText(f"檢查完成，共 {count} 筆")
        self.progress_bar.setValue(100)
        self.update_result_table()
        self.btn_check.setEnabled(True)
        self.btn_range_check.setEnabled(True)
        self.btn_stop.setEnabled(False)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = DeviceCheckerApp()
    window.show()
    sys.exit(app.exec_())
