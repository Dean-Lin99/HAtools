import sys
import os
import pandas as pd
import requests
import ipaddress
import hashlib
import datetime
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QFileDialog, QLineEdit, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView, QCheckBox,
    QMessageBox, QAbstractItemView, QProgressBar
)
from PyQt5.QtCore import Qt, QThreadPool, QRunnable, pyqtSlot, QObject, pyqtSignal, QTimer
from PyQt5.QtGui import QIcon
import threading

DEVICE_PORT = 3377
ALT_DEVICE_PORT = 8080
MAX_THREADS = 100

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
            if not self.isRowHidden(row):
                cb = self.cellWidget(row, 0)
                cb.setChecked(checked)

class ResultTable(QTableWidget):
    def __init__(self, parent=None):
        super().__init__(0, 4, parent)
        self.setHorizontalHeaderLabels(['型號', '名稱', 'IP', '執行結果'])
        self.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.device_ip_row_map = {}

    def setup_results(self, devices):
        self.setRowCount(0)
        self.device_ip_row_map = {}
        for dev in devices:
            row = self.rowCount()
            self.insertRow(row)
            self.setItem(row, 0, QTableWidgetItem(str(dev.get('model', ''))))
            self.setItem(row, 1, QTableWidgetItem(str(dev.get('name', ''))))
            self.setItem(row, 2, QTableWidgetItem(str(dev['ip'])))
            self.setItem(row, 3, QTableWidgetItem("待處理"))
            self.device_ip_row_map[dev['ip']] = row

    def update_result(self, ip, result):
        row = self.device_ip_row_map.get(ip, None)
        if row is not None:
            self.setItem(row, 3, QTableWidgetItem(result))

    def clear_results(self):
        self.setRowCount(0)
        self.device_ip_row_map = {}

class TaskSignals(QObject):
    result = pyqtSignal(str, bool, str)  # ip, success, info

class ConfigRunnable(QRunnable):
    def __init__(self, dev, server_ip, signals, stop_flag):
        super().__init__()
        self.dev = dev
        self.server_ip = server_ip
        self.signals = signals
        self.stop_flag = stop_flag

    @pyqtSlot()
    def run(self):
        ip = self.dev['ip']
        if self.stop_flag.is_set():
            self.signals.result.emit(ip, False, "已中止")
            return
        last_fail = ""
        for port in [DEVICE_PORT, ALT_DEVICE_PORT]:
            url = f"http://{ip}:{port}/set/server"
            data = {"url": f"http://{self.server_ip}:8000"}
            try:
                r = requests.post(url, json=data, timeout=3)
                if r.status_code == 200:
                    self.signals.result.emit(ip, True, "成功")
                    return
                else:
                    last_fail = f"失敗({r.status_code}) {r.text.strip()}"
            except requests.exceptions.Timeout:
                last_fail = "失敗(Timeout)"
            except requests.exceptions.ConnectionError:
                last_fail = "失敗(連線錯誤)"
            except Exception as e:
                last_fail = f"失敗({type(e).__name__})"
        self.signals.result.emit(ip, False, last_fail)

class RebootRunnable(QRunnable):
    def __init__(self, dev, signals, stop_flag):
        super().__init__()
        self.dev = dev
        self.signals = signals
        self.stop_flag = stop_flag

    @pyqtSlot()
    def run(self):
        ip = self.dev['ip']
        if self.stop_flag.is_set():
            self.signals.result.emit(ip, False, "已中止")
            return
        last_fail = ""
        for port in [DEVICE_PORT, ALT_DEVICE_PORT]:
            try:
                try:
                    url_info = f"http://{ip}:{port}/device/info"
                    r_info = requests.get(url_info, timeout=3)
                    if r_info.status_code == 200:
                        data = r_info.json()
                        room_id = data.get("room_id", "") or data.get("data", {}).get("room_id", "")
                    else:
                        continue
                except Exception:
                    continue

                try:
                    url_time = f"http://{ip}:{port}/time"
                    r_time = requests.get(url_time, timeout=3)
                    if r_time.status_code == 200:
                        data = r_time.json()
                        device_time = data.get("time", "")
                        if not device_time:
                            raise Exception
                    else:
                        raise Exception
                except Exception:
                    now = datetime.datetime.now()
                    device_time = now.strftime('%Y-%m-%dT%H:%M:%S+08:00')

                try:
                    dt = device_time.split("+")[0]
                    dt_obj = datetime.datetime.strptime(dt, "%Y-%m-%dT%H:%M:%S")
                    ymd = dt_obj.strftime('%Y%m%d')
                    hms = dt_obj.strftime('%H%M%S')
                    text = f"remote{ymd}{room_id}{hms}".lower()
                    token = hashlib.md5(text.encode('utf-8')).hexdigest()
                except Exception:
                    continue

                reboot_url = f"http://{ip}:{port}/remote/reboot"
                payload = {
                    "token": token,
                    "room": room_id,
                    "time": device_time
                }
                try:
                    r2 = requests.post(reboot_url, json=payload, timeout=5)
                    if r2.status_code == 200:
                        self.signals.result.emit(ip, True, "成功")
                        return
                    else:
                        last_fail = f"失敗({r2.status_code}) {r2.text.strip()}"
                except requests.exceptions.Timeout:
                    last_fail = "失敗(Timeout)"
                except requests.exceptions.ConnectionError:
                    last_fail = "失敗(連線錯誤)"
                except Exception as e2:
                    last_fail = f"失敗({type(e2).__name__})"
            except Exception as e:
                last_fail = f"失敗({type(e).__name__})"
        self.signals.result.emit(ip, False, last_fail)

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ICMP_Server_設定工具_V1.0_By Dean")
        self.resize(950, 700)
        icon_path = get_icon_path()
        self.setWindowIcon(QIcon(icon_path))
        self.devices = []
        self.threadpool = QThreadPool()
        self.threadpool.setMaxThreadCount(MAX_THREADS)
        self.stop_flag = threading.Event()
        self.working = False
        self.current_count = 0
        self.total_count = 0
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

        self.table = DeviceTable()
        layout.addWidget(self.table)

        self.result_table = ResultTable()
        layout.addWidget(QLabel("設備執行結果"))
        layout.addWidget(self.result_table)

        pb_hbox = QHBoxLayout()
        self.progress = QProgressBar()
        self.progress.setValue(0)
        self.progress.setVisible(False)
        pb_hbox.addWidget(self.progress)
        self.stop_btn = QPushButton("停止執行")
        self.stop_btn.setEnabled(False)
        self.stop_btn.setVisible(True)
        self.stop_btn.clicked.connect(self.stop_worker)
        pb_hbox.addWidget(self.stop_btn)
        layout.addLayout(pb_hbox)

        server_hbox = QHBoxLayout()
        server_hbox.addWidget(QLabel("Server IP:"))
        self.server_ip_edit = QLineEdit()
        self.server_ip_edit.setPlaceholderText("後台 Server IP，例如 192.168.200.3")
        server_hbox.addWidget(self.server_ip_edit)
        self.send_btn = QPushButton("發送設定")
        self.send_btn.clicked.connect(self.start_send_config)
        server_hbox.addWidget(self.send_btn)
        self.reboot_btn = QPushButton("重新啟動")
        self.reboot_btn.clicked.connect(self.start_batch_reboot)
        server_hbox.addWidget(self.reboot_btn)
        layout.addLayout(server_hbox)

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
            self.result_table.clear_results()
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
        self.result_table.clear_results()
        self.manual_ip_edit.clear()
        self.status_label.setText("手動新增成功")

    def search_devices(self):
        keyword = self.search_edit.text()
        self.table.filter(keyword)

    def start_send_config(self):
        if self.working:
            QMessageBox.warning(self, "任務進行中", "請先停止目前任務")
            return
        server_ip = self.server_ip_edit.text().strip()
        if not is_valid_ip(server_ip):
            QMessageBox.warning(self, "格式錯誤", "請輸入正確的 Server IP")
            return
        selected = self.table.get_selected_devices()
        if not selected:
            QMessageBox.warning(self, "未選取", "請至少選取一台設備")
            return
        self.result_table.clear_results()
        self.result_table.setup_results(selected)
        self.start_batch_task('config', selected, server_ip)

    def start_batch_reboot(self):
        if self.working:
            QMessageBox.warning(self, "任務進行中", "請先停止目前任務")
            return
        selected = self.table.get_selected_devices()
        if not selected:
            QMessageBox.warning(self, "未選取", "請至少選取一台設備")
            return
        self.result_table.clear_results()
        self.result_table.setup_results(selected)
        self.start_batch_task('reboot', selected, None)

    def start_batch_task(self, action, devices, server_ip):
        self.progress.setMaximum(len(devices))
        self.progress.setValue(0)
        self.progress.setVisible(True)
        self.stop_btn.setEnabled(True)
        self.status_label.setText("開始執行...")
        self.current_count = 0
        self.total_count = len(devices)
        self.working = True
        self.stop_flag.clear()
        for dev in devices:
            signals = TaskSignals()
            signals.result.connect(self.on_task_result)
            if action == 'config':
                runnable = ConfigRunnable(dev, server_ip, signals, self.stop_flag)
            elif action == 'reboot':
                runnable = RebootRunnable(dev, signals, self.stop_flag)
            self.threadpool.start(runnable)

    @pyqtSlot(str, bool, str)
    def on_task_result(self, ip, success, info):
        self.current_count += 1
        self.progress.setValue(self.current_count)
        self.result_table.update_result(ip, info)
        self.status_label.setText(f"進度：{self.current_count}/{self.total_count}")
        if self.current_count >= self.total_count:
            self.finish_task()

    def finish_task(self):
        # 任何還沒收到訊號的設備，補上失敗
        for ip, row in self.result_table.device_ip_row_map.items():
            cell = self.result_table.item(row, 3)
            if not cell or not cell.text().strip() or cell.text().strip() == "待處理":
                self.result_table.setItem(row, 3, QTableWidgetItem("失敗(離線/逾時)"))
        self.working = False
        self.progress.setVisible(False)
        self.stop_btn.setEnabled(False)
        self.status_label.setText("執行完成。")

    def stop_worker(self):
        if self.working:
            self.stop_flag.set()
            self.status_label.setText("停止要求已送出，正在等待線程結束...")
            self.stop_btn.setEnabled(False)
            timer = QTimer(self)
            def check_done():
                if self.current_count >= self.total_count:
                    timer.stop()
                    self.finish_task()
            timer.timeout.connect(check_done)
            timer.start(200)
            self.working = False

    def clear_all_data(self):
        self.devices = []
        self.table.load_devices([])
        self.result_table.clear_results()
        self.manual_ip_edit.clear()
        self.search_edit.clear()
        self.server_ip_edit.clear()
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
