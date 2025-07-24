import sys
import os
import threading
import datetime
import requests
from openpyxl import Workbook
import ctypes

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QComboBox, QTableWidget, QTableWidgetItem,
    QFileDialog, QMessageBox, QHeaderView
)
from PyQt5.QtGui import QIcon, QColor
from PyQt5.QtCore import Qt, QTimer, pyqtSignal

from scapy.all import sniff, ARP
import psutil

OUI_LIST = ["5895D8", "000246"]
DEVICE_PORTS = [3377, 80, 8080]

def resource_path(filename):
    if hasattr(sys, "_MEIPASS"):
        return os.path.join(sys._MEIPASS, filename)
    return os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), filename)

def check_npcap_installed():
    try:
        import winreg
    except ImportError:
        return False
    reg_paths = [
        r"SOFTWARE\Npcap",
        r"SOFTWARE\WOW6432Node\Npcap",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WinPcapInst",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\WinPcapInst",
    ]
    found = False
    for root in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
        for path in reg_paths:
            try:
                with winreg.OpenKey(root, path):
                    found = True
                    break
            except Exception:
                pass
        if found:
            break
    return found

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

class ARPMonitorApp(QWidget):
    add_row_signal = pyqtSignal(str, str, str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("HA_IP搜尋工具_V2.0_By Dean")
        self.resize(750, 480)
        self.setWindowIcon(QIcon(resource_path("tonnet_icon.ico")))

        self.iface_mapping = self.get_interface_mapping()
        self.seen_mac = set()
        self.sniffing = False
        self.sniffer_thread = None
        self.sniffer_stop_event = threading.Event()

        main_layout = QVBoxLayout()

        hbox_iface = QHBoxLayout()
        hbox_iface.addWidget(QLabel("選擇網卡："))
        self.iface_combo = QComboBox()
        self.iface_combo.addItems(list(self.iface_mapping.keys()))
        hbox_iface.addWidget(self.iface_combo)
        hbox_iface.addStretch()
        main_layout.addLayout(hbox_iface)

        hbox_btn = QHBoxLayout()
        self.start_btn = QPushButton("開始檢查")
        self.stop_btn = QPushButton("停止")
        self.clear_btn = QPushButton("清除資料")
        self.export_btn = QPushButton("匯出資料")
        self.stop_btn.setEnabled(False)
        hbox_btn.addWidget(self.start_btn)
        hbox_btn.addWidget(self.stop_btn)
        hbox_btn.addWidget(self.clear_btn)
        hbox_btn.addWidget(self.export_btn)
        hbox_btn.addStretch()
        main_layout.addLayout(hbox_btn)

        self.device_count_label = QLabel("目前偵測到設備數量：0")
        main_layout.addWidget(self.device_count_label)

        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["型號", "IP", "MAC"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        main_layout.addWidget(self.table)

        self.setLayout(main_layout)

        self.start_btn.clicked.connect(self.start_sniffing)
        self.stop_btn.clicked.connect(self.stop_sniffing)
        self.clear_btn.clicked.connect(self.clear_data)
        self.export_btn.clicked.connect(self.export_excel)
        self.iface_combo.currentIndexChanged.connect(self.interface_changed)
        self.add_row_signal.connect(self.append_row)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_device_count)

    def get_interface_mapping(self):
        mapping = {}
        for nic, addrs in psutil.net_if_addrs().items():
            desc = nic
            for addr in addrs:
                if getattr(addr, 'family', None).name == 'AF_LINK':
                    mapping[f"{desc} ({nic})"] = nic
        return mapping

    def update_device_count(self):
        self.device_count_label.setText(f"目前偵測到設備數量：{len(self.seen_mac)}")

    def handle_arp(self, pkt):
        if ARP in pkt and pkt[ARP].op == 1:
            src_ip = pkt[ARP].psrc
            raw_mac = pkt[ARP].hwsrc.upper()
            mac_no_colon = raw_mac.replace(":", "")
            oui = mac_no_colon[:6]
            # 增加 MAC 為全 0 也查詢 device info
            if (oui in OUI_LIST) or (mac_no_colon == "000000000000"):
                if raw_mac not in self.seen_mac:
                    self.seen_mac.add(raw_mac)
                    threading.Thread(target=self.query_and_add_device, args=(src_ip, raw_mac), daemon=True).start()

    def query_and_add_device(self, ip, mac):
        model, real_ip, real_mac = self.query_device_info(ip, mac)
        if not model:
            model = "未知/無回應"
        if not real_ip:
            real_ip = ip
        if not real_mac:
            real_mac = mac
        self.add_row_signal.emit(model, real_ip, real_mac)

    def query_device_info(self, ip, mac):
        for port in DEVICE_PORTS:
            url = f"http://{ip}:{port}/device/info"
            try:
                resp = requests.get(url, timeout=2)
                if resp.ok:
                    data = resp.json()
                    return (
                        data.get("dev_model", ""),
                        data.get("dev_ip", ip),
                        data.get("dev_mac", mac)
                    )
            except Exception as e:
                continue
        return None, None, None

    def append_row(self, model, ip, mac):
        ip = ip.split(':')[0]
        mac = mac.upper()
        row = self.table.rowCount()
        self.table.insertRow(row)
        item_model = QTableWidgetItem(model)
        item_ip = QTableWidgetItem(ip)
        item_mac = QTableWidgetItem(mac)

        mac_no_colon = mac.replace(":", "")
        # 紅色條件：OUI為0、後6碼為0、或全為0
        if (mac_no_colon[:6] == "000000") or (mac_no_colon[-6:] == "000000") or (mac_no_colon == "000000000000"):
            for item in [item_model, item_ip, item_mac]:
                item.setForeground(QColor("red"))

        self.table.setItem(row, 0, item_model)
        self.table.setItem(row, 1, item_ip)
        self.table.setItem(row, 2, item_mac)
        self.update_device_count()

    def sniff_arp(self, iface):
        self.sniffing = True
        self.sniffer_stop_event.clear()
        try:
            sniff(
                filter="arp",
                prn=self.handle_arp,
                store=0,
                iface=iface,
                stop_filter=lambda _: (not self.sniffing) or self.sniffer_stop_event.is_set()
            )
        except Exception as e:
            import traceback
            error_detail = traceback.format_exc()
            QMessageBox.critical(self, "錯誤", f"封包監聽失敗：\n{e}\n{error_detail}")
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)

    def start_sniffing(self):
        if self.sniffing:
            self.stop_sniffing()
        display_name = self.iface_combo.currentText()
        if not display_name:
            QMessageBox.critical(self, "錯誤", "請選擇一張網卡！")
            return
        iface = self.iface_mapping[display_name]
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.seen_mac.clear()
        self.table.setRowCount(0)
        self.update_device_count()
        self.sniffer_thread = threading.Thread(target=self.sniff_arp, args=(iface,), daemon=True)
        self.sniffer_thread.start()
        self.timer.start(1000)

    def stop_sniffing(self):
        self.sniffing = False
        self.sniffer_stop_event.set()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.timer.stop()
        if self.sniffer_thread is not None and self.sniffer_thread.is_alive():
            self.sniffer_thread.join(timeout=1)

    def interface_changed(self):
        self.stop_sniffing()
        self.start_sniffing()

    def clear_data(self):
        self.seen_mac.clear()
        self.table.setRowCount(0)
        self.update_device_count()

    def export_excel(self):
        if self.table.rowCount() == 0:
            QMessageBox.information(self, "匯出", "目前沒有資料可匯出。")
            return
        default_name = f"Devices_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        path, _ = QFileDialog.getSaveFileName(
            self, "儲存 Excel", default_name, "Excel 檔案 (*.xlsx)"
        )
        if path:
            wb = Workbook()
            ws = wb.active
            ws.append(["型號", "IP", "MAC"])
            for row in range(self.table.rowCount()):
                items = [self.table.item(row, col).text() for col in range(self.table.columnCount())]
                ws.append(items)
            wb.save(path)
            QMessageBox.information(self, "成功", "資料已成功匯出為 Excel 檔案！")

if __name__ == "__main__":
    app = QApplication(sys.argv)

    if not check_npcap_installed():
        QMessageBox.critical(None, "缺少元件", "本程式需安裝 Npcap (或 WinPcap) 才能使用！\n\n請至 https://nmap.org/npcap/ 下載安裝後再執行。")
        sys.exit()

    if not is_admin():
        ret = QMessageBox.question(None, "權限不足", "建議用「系統管理員」身份執行本程式。\n\n是否要繼續執行？", QMessageBox.Yes | QMessageBox.No)
        if ret == QMessageBox.No:
            sys.exit()

    window = ARPMonitorApp()
    window.show()
    sys.exit(app.exec_())
