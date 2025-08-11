import sys
import json
import requests
from datetime import datetime

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QTextEdit, QPushButton, QMessageBox, QCheckBox, QComboBox
)
from PyQt5.QtCore import Qt

HELP_JSON = '''{
  "public": [
    {"type":"voip","name":"大門口機","url":"sip:920101@192.168.200.51:5060"},
    {"type":"voip","name":"大門口機1","url":"sip:12@192.168.200.20:5060"}
  ],
  "private": [
    {"type":"voip","name":"46號03樓小門口機1","url":"sip:460304@192.168.200.193:5060"}
  ]
}'''

class MonitorDebugger(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Monitor API 除錯工具")
        self.resize(820, 700)

        root = QVBoxLayout()

        # 目標 IP 與 Path
        row1 = QHBoxLayout()
        row1.addWidget(QLabel("設備 IP:"))
        self.ip = QLineEdit()
        self.ip.setPlaceholderText("例如：192.168.200.190")
        row1.addWidget(self.ip)

        row1.addWidget(QLabel("路徑:"))
        self.path = QLineEdit("/monitor")
        row1.addWidget(self.path)

        root.addLayout(row1)

        # 方法 / Content-Type / Raw開關 / Timeout
        row2 = QHBoxLayout()
        self.method = QComboBox()
        self.method.addItems(["POST", "GET"])
        row2.addWidget(QLabel("方法:"))
        row2.addWidget(self.method)

        self.chk_raw = QCheckBox("以原始本文送出（不自動加 Content-Type，無 JSON 轉換）")
        row2.addWidget(self.chk_raw)

        row2.addWidget(QLabel("Content-Type:"))
        self.ct = QComboBox()
        self.ct.addItems([
            "application/json",
            "text/plain",
            "application/octet-stream",
            "(不指定)"
        ])
        row2.addWidget(self.ct)

        row2.addWidget(QLabel("逾時(s):"))
        self.timeout = QLineEdit("5")
        self.timeout.setFixedWidth(60)
        row2.addWidget(self.timeout)

        row2.addStretch()
        root.addLayout(row2)

        # JSON/Body
        root.addWidget(QLabel("請求本文（POST 才會送）："))
        self.body = QTextEdit()
        self.body.setPlainText(HELP_JSON)
        root.addWidget(self.body, stretch=2)

        # 操作列
        row3 = QHBoxLayout()
        self.btn_post = QPushButton("送出 ▶")
        self.btn_post.clicked.connect(self.on_send)
        row3.addWidget(self.btn_post)

        self.btn_get_monitor = QPushButton("嘗試回讀 GET /monitor")
        self.btn_get_monitor.clicked.connect(self.on_get_monitor)
        row3.addWidget(self.btn_get_monitor)

        self.btn_get_info = QPushButton("GET /device/info")
        self.btn_get_info.clicked.connect(self.on_get_device_info)
        row3.addWidget(self.btn_get_info)

        self.btn_quick_flow = QPushButton("一鍵：POST /monitor → GET /monitor")
        self.btn_quick_flow.clicked.connect(self.on_quick_flow)
        row3.addStretch()
        root.addLayout(row3)

        # 結果視窗
        root.addWidget(QLabel("請求/回應紀錄："))
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        root.addWidget(self.log, stretch=3)

        self.setLayout(root)

    def logln(self, text=""):
        now = datetime.now().strftime("%H:%M:%S")
        self.log.append(f"[{now}] {text}")

    def build_url(self):
        ip = self.ip.text().strip()
        path = self.path.text().strip() or "/monitor"
        if not ip:
            raise ValueError("請輸入設備 IP")
        if not path.startswith("/"):
            path = "/" + path
        return f"http://{ip}:3377{path}"

    def current_timeout(self):
        t = self.timeout.text().strip()
        try:
            return float(t) if t else 5.0
        except:
            return 5.0

    def on_send(self):
        try:
            url = self.build_url()
        except Exception as e:
            QMessageBox.warning(self, "錯誤", str(e))
            return

        method = self.method.currentText()
        use_raw = self.chk_raw.isChecked()
        ct_sel = self.ct.currentText()
        timeout = self.current_timeout()

        headers = {}
        data = None
        json_payload = None

        # Content-Type 邏輯
        if ct_sel != "(不指定)":
            headers["Content-Type"] = ct_sel

        # 準備本文
        body_text = self.body.toPlainText()

        if method == "POST":
            if use_raw:
                # 原樣送出
                data = body_text.encode("utf-8")
            else:
                # 走 JSON 模式（requests 會自加 Content-Type: application/json）
                try:
                    json_payload = json.loads(body_text) if body_text.strip() else {}
                except json.JSONDecodeError as e:
                    QMessageBox.warning(self, "JSON 格式錯誤", str(e))
                    return

        # 顯示請求
        self.logln(f"➡ {method} {url}")
        if headers:
            self.logln(f"Request Headers: {headers}")
        if method == "POST":
            preview = body_text if len(body_text) < 2000 else (body_text[:2000] + "...(截斷)")
            self.logln(f"Request Body ({'raw' if use_raw else 'json'}):\n{preview}")

        # 發送
        try:
            if method == "GET":
                resp = requests.get(url, headers=headers, timeout=timeout)
            else:
                if use_raw:
                    resp = requests.post(url, headers=headers, data=data, timeout=timeout)
                else:
                    resp = requests.post(url, headers=headers, json=json_payload, timeout=timeout)
        except Exception as e:
            self.logln(f"❌ 請求失敗：{e}")
            QMessageBox.critical(self, "請求失敗", str(e))
            return

        # 顯示回應
        self.logln(f"⬅ 狀態碼: {resp.status_code}")
        self.logln(f"Response Headers: {dict(resp.headers)}")
        text = resp.text
        preview = text if len(text) < 5000 else (text[:5000] + "...(截斷)")
        self.logln(f"Response Body:\n{preview}\n")

        # 額外提示
        if resp.status_code == 200 and method == "POST" and not resp.text.strip():
            self.logln("提示：200 但空回應，設備可能僅表示『已接收』，未必『已套用』。可嘗試 GET /monitor 回讀或重啟/重新載入。")

    def on_get_monitor(self):
        # 嘗試讀回 /monitor（若設備不支援，會 404/405）
        old_path = self.path.text()
        self.path.setText("/monitor")
        self.method.setCurrentText("GET")
        self.on_send()
        self.path.setText(old_path)

    def on_get_device_info(self):
        old_path = self.path.text()
        self.path.setText("/device/info")
        self.method.setCurrentText("GET")
        self.on_send()
        self.path.setText(old_path)

    def on_quick_flow(self):
        # 先 POST /monitor，再 GET /monitor
        old_method = self.method.currentText()
        old_path = self.path.text()

        try:
            self.path.setText("/monitor")
            self.method.setCurrentText("POST")
            self.on_send()

            self.method.setCurrentText("GET")
            self.on_send()
        finally:
            self.method.setCurrentText(old_method)
            self.path.setText(old_path)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    w = MonitorDebugger()
    w.show()
    sys.exit(app.exec_())
