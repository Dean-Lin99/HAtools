# -*- coding: utf-8 -*-
"""
RS-485 撥號 GUI（支援 9600,N,8,1 與十六進位顯示）
- 九宮格：1~9 / ✔️撥號 / 0 / ⌫退格
- 模式：逐鍵送出 或 整串送出
- A4：數字鍵入；A5：掛斷；Checksum = 所有位元組加總的低 8-bit
- 監聽接收：以十六進位顯示
- 手動 HEX 送出（輸入 "EE A4 01 ..." 或 "eea401..." 皆可）
"""

import sys
import time
from typing import List

from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QGridLayout, QHBoxLayout,
    QPushButton, QLineEdit, QLabel, QComboBox, QCheckBox, QPlainTextEdit,
    QMessageBox, QSizePolicy, QGroupBox
)

# ----- serial -----
try:
    import serial
    from serial.tools import list_ports
    HAS_SERIAL = True
except Exception:
    HAS_SERIAL = False
    serial = None
    list_ports = None

# ---------------- 協議 ----------------
def checksum8(bs: List[int]) -> int:
    return (sum(bs) & 0xFF)

def ascii_digits_to_bytes(digits: str) -> List[int]:
    for ch in digits:
        if ch < '0' or ch > '9':
            raise ValueError(f"僅允許 0~9，發現: {repr(ch)}")
    return [ord(c) for c in digits]

def mk_a4_digits(digits: str, addr: int) -> bytes:
    n = len(digits)
    data = [0xEE, 0xA4, addr, 6 + n, n]
    data += ascii_digits_to_bytes(digits)
    data.append(checksum8(data))
    return bytes(data)

def mk_a5_hangup(addr: int) -> bytes:
    data = [0xEE, 0xA5, addr, 0x05]
    data.append(checksum8(data))
    return bytes(data)

def hex_join(b: bytes) -> str:
    return " ".join(f"{x:02X}" for x in b)

def parse_hex_string(s: str) -> bytes:
    """
    將使用者輸入的 HEX 字串轉 bytes
    可接受：
      "EE A4 01 07 01 30 CB"
      "eea401070130cb"
      "EE-A4-01-07-01-30-CB"
    """
    s = s.strip().replace("-", " ").replace("_", " ")
    if " " not in s and all(ch in "0123456789abcdefABCDEF" for ch in s) and len(s) % 2 == 0:
        # 連續的十六進位
        return bytes.fromhex(s)
    # 有分隔
    parts = s.split()
    vals = []
    for p in parts:
        p = p.strip()
        if p.startswith("0x") or p.startswith("0X"):
            p = p[2:]
        if not p:
            continue
        vals.append(int(p, 16) & 0xFF)
    return bytes(vals)

# ---------------- Serial Reader Thread ----------------
class SerialReader(QThread):
    recv = pyqtSignal(bytes)
    info = pyqtSignal(str)

    def __init__(self, ser):
        super().__init__()
        self._ser = ser
        self._running = True

    def run(self):
        self.info.emit("接收執行緒啟動。")
        try:
            while self._running:
                if self._ser is None:
                    break
                n = self._ser.in_waiting if self._ser else 0
                if n:
                    data = self._ser.read(n)
                    if data:
                        self.recv.emit(data)
                else:
                    self.msleep(10)
        except Exception as e:
            self.info.emit(f"接收執行緒錯誤：{e}")
        self.info.emit("接收執行緒結束。")

    def stop(self):
        self._running = False

# ---------------- Main Window ----------------
class Dial485Window(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("RS-485 撥號鍵盤（Hex 顯示）")
        self.resize(900, 640)

        self.ser = None
        self.reader = None

        # ===== 連線區 =====
        conn_box = QGroupBox("連線設定")
        conn_l = QHBoxLayout(conn_box)

        self.port_combo = QComboBox()
        self.refresh_ports_btn = QPushButton("重新掃描")
        self.refresh_ports_btn.clicked.connect(self.refresh_ports)

        self.baud_combo = QComboBox()
        for b in [9600, 19200, 38400, 57600, 115200]:
            self.baud_combo.addItem(str(b))
        self.baud_combo.setCurrentText("9600")  # AccessPort 預設 9600

        self.databits_combo = QComboBox()
        for d in [5, 6, 7, 8]:
            self.databits_combo.addItem(str(d))
        self.databits_combo.setCurrentText("8")

        self.parity_combo = QComboBox()
        self.parity_combo.addItems(["NONE", "EVEN", "ODD"])

        self.stopbits_combo = QComboBox()
        self.stopbits_combo.addItems(["1", "1.5", "2"])
        self.stopbits_combo.setCurrentText("1")

        self.addr_edit = QLineEdit("01")
        self.addr_edit.setFixedWidth(48)
        self.addr_edit.setToolTip("位址（十六進位）")

        self.connect_btn = QPushButton("連線")
        self.connect_btn.setCheckable(True)
        self.connect_btn.clicked.connect(self.on_toggle_connect)

        conn_l.addWidget(QLabel("埠："))
        conn_l.addWidget(self.port_combo, 2)
        conn_l.addWidget(self.refresh_ports_btn)
        conn_l.addSpacing(10)
        conn_l.addWidget(QLabel("鮑率："))
        conn_l.addWidget(self.baud_combo)
        conn_l.addSpacing(10)
        conn_l.addWidget(QLabel("資料位元："))
        conn_l.addWidget(self.databits_combo)
        conn_l.addSpacing(10)
        conn_l.addWidget(QLabel("同位："))
        conn_l.addWidget(self.parity_combo)
        conn_l.addSpacing(10)
        conn_l.addWidget(QLabel("停止位元："))
        conn_l.addWidget(self.stopbits_combo)
        conn_l.addSpacing(10)
        conn_l.addWidget(QLabel("位址："))
        conn_l.addWidget(self.addr_edit)
        conn_l.addSpacing(10)
        conn_l.addWidget(self.connect_btn)

        # ===== 撥號鍵盤 =====
        dial_box = QGroupBox("撥號")
        grid = QGridLayout(dial_box)
        grid.setSpacing(10)

        self.display = QLineEdit()
        self.display.setPlaceholderText("輸入號碼…（僅 0-9）")
        self.display.setAlignment(Qt.AlignRight)
        self.display.setStyleSheet("font-size: 20px;")
        self.display.textEdited.connect(self.on_text_digits_edited)
        grid.addWidget(self.display, 0, 0, 1, 3)

        self.mode_step_chk = QCheckBox("逐鍵送出")
        self.mode_step_chk.setChecked(True)
        grid.addWidget(self.mode_step_chk, 1, 0, 1, 1)

        clear_btn = QPushButton("🧹 全清")
        clear_btn.clicked.connect(lambda: self.display.setText(""))
        grid.addWidget(clear_btn, 1, 2, 1, 1)

        # 1~9
        positions = [
            (2,0,"1"), (2,1,"2"), (2,2,"3"),
            (3,0,"4"), (3,1,"5"), (3,2,"6"),
            (4,0,"7"), (4,1,"8"), (4,2,"9")
        ]
        for r,c,t in positions:
            b = self.mk_digit_btn(t)
            grid.addWidget(b, r, c)

        call_btn = QPushButton("✔️ 撥號")
        call_btn.clicked.connect(self.on_call)
        call_btn.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        call_btn.setStyleSheet("font-size: 18px; padding: 12px;")

        zero_btn = self.mk_digit_btn("0")

        back_btn = QPushButton("⌫ 退格")
        back_btn.clicked.connect(self.on_backspace)
        back_btn.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        back_btn.setStyleSheet("font-size: 18px; padding: 12px;")

        grid.addWidget(call_btn, 5, 0)
        grid.addWidget(zero_btn, 5, 1)
        grid.addWidget(back_btn, 5, 2)

        # 掛斷
        hang_box = QHBoxLayout()
        hang_btn = QPushButton("📴 掛斷 (A5)")
        hang_btn.clicked.connect(self.on_hangup)
        hang_box.addWidget(hang_btn)
        grid.addLayout(hang_box, 6, 0, 1, 3)

        # ===== 手動 HEX 送出 =====
        hex_box = QGroupBox("手動 HEX 送出")
        hex_l = QHBoxLayout(hex_box)
        self.hex_edit = QLineEdit()
        self.hex_edit.setPlaceholderText("例：EE A4 01 07 01 30 CB 或 eea401070130cb")
        send_hex_btn = QPushButton("送出 HEX")
        send_hex_btn.clicked.connect(self.on_send_hex)
        hex_l.addWidget(self.hex_edit, 4)
        hex_l.addWidget(send_hex_btn, 1)

        # ===== 接收/Log =====
        rx_box = QGroupBox("接收（十六進位）")
        rx_l = QVBoxLayout(rx_box)
        self.rx_view = QPlainTextEdit()
        self.rx_view.setReadOnly(True)
        self.rx_view.setStyleSheet("font-family: Consolas, monospace;")
        rx_l.addWidget(self.rx_view)

        log_box = QGroupBox("事件與送出 Log")
        log_l = QVBoxLayout(log_box)
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setStyleSheet("font-family: Consolas, monospace;")
        log_l.addWidget(self.log)

        # ===== 版面 =====
        left = QVBoxLayout()
        left.addWidget(conn_box)
        left.addWidget(dial_box)
        left.addWidget(hex_box)

        right = QVBoxLayout()
        right.addWidget(rx_box, 3)
        right.addWidget(log_box, 2)

        root = QWidget()
        main = QHBoxLayout(root)
        main.addLayout(left, 5)
        main.addLayout(right, 7)

        self.setCentralWidget(root)

        # 初始列出埠
        self.refresh_ports()

    # ---------- UI helpers ----------
    def mk_digit_btn(self, d: str) -> QPushButton:
        b = QPushButton(d)
        b.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        b.setStyleSheet("font-size: 22px; padding: 12px;")
        b.clicked.connect(lambda: self.on_digit(d))
        return b

    def log_append(self, text: str):
        ts = time.strftime("%H:%M:%S")
        self.log.appendPlainText(f"[{ts}] {text}")

    def rx_append(self, b: bytes):
        if not b:
            return
        self.rx_view.appendPlainText(hex_join(b))

    # ---------- Input behaviors ----------
    def on_text_digits_edited(self, s: str):
        filtered = ''.join(ch for ch in s if '0' <= ch <= '9')
        if filtered != s:
            cur = self.display.cursorPosition()
            self.display.blockSignals(True)
            self.display.setText(filtered)
            self.display.blockSignals(False)
            self.display.setCursorPosition(min(cur, len(filtered)))

    def on_digit(self, d: str):
        self.display.insert(d)
        if self.mode_step_chk.isChecked():
            try:
                frame = mk_a4_digits(d, addr=self.get_addr())
                self.send_bytes(frame)
            except Exception as e:
                self.log_append(f"逐鍵送出失敗：{e}")

    def on_backspace(self):
        t = self.display.text()
        if t:
            self.display.setText(t[:-1])

    def on_call(self):
        digits = self.display.text().strip()
        if not digits:
            self.log_append("撥號：目前沒有號碼。")
            return
        if not self.mode_step_chk.isChecked():
            try:
                frame = mk_a4_digits(digits, addr=self.get_addr())
                self.send_bytes(frame)
            except Exception as e:
                self.log_append(f"撥號送出失敗：{e}")
        else:
            self.log_append("撥號：逐鍵模式，已逐鍵送出。")

    def on_hangup(self):
        try:
            frame = mk_a5_hangup(addr=self.get_addr())
            self.send_bytes(frame)
        except Exception as e:
            self.log_append(f"掛斷失敗：{e}")

    def on_send_hex(self):
        s = self.hex_edit.text().strip()
        if not s:
            return
        try:
            b = parse_hex_string(s)
            if not b:
                self.log_append("HEX 空字串。")
                return
            self.send_bytes(b, prefix="HEX")
        except Exception as e:
            QMessageBox.warning(self, "HEX 格式錯誤", f"解析失敗：{e}")

    # ---------- Serial ----------
    def refresh_ports(self):
        self.port_combo.clear()
        if HAS_SERIAL:
            ports = list(list_ports.comports())
            if not ports:
                self.port_combo.addItem("(找不到可用序列埠)")
            for p in ports:
                self.port_combo.addItem(p.device)
        else:
            self.port_combo.addItem("(未安裝 pyserial)")
            self.port_combo.setEnabled(False)

    def get_addr(self) -> int:
        s = self.addr_edit.text().strip()
        if not s:
            self.addr_edit.setText("01")
            return 0x01
        try:
            v = int(s, 16)
            if 0 <= v <= 0xFF:
                return v
        except Exception:
            pass
        QMessageBox.warning(self, "位址錯誤", "位址請輸入 00~FF（十六進位）。已改回 01。")
        self.addr_edit.setText("01")
        return 0x01

    def on_toggle_connect(self, checked: bool):
        if not HAS_SERIAL:
            QMessageBox.information(self, "序列埠", "未安裝 pyserial，無法連線。")
            self.connect_btn.setChecked(False)
            return
        if checked:
            port = self.port_combo.currentText().strip()
            if not port or port.startswith("("):
                QMessageBox.warning(self, "序列埠", "請選擇有效的序列埠。")
                self.connect_btn.setChecked(False)
                return
            baud = int(self.baud_combo.currentText())
            databits = int(self.databits_combo.currentText())
            parity_s = self.parity_combo.currentText()
            stop_s = self.stopbits_combo.currentText()

            # map to pyserial
            bytesize_map = {5: serial.FIVEBITS, 6: serial.SIXBITS, 7: serial.SEVENBITS, 8: serial.EIGHTBITS}
            parity_map = {"NONE": serial.PARITY_NONE, "EVEN": serial.PARITY_EVEN, "ODD": serial.PARITY_ODD}
            stop_map = {"1": serial.STOPBITS_ONE, "1.5": serial.STOPBITS_ONE_POINT_FIVE, "2": serial.STOPBITS_TWO}

            try:
                self.ser = serial.Serial(
                    port=port,
                    baudrate=baud,
                    bytesize=bytesize_map[databits],
                    parity=parity_map[parity_s],
                    stopbits=stop_map[stop_s],
                    timeout=0.05,
                    write_timeout=0.5
                )
                self.log_append(f"已連線 {port} @ {baud},{parity_s},{databits},{stop_s}")
                self.connect_btn.setText("中斷")
                # 啟動接收
                self.reader = SerialReader(self.ser)
                self.reader.recv.connect(self.on_serial_recv)
                self.reader.info.connect(self.log_append)
                self.reader.start()
            except Exception as e:
                self.log_append(f"連線失敗：{e}")
                self.connect_btn.setChecked(False)
        else:
            self.close_serial()

    def on_serial_recv(self, b: bytes):
        self.rx_append(b)

    def send_bytes(self, b: bytes, prefix: str = "送出"):
        if not HAS_SERIAL or self.ser is None or not self.ser.is_open:
            self.log_append(f"(未連線) {prefix}：{hex_join(b)}")
            return
        try:
            self.ser.write(b)
            self.ser.flush()
            self.log_append(f"{prefix}：{hex_join(b)}")
        except Exception as e:
            self.log_append(f"{prefix}失敗：{e}")

    def close_serial(self):
        if self.reader:
            try:
                self.reader.stop()
                self.reader.wait(500)
            except Exception:
                pass
            self.reader = None
        if self.ser:
            try:
                p = self.ser.port
                self.ser.close()
                self.log_append(f"已中斷 {p}")
            except Exception as e:
                self.log_append(f"中斷錯誤：{e}")
        self.ser = None
        self.connect_btn.setText("連線")
        self.connect_btn.setChecked(False)

    # ---------- window events ----------
    def closeEvent(self, event):
        self.close_serial()
        super().closeEvent(event)

# ---------------- main ----------------
def main():
    app = QApplication(sys.argv)
    w = Dial485Window()
    w.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
