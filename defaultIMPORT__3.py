# device_updater_gui.py
# -*- coding: utf-8 -*-

import sys
import os
import re
import ipaddress
import pandas as pd
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QFileDialog, QLineEdit, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView, QCheckBox,
    QMessageBox, QAbstractItemView
)
from PySide6.QtCore import Qt

# ========== 匯入 Excel 的工具 ==========
def is_nullish(v) -> bool:
    if v is None:
        return True
    s = str(v).strip()
    return s == "" or s.lower() in ("nan", "none")

def is_valid_ip(s):
    try:
        ipstr = str(s).replace(" ", "").strip()
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
        valid = sum(1 for cell in df.iloc[:, col] if is_valid_ip(cell))
        if valid >= 2:
            return col
    return None

def is_first_column_serial(col, min_length=5):
    numbers = []
    for val in col:
        if is_nullish(val):
            numbers.append(None)
            continue
        try:
            numbers.append(int(str(val).strip()))
        except:
            numbers.append(None)
    max_streak = 0
    streak = 0
    prev = None
    for n in numbers:
        if n is not None and (prev is None or n == prev + 1):
            streak += 1
        else:
            streak = 1 if n is not None else 0
        prev = n
        max_streak = max(max_streak, streak)
    return max_streak >= min_length

def extract_room_no_from_row(row, type_col_idx, skip_first_col=False):
    parts = []
    for i in range(type_col_idx):
        if skip_first_col and i == 0:
            continue
        val = row[i]
        if is_nullish(val):
            continue
        s = str(val).strip()
        if re.fullmatch(r"\d+", s):
            parts.append(s)
    return "".join(parts)

def process_one_sheet(df_raw):
    ip_col_idx = find_ip_col_index(df_raw)
    if ip_col_idx is None or ip_col_idx < 2:
        return None
    devtype_col_idx = ip_col_idx - 2
    name_col_idx = ip_col_idx - 1

    skip_first = False
    if df_raw.shape[1] > 0:
        try:
            skip_first = is_first_column_serial(df_raw.iloc[:, 0], min_length=5)
        except Exception:
            skip_first = False

    devices = []
    for _, row in df_raw.iterrows():
        ip_raw = row[ip_col_idx] if ip_col_idx < len(row) else ""
        ip = "" if is_nullish(ip_raw) else str(ip_raw).replace(" ", "").strip()
        if not is_valid_ip(ip):
            continue

        dev_type_raw = row[devtype_col_idx] if devtype_col_idx >= 0 else ""
        dev_type = "" if is_nullish(dev_type_raw) else str(dev_type_raw).strip()
        if "管理中心" in dev_type:
            continue

        name_raw = row[name_col_idx] if name_col_idx >= 0 else ""
        name = "" if is_nullish(name_raw) else str(name_raw).strip()

        room_no = extract_room_no_from_row(row, devtype_col_idx, skip_first)
        devices.append({
            "設備類型": dev_type,
            "名稱": name,
            "IP": ip,
            "房號": room_no,
        })

    if not devices:
        return None

    df = pd.DataFrame(devices).drop_duplicates(subset="IP")
    return df.to_dict(orient="records")

def load_excel_and_parse_devices(file_path):
    xls = pd.ExcelFile(file_path)

    if "貼紙印製" in xls.sheet_names:
        df_raw = pd.read_excel(file_path, sheet_name="貼紙印製", header=None, dtype=str)
        res = process_one_sheet(df_raw)
        if res is not None:
            return res

    for sheet in xls.sheet_names:
        if sheet == "貼紙印製":
            continue
        df_raw = pd.read_excel(file_path, sheet_name=sheet, header=None, dtype=str)
        res = process_one_sheet(df_raw)
        if res is not None:
            return res

    return []

# ========== GUI ==========
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("設備韌體更新工具（可選取 + 搜尋）")
        self.resize(1100, 700)

        self.devices = []
        self._build_ui()

    def _build_ui(self):
        root = QWidget()
        layout = QVBoxLayout(root)

        # 匯入 Excel
        h = QHBoxLayout()
        self.btn_import = QPushButton("匯入 Excel")
        self.btn_import.clicked.connect(self.on_import)
        h.addWidget(self.btn_import)

        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("搜尋設備（名稱/IP/房號）")
        self.search_edit.textChanged.connect(self.apply_filter)
        h.addWidget(self.search_edit, 1)

        self.btn_all = QPushButton("全選")
        self.btn_all.clicked.connect(lambda: self.set_all_checked(True))
        self.btn_none = QPushButton("取消全選")
        self.btn_none.clicked.connect(lambda: self.set_all_checked(False))
        h.addWidget(self.btn_all)
        h.addWidget(self.btn_none)
        layout.addLayout(h)

        # 表格
        self.tbl = QTableWidget(0, 5)
        self.tbl.setHorizontalHeaderLabels(["選取", "設備類型", "名稱", "IP", "房號"])
        self.tbl.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tbl.setEditTriggers(QAbstractItemView.NoEditTriggers)
        layout.addWidget(self.tbl)

        # 開始更新
        self.btn_update = QPushButton("開始更新")
        self.btn_update.clicked.connect(self.on_update)
        layout.addWidget(self.btn_update)

        self.setCentralWidget(root)

    def on_import(self):
        path, _ = QFileDialog.getOpenFileName(self, "匯入 Excel", "", "Excel Files (*.xls *.xlsx)")
        if not path:
            return
        try:
            devices = load_excel_and_parse_devices(path)
            self.devices = devices
            self.populate_table(devices)
            QMessageBox.information(self, "成功", f"匯入成功，共 {len(devices)} 筆")
        except Exception as e:
            QMessageBox.critical(self, "錯誤", f"匯入失敗：{e}")

    def populate_table(self, devices):
        self.tbl.setRowCount(0)
        for d in devices:
            r = self.tbl.rowCount()
            self.tbl.insertRow(r)
            cb = QCheckBox()
            self.tbl.setCellWidget(r, 0, cb)
            self.tbl.setItem(r, 1, QTableWidgetItem(d.get("設備類型", "")))
            self.tbl.setItem(r, 2, QTableWidgetItem(d.get("名稱", "")))
            self.tbl.setItem(r, 3, QTableWidgetItem(d.get("IP", "")))
            self.tbl.setItem(r, 4, QTableWidgetItem(d.get("房號", "")))

    def set_all_checked(self, checked):
        for r in range(self.tbl.rowCount()):
            cb = self.tbl.cellWidget(r, 0)
            if cb:
                cb.setChecked(checked)

    def apply_filter(self):
        kw = self.search_edit.text().lower()
        for r in range(self.tbl.rowCount()):
            texts = []
            for c in range(1, self.tbl.columnCount()):
                it = self.tbl.item(r, c)
                if it:
                    texts.append(it.text().lower())
            self.tbl.setRowHidden(r, kw not in " ".join(texts))

    def get_selected_devices(self):
        res = []
        for r in range(self.tbl.rowCount()):
            cb = self.tbl.cellWidget(r, 0)
            if cb and cb.isChecked() and not self.tbl.isRowHidden(r):
                res.append({
                    "設備類型": self.tbl.item(r, 1).text(),
                    "名稱": self.tbl.item(r, 2).text(),
                    "IP": self.tbl.item(r, 3).text(),
                    "房號": self.tbl.item(r, 4).text(),
                })
        return res

    def on_update(self):
        selected = self.get_selected_devices()
        if not selected:
            QMessageBox.warning(self, "提醒", "請至少勾選一台設備")
            return
        msg = "\n".join([f"{d['IP']} ({d['名稱']})" for d in selected])
        QMessageBox.information(self, "更新設備", f"即將更新以下設備：\n{msg}")

# ========== 入口 ==========
if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())
