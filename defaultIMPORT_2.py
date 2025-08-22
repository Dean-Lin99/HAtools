import sys
import os
import re
import csv
import ipaddress
from datetime import datetime
import pandas as pd

# ====== PySide6 ======
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QFileDialog, QLineEdit, QLabel,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
    QStatusBar, QMessageBox
)
from PySide6.QtGui import QIcon
from PySide6.QtCore import Qt

# =========================
# 常數
# =========================
FIXED_COLUMNS = ["選取", "設備類型", "名稱", "IP", "房號"]

# =========================
# 工具
# =========================
def get_icon_path():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "main.ico")

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
    """尋找最可能是 IP 的欄位：有 >=2 個有效 IPv4 即視為 IP 欄"""
    for col in range(len(df.columns)):
        valid = sum(1 for cell in df.iloc[:, col] if is_valid_ip(cell))
        if valid >= 2:
            return col
    return None

def is_first_column_serial(col, min_length=5):
    """偵測第 0 欄是否為流水號（連續整數出現長度 >= min_length）"""
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
    """
    規則：抓「設備類型」欄位之前所有「純數字欄」串接為房號。
    若判定第 0 欄是流水號，則跳過第 0 欄。
    """
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
    """
    對單張 sheet 進行解析：
    1) 自動找 IP 欄
    2) 偵測第 0 欄是否為流水號，若是則不納入房號
    3) 「設備類型」在 IP 欄左二、「名稱」在左一
    4) 過濾「管理中心」
    5) 產生清單後依 IP 去重
    """
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
            "選取": False,
            "設備類型": dev_type,
            "名稱": name,
            "IP": ip,
            "房號": room_no
        })

    if not devices:
        return None

    df = pd.DataFrame(devices).drop_duplicates(subset="IP")
    cols = ["選取", "設備類型", "名稱", "IP", "房號"]
    result = [{k: rec.get(k, "") for k in cols} for rec in df.to_dict(orient="records")]
    return result

def load_excel_and_parse_devices(file_path):
    """
    對整本 Excel 進行解析：
    - 優先處理「貼紙印製」sheet；若解析成功直接回傳
    - 依序嘗試其他 sheet
    - 若都無法解析，退而求其次：全檔掃描所有儲存格，抓出所有不重複的 IP
    """
    xls = pd.ExcelFile(file_path)

    # 1) 優先「貼紙印製」
    if "貼紙印製" in xls.sheet_names:
        df_raw = pd.read_excel(file_path, sheet_name="貼紙印製", header=None, dtype=str)
        res = process_one_sheet(df_raw)
        if res is not None:
            return res

    # 2) 其他 sheet 逐一嘗試
    for sheet in xls.sheet_names:
        if sheet == "貼紙印製":
            continue
        df_raw = pd.read_excel(file_path, sheet_name=sheet, header=None, dtype=str)
        res = process_one_sheet(df_raw)
        if res is not None:
            return res

    # 3) 全檔 fallback：單純抓 IP
    ip_set = set()
    device_list = []
    for sheet in xls.sheet_names:
        df = pd.read_excel(file_path, sheet_name=sheet, header=None, dtype=str)
        for _, row in df.iterrows():
            for cell in row:
                if is_nullish(cell):
                    continue
                ip = str(cell).replace(" ", "").strip()
                if is_valid_ip(ip) and ip not in ip_set:
                    device_list.append({"選取": False, "設備類型": "", "名稱": "", "IP": ip, "房號": ""})
                    ip_set.add(ip)
    return device_list

# =========================
# 簡易 GUI：只做匯入與匯出
# =========================
class SimpleTable(QTableWidget):
    def __init__(self, columns):
        super().__init__(0, len(columns))
        self.columns = columns
        self.setHorizontalHeaderLabels(columns)
        self.verticalHeader().setVisible(False)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setAlternatingRowColors(True)
        self.horizontalHeader().setStretchLastSection(True)
        for c in range(len(columns)):
            self.horizontalHeader().setSectionResizeMode(c, QHeaderView.ResizeToContents)
        self.setStyleSheet("""
            QTableWidget {
                gridline-color: #e5e7eb;
                selection-background-color: #dbeafe;
                selection-color: #111827;
                alternate-background-color: #fafafa;
                background-color: white;
                color: black;   /* 🔥 強制字體顏色為黑色 */
                border: 1px solid #e5e7eb;
                border-radius: 6px;
            }
            QHeaderView::section {
                background: #f3f4f6;
                padding: 8px;
                border: 0px solid #e5e7eb;
                border-right: 1px solid #e5e7eb;
                font-weight: 600;
                color: black;   /* 🔥 強制字體顏色為黑色 */
            }
            QTableWidget::item { padding: 6px; }
        """)

    def populate(self, rows):
        self.setRowCount(0)
        if not rows:
            return
        for r, rec in enumerate(rows):
            self.insertRow(r)
            for c, key in enumerate(self.columns):
                val = rec.get(key, "")
                self.setItem(r, c, QTableWidgetItem(str(val)))

class ImporterWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Excel 匯入（單獨版）")
        icon_path = get_icon_path()
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

        self.records = []

        root = QWidget()
        root_l = QVBoxLayout(root)
        top = QHBoxLayout()
        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText("選擇要匯入的 Excel（.xls / .xlsx）")
        btn_browse = QPushButton("瀏覽…")
        btn_browse.clicked.connect(self.browse_excel)
        btn_import = QPushButton("匯入 Excel")
        btn_import.clicked.connect(self.do_import)
        btn_export = QPushButton("匯出 CSV")
        btn_export.clicked.connect(self.export_csv)

        for w in (self.path_edit, btn_browse, btn_import, btn_export):
            if isinstance(w, (QLineEdit, QPushButton)):
                w.setFixedHeight(34)

        top.addWidget(self.path_edit, 1)
        top.addWidget(btn_browse)
        top.addWidget(btn_import)
        top.addWidget(btn_export)

        self.table = SimpleTable(FIXED_COLUMNS)
        root_l.addLayout(top)
        root_l.addWidget(self.table)

        self.setCentralWidget(root)
        self.setStatusBar(QStatusBar())
        self.statusBar().showMessage("就緒")

        # 支援把檔案拖曳進視窗
        self.setAcceptDrops(True)

    # ---- Drag & Drop ----
    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()

    def dropEvent(self, e):
        urls = e.mimeData().urls()
        if not urls:
            return
        local = urls[0].toLocalFile()
        if local.lower().endswith((".xls", ".xlsx")):
            self.path_edit.setText(local)
            self.do_import()
        else:
            QMessageBox.warning(self, "格式不支援", "請拖曳 .xls 或 .xlsx 檔案")

    # ---- Actions ----
    def browse_excel(self):
        path, _ = QFileDialog.getOpenFileName(self, "選擇 Excel", "", "Excel Files (*.xls *.xlsx)")
        if path:
            self.path_edit.setText(path)

    def do_import(self):
        path = self.path_edit.text().strip()
        if not path:
            QMessageBox.information(self, "未選擇", "請先選擇一個 Excel 檔案")
            return
        try:
            recs = load_excel_and_parse_devices(path)
            self.records = recs or []
            self.table.populate(self.records)
            self.statusBar().showMessage(f"匯入成功：{len(self.records)} 筆")
        except Exception as e:
            self.records = []
            self.table.populate([])
            self.statusBar().showMessage("匯入失敗")
            QMessageBox.critical(self, "匯入失敗", f"{e}")

    def export_csv(self):
        if not self.records:
            QMessageBox.information(self, "無資料", "目前沒有可匯出的資料。")
            return
        default_name = f"匯入結果_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        path, _ = QFileDialog.getSaveFileName(self, "匯出 CSV", default_name, "CSV Files (*.csv)")
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerow(FIXED_COLUMNS)
            for r in self.records:
                writer.writerow([r.get(k, "") for k in FIXED_COLUMNS])
        self.statusBar().showMessage(f"已匯出：{os.path.basename(path)}")

# =========================
# 進入點
# =========================
if __name__ == "__main__":
    import warnings
    warnings.filterwarnings("ignore")
    app = QApplication(sys.argv)

    

    icon = get_icon_path()
    if os.path.exists(icon):
        app.setWindowIcon(QIcon(icon))

    win = ImporterWindow()
    win.resize(1080, 680)
    win.show()
    sys.exit(app.exec())
