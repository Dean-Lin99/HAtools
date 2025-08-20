# -*- coding: utf-8 -*-
"""
SIP/SDP Analyzer GUI (Full, Debug-enabled, Fixed)
- 修正欄位探測：改用 -c 1，避免 "The specified packet count is zero"
- 強化 SIP 偵測：多重 fallback（sip/sdp/sipxml/sipfrag、payload 搜尋、io,phs 統計）
- 支援手動指定 SIP 埠與自訂顯示過濾器
- 除錯模式會把每個 tshark 命令與前幾千字輸出顯示在【診斷】
"""

import os
import re
import sys
import shutil
import subprocess
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Iterable

from PyQt5.QtCore import Qt, QThread, pyqtSignal, QAbstractTableModel, QModelIndex
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QFileDialog, QPushButton,
    QLineEdit, QLabel, QTableView, QTabWidget, QTextEdit, QMessageBox, QCheckBox
)

# ---------------- Subprocess (UTF-8 safe) ----------------
def run_utf8(cmd: list, check: bool = False):
    return subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=check,
    )

def blob(*parts) -> str:
    return "".join(p for p in parts if isinstance(p, str))

# ---------------- Helpers ----------------
def is_private_ip(ip: str) -> bool:
    if not ip or "." not in ip:
        return False
    a, b, *_ = ip.split(".") + ["0", "0"]
    if a == "10": return True
    if a == "192" and b == "168": return True
    if a == "172":
        try:
            s = int(b); return 16 <= s <= 31
        except Exception:
            return False
    return False

def is_same_l3(ip1: str, ip2: str) -> bool:
    try:
        return ".".join(ip1.split(".")[:2]) == ".".join(ip2.split(".")[:2])
    except Exception:
        return False

# ---------------- Data structures ----------------
@dataclass
class SipEvent:
    time: float
    src: str
    dst: str
    method: str = ""
    status: str = ""
    call_id: str = ""
    cseq: str = ""
    branch: str = ""
    sdp_c_ip: str = ""
    media: List[Tuple[str, str]] = field(default_factory=list)
    attrs: List[str] = field(default_factory=list)

@dataclass
class CallSummary:
    call_id: str
    parties: Counter = field(default_factory=Counter)
    methods: Counter = field(default_factory=Counter)
    statuses: Counter = field(default_factory=Counter)
    directions: Counter = field(default_factory=Counter)  # sendrecv/recvonly/sendonly/invalid_recvon
    offered_codecs: set = field(default_factory=set)
    sdp_c_ips: Counter = field(default_factory=Counter)
    audio_ports: set = field(default_factory=set)
    video_ports: set = field(default_factory=set)
    has_duplicated_nat_view: bool = False
    problems: List[str] = field(default_factory=list)
    timeline: List[SipEvent] = field(default_factory=list)

# ---------------- Field map (generic → candidates) ----------------
GEN_KEYS = [
    "time", "ip.src", "ip.dst", "sip.Request-Line", "sip.Status-Code",
    "sip.CSeq.method", "sip.Call-ID", "sip.via.branch",
    "sdp.connection_info_address", "sdp.media.media", "sdp.media_port",
    "sdp.attribute", "sdp.rtpmap.payload_type", "sdp.rtpmap.encoding_name",
    "sdp.rtpmap.clock_rate",
]
ESSENTIAL_KEYS = ["time", "ip.src", "ip.dst"]

FIELD_CANDIDATES = {
    "time": ["frame.time_epoch"],
    "ip.src": ["ip.src"],
    "ip.dst": ["ip.dst"],

    # SIP
    "sip.Request-Line": ["sip.Request-Line", "sip.request_line"],
    "sip.Status-Code":  ["sip.Status-Code", "sip.status_code"],
    "sip.CSeq.method":  ["sip.CSeq.method", "sip.cseq.method"],
    "sip.Call-ID":      ["sip.Call-ID", "sip.call_id"],
    "sip.via.branch":   ["sip.via.branch", "sip.Via.Branch", "sip.via.branch_id"],

    # SDP
    "sdp.connection_info_address": [
        "sdp.connection_info.address", "sdp.connection_info_address", "sdp.connection.address"
    ],
    "sdp.media.media": ["sdp.media.type", "sdp.media.media", "sdp.media.media_type"],
    "sdp.media_port":  ["sdp.media.port", "sdp.media_port"],
    "sdp.attribute":   ["sdp.attribute", "sdp.media.attribute", "sdp.attribute.value"],

    # rtpmap（可缺）
    "sdp.rtpmap.payload_type": ["sdp.rtpmap.payload_type", "sdp.media.rtpmap.payload_type"],
    "sdp.rtpmap.encoding_name":["sdp.rtpmap.encoding_name", "sdp.media.rtpmap.encoding_name"],
    "sdp.rtpmap.clock_rate":   ["sdp.rtpmap.clock_rate", "sdp.media.rtpmap.clock_rate"],
}

# ---------------- tshark helpers ----------------
def find_tshark_path(saved_hint: str = None) -> Optional[str]:
    if saved_hint and os.path.isfile(saved_hint) and saved_hint.lower().endswith("tshark.exe"):
        return saved_hint
    p = shutil.which("tshark")
    if p and p.lower().endswith("tshark.exe"):
        return p
    common = r"C:\Program Files\Wireshark\tshark.exe"
    if os.path.isfile(common):
        return common
    return None

def validate_tshark(tshark_path: str) -> str:
    if not tshark_path or not os.path.isfile(tshark_path):
        raise FileNotFoundError("找不到 tshark.exe，請安裝 Wireshark 或選擇正確路徑。")
    if not tshark_path.lower().endswith("tshark.exe"):
        raise RuntimeError(f"選到的不是 tshark.exe：{tshark_path}")
    out = run_utf8([tshark_path, "-v"])
    if "tshark" not in blob(out.stdout, out.stderr).lower():
        raise RuntimeError("這個檔案不是 TShark（-v 輸出不含 'TShark'）。")
    return tshark_path

def _list_tshark_fields(tshark_path: str, debug_log: list) -> set:
    cmd = [tshark_path, "-G", "fields"]
    debug_log.append(f"$ {' '.join(cmd)}")
    proc = run_utf8(cmd)
    text = blob(proc.stdout, proc.stderr)
    debug_log.append(text[:3000])
    if proc.returncode != 0:
        return set()
    fields = set()
    for line in text.splitlines():
        if line.startswith("F\t"):
            parts = line.split("\t")
            if len(parts) > 2:
                fields.add(parts[1])
    return fields

def _probe_field_on_pcap(tshark_path: str, pcap_path: str, field_name: str, debug_log: list) -> bool:
    # 修正：改用 -c 1（你的環境 -c 0 會報錯）
    cmd = [tshark_path, "-n", "-r", pcap_path, "-T", "fields", "-e", field_name, "-c", "1"]
    debug_log.append(f"$ {' '.join(cmd)}")
    proc = run_utf8(cmd)
    text = blob(proc.stdout, proc.stderr)
    debug_log.append(text[:1000])
    # 只要不是「not a valid field」就視為支援（即使沒有值）
    return "not a valid field" not in text.lower()

def _resolve_fields(tshark_path: str, pcap_path: str, debug_log: list) -> Tuple[Dict[str, Optional[str]], List[str]]:
    available = _list_tshark_fields(tshark_path, debug_log)
    resolved: Dict[str, Optional[str]] = {}
    skipped: List[str] = []
    for gk in GEN_KEYS:
        cands = FIELD_CANDIDATES.get(gk, [])
        picked: Optional[str] = None
        if available:
            for cand in cands:
                if cand in available:
                    picked = cand; break
        if not picked:
            for cand in cands:
                if _probe_field_on_pcap(tshark_path, pcap_path, cand, debug_log):
                    picked = cand; break
        resolved[gk] = picked
        if not picked and gk not in ESSENTIAL_KEYS:
            skipped.append(gk)

    # 確保基本欄位一定有
    for gk in ESSENTIAL_KEYS:
        if not resolved.get(gk):
            cands = FIELD_CANDIDATES.get(gk, [])
            resolved[gk] = cands[0] if cands else gk
    return resolved, skipped

def _extract_ports(tshark_path: str, pcap_path: str, proto: str, debug_log: list) -> List[int]:
    if proto == "udp":
        cmd = [tshark_path, "-n", "-r", pcap_path, "-Y", "udp", "-T", "fields",
               "-e", "udp.srcport", "-e", "udp.dstport"]
    else:
        cmd = [tshark_path, "-n", "-r", pcap_path, "-Y", "tcp", "-T", "fields",
               "-e", "tcp.srcport", "-e", "tcp.dstport"]
    debug_log.append(f"$ {' '.join(cmd)}")
    proc = run_utf8(cmd)
    text = blob(proc.stdout, proc.stderr)
    debug_log.append(text[:1500])
    ports = set()
    for line in text.splitlines():
        parts = [p for p in line.split("\t") if p]
        for p in parts:
            try:
                v = int(p)
                if 1 <= v <= 65535:
                    ports.add(v)
            except Exception:
                pass
    common = [5060, 5061, 5070, 5071, 5080, 5090, 6060, 6070, 7070, 7078]
    ordered = list(dict.fromkeys(common + sorted([p for p in ports if p <= 20000])))
    return ordered[:40]

def _build_decoders(udp_ports: Iterable[int], tcp_ports: Iterable[int]) -> List[str]:
    decoders = []
    for p in udp_ports:
        decoders += ["-d", f"udp.port=={p},sip"]
    for p in tcp_ports:
        decoders += ["-d", f"tcp.port=={p},sip"]
    return decoders

def _try_has_sip(tshark_path: str, pcap_path: str, display_filter: str, decoders: List[str], debug_log: list) -> bool:
    # 1) 直接用使用者/預設過濾器
    cmd = [tshark_path, "-n", "-r", pcap_path] + decoders + \
          ["-Y", display_filter, "-T", "fields", "-e", "frame.number", "-c", "1"]
    debug_log.append(f"$ {' '.join(cmd)}")
    proc = run_utf8(cmd)
    txt = blob(proc.stdout, proc.stderr)
    debug_log.append(txt[:1000])
    if proc.returncode == 0 and txt.strip():
        return True

    # 2) 常見 SIP 家族
    for filt in [
        'sip || sdp || sipxml || sipfrag',
        'sip || sdp || sipxml || http && tcp.port==5061',
    ]:
        cmd = [tshark_path, "-n", "-r", pcap_path] + decoders + \
              ["-Y", filt, "-T", "fields", "-e", "frame.number", "-c", "1"]
        debug_log.append(f"$ {' '.join(cmd)}")
        proc = run_utf8(cmd); txt = blob(proc.stdout, proc.stderr)
        debug_log.append(txt[:600])
        if proc.returncode == 0 and txt.strip():
            return True

    # 3) 原始 payload 搜尋關鍵字
    for filt in ['data contains "SIP/2.0"', 'data contains "INVITE"']:
        cmd = [tshark_path, "-n", "-r", pcap_path] + decoders + \
              ["-Y", filt, "-T", "fields", "-e", "frame.number", "-c", "1"]
        debug_log.append(f"$ {' '.join(cmd)}")
        proc = run_utf8(cmd); txt = blob(proc.stdout, proc.stderr)
        debug_log.append(txt[:600])
        if proc.returncode == 0 and txt.strip():
            return True

    # 4) 協定統計（io,phs）偵測
    cmd = [tshark_path, "-n", "-r", pcap_path] + decoders + ["-q", "-z", "io,phs"]
    debug_log.append(f"$ {' '.join(cmd)}")
    proc = run_utf8(cmd); txt = blob(proc.stdout, proc.stderr)
    debug_log.append(txt[:2000])
    if re.search(r"\bsip\b", txt, re.I) or re.search(r"\bsdp\b", txt, re.I):
        return True

    return False

def _pcap_has_sip_and_decoders(tshark_path: str, pcap_path: str, display_filter: str, manual_ports: List[int], debug_log: list) -> Tuple[bool, List[str]]:
    # 先不解碼直查
    if _try_has_sip(tshark_path, pcap_path, display_filter, [], debug_log):
        return True, []
    # 使用手動埠
    decoders = _build_decoders(manual_ports, [])
    if decoders and _try_has_sip(tshark_path, pcap_path, display_filter, decoders, debug_log):
        return True, decoders
    # 自動掃埠
    udp_ports = _extract_ports(tshark_path, pcap_path, "udp", debug_log)
    tcp_ports = _extract_ports(tshark_path, pcap_path, "tcp", debug_log)
    decoders2 = _build_decoders(udp_ports[:20], tcp_ports[:10])
    if _try_has_sip(tshark_path, pcap_path, display_filter, decoders2, debug_log):
        return True, decoders2
    return False, decoders or decoders2

def run_tshark(tshark_path: str, pcap_path: str, display_filter: str, manual_ports: List[int], debug_enabled: bool) -> Tuple[List[Dict[str, str]], bool, Dict[str, Optional[str]], List[str], List[str], str]:
    """
    回傳 (rows, has_sip, field_map, skipped, decoders_used, debug_text)
    """
    debug_log: List[str] = []
    has_sip, decoders_used = _pcap_has_sip_and_decoders(tshark_path, pcap_path, display_filter, manual_ports, debug_log)
    fld_map, skipped = _resolve_fields(tshark_path, pcap_path, debug_log)

    usable_pairs = [(gk, real) for gk, real in fld_map.items() if real]
    for gk in ESSENTIAL_KEYS:
        if gk not in [p[0] for p in usable_pairs]:
            usable_pairs.append((gk, FIELD_CANDIDATES[gk][0] if FIELD_CANDIDATES.get(gk) else gk))

    cmd = [tshark_path, "-n", "-r", pcap_path] + decoders_used + ["-T", "fields"]
    if has_sip:
        cmd += ["-Y", display_filter]
    real_fields = []
    for _, real in usable_pairs:
        real_fields.append(real)
        cmd += ["-e", real]
    cmd += ["-E", "separator=|", "-E", "occurrence=f"]
    debug_log.append(f"$ {' '.join(cmd)}")
    proc = run_utf8(cmd)
    text = blob(proc.stdout, proc.stderr)
    debug_log.append(text[:3000])

    if proc.returncode != 0:
        raise RuntimeError(text.strip() or "tshark 執行失敗")

    rows = []
    if text.strip():
        real2gen = {real: gk for gk, real in usable_pairs}
        for ln in text.splitlines():
            parts = ln.split("|")
            if len(parts) < len(real_fields):
                parts += [""] * (len(real_fields) - len(parts))
            row = {}
            for i, real in enumerate(real_fields):
                gen = real2gen.get(real)
                if gen:
                    row[gen] = parts[i]
            rows.append(row)

    debug_text = "\n".join(debug_log) if debug_enabled else ""
    return rows, has_sip, fld_map, skipped, decoders_used, debug_text

# ---------------- Parsing ----------------
DIR_PAT = re.compile(r"\ba=(sendrecv|recvonly|sendonly)\b", re.I)
RECVON_PAT = re.compile(r"\ba=recvon\b", re.I)

def parse_rows(rows: List[Dict[str, str]]) -> Dict[str, CallSummary]:
    calls: Dict[str, CallSummary] = {}
    sig_seen: Dict[Tuple[str, str, str], set] = defaultdict(set)

    for r in rows:
        call_id = (r.get("sip.Call-ID") or "").strip()
        if not call_id:
            continue

        ev = SipEvent(
            time=float(r.get("time") or 0.0),
            src=r.get("ip.src", ""),
            dst=r.get("ip.dst", ""),
            status=(r.get("sip.Status-Code") or "").strip(),
            call_id=call_id,
            cseq=(r.get("sip.CSeq.method") or "").strip(),
            branch=(r.get("sip.via.branch") or "").strip(),
            sdp_c_ip=(r.get("sdp.connection_info_address") or "").strip(),
        )

        req_line = r.get("sip.Request-Line", "")
        if req_line:
            parts = req_line.split(" ")
            if parts:
                ev.method = parts[0].strip().upper()

        media = (r.get("sdp.media.media") or "").strip()
        mport = (r.get("sdp.media_port") or "").strip()
        if media and mport:
            ev.media.append((media, mport))

        attr = (r.get("sdp.attribute") or "").strip()
        if attr:
            ev.attrs = [a.strip() for a in attr.split(",") if a.strip()]

        csum = calls.setdefault(call_id, CallSummary(call_id=call_id))
        csum.timeline.append(ev)
        if ev.src: csum.parties[ev.src] += 1
        if ev.dst: csum.parties[ev.dst] += 1
        if ev.method: csum.methods[ev.method] += 1
        if ev.status: csum.statuses[ev.status] += 1

        a_blob = " ".join(ev.attrs)
        mdir = DIR_PAT.search(a_blob)
        if mdir:
            csum.directions[mdir.group(1).lower()] += 1
        if RECVON_PAT.search(a_blob):
            csum.directions["invalid_recvon"] += 1
            csum.problems.append("偵測非標準 a=recvon（拼字錯誤）")

        if ev.sdp_c_ip:
            csum.sdp_c_ips[ev.sdp_c_ip] += 1
            if is_private_ip(ev.sdp_c_ip) and not is_same_l3(ev.sdp_c_ip, ev.src):
                csum.problems.append(f"SDP c={ev.sdp_c_ip} 可能對外不可達（由 {ev.src} 送出）")

        for med, port in ev.media:
            if med.lower() == "audio":
                csum.audio_ports.add(port)
            elif med.lower() == "video":
                csum.video_ports.add(port)

        key = (call_id, ev.cseq, ev.branch)
        if ev.branch:
            sig_seen[key].add(ev.src)
            if len(sig_seen[key]) >= 2:
                csum.has_duplicated_nat_view = True

        if ev.status == "487":
            csum.problems.append("487 Request Terminated（通話建立前被取消/取代）")
        if ev.status == "488":
            csum.problems.append("488 Not Acceptable Here（SDP 編碼/參數不匹配）")
        if ev.status == "405":
            csum.problems.append("405 Method Not Allowed（方法不被允許）")

    for r in rows:
        call_id = (r.get("sip.Call-ID") or "").strip()
        if not call_id or call_id not in calls:
            continue
        enc = (r.get("sdp.rtpmap.encoding_name") or "").upper()
        rate = (r.get("sdp.rtpmap.clock_rate") or "")
        if enc:
            calls[call_id].offered_codecs.add(enc + (f"/{rate}" if rate else ""))

    for c in calls.values():
        c.problems = sorted(set(c.problems))
        c.timeline.sort(key=lambda e: e.time)
    return calls

# ---------------- Qt Model ----------------
class CallsTableModel(QAbstractTableModel):
    HEADERS = ["Call-ID", "事件數", "487", "488", "405", "NAT重複", "方向", "SDP c=（前3）", "Audio埠", "Video埠", "Codecs（節選）"]
    def __init__(self, data: List[CallSummary]): super().__init__(); self.data_list = data
    def rowCount(self, parent=QModelIndex()): return len(self.data_list)
    def columnCount(self, parent=QModelIndex()): return len(self.HEADERS)
    def headerData(self, s, o, r=Qt.DisplayRole):
        return self.HEADERS[s] if (r==Qt.DisplayRole and o==Qt.Horizontal) else None
    def data(self, idx, r=Qt.DisplayRole):
        if not idx.isValid(): return None
        c: CallSummary = self.data_list[idx.row()]
        col = idx.column()
        if r == Qt.DisplayRole:
            if col==0: return c.call_id
            if col==1: return len(c.timeline)
            if col==2: return c.statuses.get("487",0)
            if col==3: return c.statuses.get("488",0)
            if col==4: return c.statuses.get("405",0)
            if col==5: return "是" if c.has_duplicated_nat_view else ""
            if col==6:
                seg=[]
                for k in ["sendrecv","recvonly","sendonly","invalid_recvon"]:
                    v=c.directions.get(k,0)
                    if v: seg.append({"sendrecv":"↔︎","recvonly":"⬅︎只收","sendonly":"➡︎只送","invalid_recvon":"⚠recvon"}[k]+f"×{v}")
                return " / ".join(seg)
            if col==7: return ", ".join([f"{ip}×{cnt}" for ip,cnt in c.sdp_c_ips.most_common(3)])
            if col==8: return ",".join(sorted(c.audio_ports)) if c.audio_ports else ""
            if col==9: return ",".join(sorted(c.video_ports)) if c.video_ports else ""
            if col==10:return ", ".join(sorted(list(c.offered_codecs))[:5])
        if r == Qt.TextAlignmentRole: return Qt.AlignCenter
        return None

# ---------------- Background thread ----------------
class ParseThread(QThread):
    progress = pyqtSignal(str)
    finished_ok = pyqtSignal(dict, str, bool, dict, list, list, str)  # + debug_text
    failed = pyqtSignal(str)
    def __init__(self, tshark_path, pcap_path, display_filter, manual_ports, debug_enabled):
        super().__init__()
        self.tshark_path=tshark_path; self.pcap_path=pcap_path
        self.display_filter=display_filter; self.manual_ports=manual_ports; self.debug_enabled=debug_enabled
    def run(self):
        try:
            self.progress.emit("執行 tshark（除錯中…）")
            rows, has_sip, fld_map, skipped, decoders, dbg = run_tshark(
                self.tshark_path, self.pcap_path, self.display_filter, self.manual_ports, self.debug_enabled
            )
            self.progress.emit(f"已抽取 {len(rows)} 筆紀錄，分析中…")
            calls = parse_rows(rows)
            self.finished_ok.emit(calls, self.tshark_path, has_sip, fld_map, skipped, decoders, dbg)
        except Exception as e:
            self.failed.emit(str(e))

# ---------------- Main window ----------------
class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SIP/SDP 自動化分析 GUI")
        self.resize(1320, 780)
        self.tshark_path = find_tshark_path()
        self.calls: Dict[str, CallSummary] = {}

        top = QHBoxLayout()
        self.btn_open = QPushButton("開檔 (pcap/pcapng)"); self.btn_open.clicked.connect(self.open_file)
        self.le_filter = QLineEdit("sip || sdp"); self.le_filter.setFixedWidth(220)
        self.le_filter.setToolTip("自訂顯示過濾器（例如：sip || sdp || sipxml || data contains \"SIP/2.0\"）")
        self.le_ports = QLineEdit(""); self.le_ports.setPlaceholderText("手動指定 SIP 埠，例如 5060,7078"); self.le_ports.setFixedWidth(220)
        self.cb_debug = QCheckBox("啟用除錯輸出")

        self.le_search = QLineEdit(); self.le_search.setPlaceholderText("關鍵字過濾：Call-ID / IP / 狀態碼 / 方向…")
        self.le_search.textChanged.connect(self.apply_filter)
        self.cb_only_problem = QCheckBox("只看有問題"); self.cb_only_problem.stateChanged.connect(self.apply_filter)
        self.lbl_tshark = QLabel(f"tshark: {self.tshark_path or '未找到（開檔時會詢問）'}")
        self.lbl_status = QLabel("準備就緒")

        top.addWidget(self.btn_open)
        top.addWidget(QLabel("過濾器:")); top.addWidget(self.le_filter)
        top.addWidget(QLabel("手動埠:")); top.addWidget(self.le_ports)
        top.addWidget(self.cb_debug)
        top.addWidget(self.le_search,1)
        top.addWidget(self.cb_only_problem)
        top.addWidget(self.lbl_tshark); top.addWidget(self.lbl_status)

        self.tabs = QTabWidget()
        self.table = QTableView(); self.model = CallsTableModel([]); self.table.setModel(self.model)
        self.table.doubleClicked.connect(self.show_detail_tab); self.tabs.addTab(self.table,"總覽")
        self.txt_detail = QTextEdit(); self.txt_detail.setReadOnly(True); self.tabs.addTab(self.txt_detail,"通話明細")
        self.txt_report = QTextEdit(); self.txt_report.setReadOnly(True); self.tabs.addTab(self.txt_report,"報告 (Markdown)")
        self.txt_diag = QTextEdit(); self.txt_diag.setReadOnly(True); self.tabs.addTab(self.txt_diag,"診斷")

        lay = QVBoxLayout(self); lay.addLayout(top); lay.addWidget(self.tabs)

    def _ask_for_tshark(self) -> Optional[str]:
        guess = QFileDialog.getOpenFileName(self,"選擇 tshark.exe",r"C:\Program Files\Wireshark","Executables (*.exe)")[0]
        if not guess: return None
        try:
            good = validate_tshark(guess); self.lbl_tshark.setText(f"tshark: {good}"); return good
        except Exception as e:
            QMessageBox.critical(self,"tshark 驗證失敗",str(e)); return None

    def open_file(self):
        if not self.tshark_path:
            self.tshark_path = find_tshark_path()
        if not self.tshark_path:
            self.tshark_path = self._ask_for_tshark()
            if not self.tshark_path: return
        else:
            try:
                self.tshark_path = validate_tshark(self.tshark_path)
            except Exception:
                self.tshark_path = self._ask_for_tshark()
                if not self.tshark_path: return

        pcap, _ = QFileDialog.getOpenFileName(self,"開啟封包檔","", "PCAP Files (*.pcap *.pcapng)")
        if not pcap: return

        # parse manual ports
        ports=[]
        for s in self.le_ports.text().replace("，",",").split(","):
            s=s.strip()
            if not s: continue
            try:
                v=int(s)
                if 1<=v<=65535: ports.append(v)
            except: pass

        self.lbl_status.setText("解析中…"); self.btn_open.setEnabled(False)
        self.thread = ParseThread(
            self.tshark_path, pcap,
            self.le_filter.text().strip() or "sip || sdp",
            ports, self.cb_debug.isChecked()
        )
        self.thread.progress.connect(self.lbl_status.setText)
        self.thread.finished_ok.connect(self.on_parsed)
        self.thread.failed.connect(self.on_failed)
        self.thread.start()

    def on_parsed(self, calls, tshark_path, has_sip, field_map, skipped, decoders, debug_text):
        self.calls = calls; self.btn_open.setEnabled(True)
        if not has_sip:
            self.lbl_status.setText("⚠ 仍未偵測到 SIP/SDP（已嘗試強制解碼與多重 fallback）。")
        else:
            msg = f"完成：{len(calls)} 個 Call-ID"
            if decoders: msg += f"（已強制解碼 {len(decoders)//2} 個埠）"
            self.lbl_status.setText(msg)
        self.apply_filter(); self.update_report(); self.update_diag(tshark_path, has_sip, field_map, skipped, decoders, debug_text)

    def on_failed(self, msg):
        self.btn_open.setEnabled(True); QMessageBox.critical(self,"解析失敗",msg); self.lbl_status.setText("失敗")

    def apply_filter(self):
        kw = self.le_search.text().strip().lower(); only_prob = self.cb_only_problem.isChecked()
        filtered = []
        for c in self.calls.values():
            if only_prob and not c.problems: continue
            blob_ = " ".join([
                c.call_id,
                " ".join([f"{k}:{v}" for k,v in c.statuses.items()]),
                " ".join(c.sdp_c_ips.keys()),
                ",".join(c.audio_ports), ",".join(c.video_ports),
                " ".join(c.problems), " ".join(c.directions.keys()),
            ]).lower()
            if (not kw) or (kw in blob_): filtered.append(c)
        filtered.sort(key=lambda x: (x.statuses.get("488",0), x.statuses.get("487",0), len(x.problems)), reverse=True)
        self.model = CallsTableModel(filtered); self.table.setModel(self.model)

    def show_detail_tab(self, index: QModelIndex):
        c: CallSummary = self.model.data_list[index.row()]
        lines = [f"# Call-ID: {c.call_id}\n"]
        if c.problems: lines.append("⚠ 問題：\n- " + "\n- ".join(sorted(set(c.problems))) + "\n")
        lines.append(f"方向統計：{dict(c.directions)}")
        lines.append(f"SDP c= IP 統計：{dict(c.sdp_c_ips)}")
        lines.append(f"Audio RTP 埠：{sorted(c.audio_ports)}")
        lines.append(f"Video RTP 埠：{sorted(c.video_ports)}")
        lines.append(f"Codecs：{sorted(c.offered_codecs)}")
        lines.append(f"NAT 內外重複觀察：{'是' if c.has_duplicated_nat_view else '否'}\n")
        lines.append("## 事件時間線")
        for ev in c.timeline:
            desc = ev.method or ev.status or "SDP"; extras=[]
            if ev.sdp_c_ip: extras.append(f"c={ev.sdp_c_ip}")
            if ev.media: extras.append("media=" + ",".join([f"{m}:{p}" for m,p in ev.media]))
            if ev.attrs:
                imp=[a for a in ev.attrs if any(k in a.lower() for k in
                    ["sendrecv","recvonly","sendonly","rtpmap","fmtp","packetization-mode","profile-level-id","recvon"])]
                if imp: extras.append("attrs="+";".join(imp))
            lines.append(f"- t={ev.time:.6f} {ev.src} → {ev.dst} | {desc} | CSeq={ev.cseq} | branch={ev.branch} | " + " ".join(extras))
        self.txt_detail.setPlainText("\n".join(lines)); self.tabs.setCurrentWidget(self.txt_detail)

    def update_report(self):
        out = ["# SIP/SDP 分析報告（自動產生）\n", f"通話數：{len(self.calls)}\n"]
        interesting = sorted(self.calls.values(), key=lambda c: (len(c.problems), c.statuses.get("488",0), c.statuses.get("487",0)), reverse=True)[:20]
        for c in interesting:
            out.append(f"## Call-ID: {c.call_id}")
            if c.problems:
                out.append("**問題**："); out += [f"- {p}" for p in sorted(set(c.problems))]
            out.append(f"- 487/488/405 = {c.statuses.get('487',0)}/{c.statuses.get('488',0)}/{c.statuses.get('405',0)}")
            out.append(f"- NAT 內外重複觀察：{'是' if c.has_duplicated_nat_view else '否'}")
            out.append(f"- 方向統計：{dict(c.directions)}")
            out.append(f"- SDP c= 前三名：{c.sdp_c_ips.most_common(3)}")
            out.append(f"- Audio RTP 埠：{sorted(c.audio_ports)}")
            out.append(f"- Video RTP 埠：{sorted(c.video_ports)}")
            out.append(f"- Codecs：{sorted(c.offered_codecs)}\n")
        self.txt_report.setPlainText("\n".join(out))

    def update_diag(self, tshark_path: str, has_sip: bool, field_map: Dict[str, Optional[str]], skipped: List[str], decoders: List[str], debug_text: str):
        lines = []
        lines.append(f"tshark 路徑：{tshark_path}")
        lines.append(f"SIP/SDP 是否偵測到：{'是' if has_sip else '否'}")
        if decoders:
            used = [decoders[i+1] for i in range(0, len(decoders), 2)]
            lines.append("強制解碼為 SIP 的埠：")
            for rule in used:
                lines.append(f"  - {rule}")
        lines.append("\n=== 欄位對應（通用鍵 → 實際欄位名） ===")
        for k in GEN_KEYS:
            lines.append(f"{k:30s}  →  {field_map.get(k) or '(未採用/偵測不到)'}")
        if skipped:
            lines.append("\n=== 略過的欄位（此版本 tshark 不支援） ===")
            for k in skipped:
                lines.append(f"- {k}")
        if self.cb_debug.isChecked() and debug_text:
            lines.append("\n=== 除錯命令與輸出（節錄） ===")
            lines.append(debug_text)
        self.txt_diag.setPlainText("\n".join(lines))

# ---------------- Entry ----------------
def main():
    app = QApplication(sys.argv)
    w = MainWindow(); w.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
