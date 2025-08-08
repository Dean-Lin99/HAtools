# sip_rtp_gui_win.py
# -*- coding: utf-8 -*-
import sys, os, csv, threading, asyncio, re, binascii
from collections import defaultdict, Counter
from datetime import datetime

from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QColor, QBrush, QFont
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QFileDialog,
    QLineEdit, QLabel, QTableWidget, QTableWidgetItem, QHeaderView, QTextEdit,
    QProgressBar, QMessageBox, QCheckBox, QSplitter
)

# 需要 Wireshark/tshark 與 pyshark
try:
    import pyshark
    _PYSHARK_ERR = None
except Exception as e:
    pyshark = None
    _PYSHARK_ERR = str(e)


def human_err(msg: str):
    m = QMessageBox(QMessageBox.Critical, "錯誤", msg)
    m.exec_()


class AnalyzerThread(QThread):
    progress = pyqtSignal(int)                     # 0~100
    log = pyqtSignal(str)                          # 追加到日誌視窗
    done = pyqtSignal(dict, list, dict, list)      # sdp_map, rtp_rows, rtp_by_dst, compare_rows
    error = pyqtSignal(str)

    def __init__(self, pcap_path, ip_a, ip_b, sip_ports, tshark_path=None, parent=None):
        super().__init__(parent)
        self.pcap_path = pcap_path
        self.ip_a = ip_a.strip() if ip_a else None
        self.ip_b = ip_b.strip() if ip_b else None
        self.sip_ports = sip_ports or []  # list[str]
        self.tshark_path = tshark_path
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def _safe_get(self, layer, field, default=None):
        try:
            return getattr(layer, field)
        except Exception:
            return default

    # ---------- SIP/SDP 解析 ----------
    def collect_sip_sdps(self):
        """
        讀取 SIP 封包，抓每個來源 IP 最新一次的 audio SDP 公布 (c=IP, m=audio port)。
        回傳 sdp_map: {src_ip: {"conn_ip": str, "audio_port": str, "payloads": str}}
        """
        sdp_map = {}
        decode = {}
        for p in self.sip_ports:
            decode[f"udp.port=={p}"] = "sip"
            decode[f"tcp.port=={p}"] = "sip"

        try:
            cap = pyshark.FileCapture(
                self.pcap_path,
                display_filter="sip",
                keep_packets=False,
                use_json=True,
                tshark_path=self.tshark_path,
                decode_as=decode if decode else None
            )
        except Exception as e:
            self.error.emit(f"SIP 解析失敗：{e}")
            return {}

        idx = 0
        for pkt in cap:
            if self._stop.is_set():
                break
            idx += 1
            if idx % 200 == 0:
                self.progress.emit(6)
            try:
                if not hasattr(pkt, 'sip'):
                    continue
                src_ip = self._safe_get(pkt.ip, 'src')
                if not src_ip:
                    continue
                if hasattr(pkt, 'sdp'):
                    sdp = pkt.sdp
                    conn_ip = self._safe_get(sdp, 'connection_info_address')
                    media = self._safe_get(sdp, 'media')
                    media_port = self._safe_get(sdp, 'media_port')
                    media_format = self._safe_get(sdp, 'media_format')
                    if media and 'audio' in str(media).lower() and media_port and conn_ip:
                        sdp_map[src_ip] = {
                            "conn_ip": str(conn_ip),
                            "audio_port": str(media_port),
                            "payloads": str(media_format) if media_format else ""
                        }
            except Exception:
                continue
        try:
            cap.close()
        except Exception:
            pass

        # 如果沒抓到 SDP，嘗試暴力掃（明文才有用；TLS 看不到）
        if not sdp_map:
            self.log.emit("⚠️ 未抓到 SDP，嘗試暴力掃描 SDP 內容（v=0 / m=audio）...")
            brute = self.bruteforce_scan_sdp()
            if brute:
                self.log.emit(f"暴力掃描到 {len(brute)} 筆 SDP 提示。")
                # 以來源 IP 合併（最後一次為準）
                for src_ip, rec in brute.items():
                    sdp_map[src_ip] = rec
            else:
                self.log.emit("暴力掃描仍未找到 SDP（可能走 TLS 或 pcap 未含信令）。")

        return sdp_map

    def _hexlayer_to_ascii(self, pkt):
        """
        從常見的載荷欄位取 hex，轉成可讀字串。
        優先順序：data.data > tcp.payload > udp.payload
        """
        hexstr = None
        if hasattr(pkt, 'data') and hasattr(pkt.data, 'data'):
            hexstr = pkt.data.data
        elif hasattr(pkt, 'tcp') and hasattr(pkt.tcp, 'payload'):
            hexstr = pkt.tcp.payload
        elif hasattr(pkt, 'udp') and hasattr(pkt.udp, 'payload'):
            hexstr = pkt.udp.payload
        if not hexstr:
            return ""
        # remove colons and spaces, then hex->bytes->str
        s = re.sub(r'[:\s]', '', str(hexstr))
        try:
            return binascii.unhexlify(s).decode('utf-8', 'ignore')
        except Exception:
            try:
                return binascii.unhexlify(s).decode('latin1', 'ignore')
            except Exception:
                return ""

    def bruteforce_scan_sdp(self):
        """
        沒有 SIP 時的備援：以文字匹配撈出含 SDP 關鍵字的封包，直接解析 payload。
        回傳 map: {src_ip: {"conn_ip": str, "audio_port": str, "payloads": str}}
        """
        out = {}
        try:
            cap = pyshark.FileCapture(
                self.pcap_path,
                display_filter='frame contains "v=0" and frame contains "m=audio"',
                keep_packets=False,
                use_json=True,
                tshark_path=self.tshark_path
            )
        except Exception:
            return out

        for pkt in cap:
            try:
                src_ip = self._safe_get(pkt.ip, 'src')
                if not src_ip:
                    continue
                text = self._hexlayer_to_ascii(pkt)
                if not text:
                    continue
                # 解析 c=IN IP4 x.x.x.x
                m_conn = re.search(r'(?mi)^c=\s*IN\s+IP4\s+([^\s\r\n]+)', text)
                # 解析 m=audio <port> <proto> <fmt list>
                m_audio = re.search(r'(?mi)^m=\s*audio\s+(\d+)\s+([^\s]+)\s+([^\r\n]+)', text)
                if m_conn and m_audio:
                    conn_ip = m_conn.group(1)
                    audio_port = m_audio.group(1)
                    payloads = m_audio.group(3).strip()
                    out[src_ip] = {
                        "conn_ip": conn_ip,
                        "audio_port": audio_port,
                        "payloads": payloads
                    }
            except Exception:
                continue
        try:
            cap.close()
        except Exception:
            pass
        return out

    # ---------- RTP 解析（一般 + Decode-As 加強） ----------
    def collect_rtp_streams(self, decode_ports=None):
        """
        掃描 RTP，回傳:
          rtp_rows: list[dict(src_ip,src_port,dst_ip,dst_port,ssrc,pt,packets)]
          by_dst: {(src_ip,dst_ip,dst_port)->packet_count}
        若給了 decode_ports（list[str]），會用 decode_as 將這些 UDP port 強制解為 RTP。
        """
        streams = defaultdict(lambda: {"count": 0, "ssrc": None, "pt": None})
        rows = []

        kwargs = dict(
            display_filter="rtp",
            keep_packets=False,
            use_json=True,
            tshark_path=self.tshark_path
        )
        if decode_ports:
            kwargs["decode_as"] = {f"udp.port=={p}": "rtp" for p in decode_ports}

        try:
            cap = pyshark.FileCapture(self.pcap_path, **kwargs)
        except Exception as e:
            self.error.emit(f"RTP 解析失敗：{e}")
            return [], {}

        i = 0
        for pkt in cap:
            if self._stop.is_set():
                break
            i += 1
            if i % 500 == 0:
                self.progress.emit(48)
            try:
                ip = pkt.ip
                udp = pkt.udp
                rtp = pkt.rtp
                key = (str(ip.src), str(udp.srcport), str(ip.dst), str(udp.dstport),
                       self._safe_get(rtp, 'ssrc'), self._safe_get(rtp, 'payload_type'))
                streams[key]["count"] += 1
                streams[key]["ssrc"] = self._safe_get(rtp, 'ssrc')
                streams[key]["pt"] = self._safe_get(rtp, 'payload_type')
            except Exception:
                continue

        try:
            cap.close()
        except Exception:
            pass

        for (sip, sport, dip, dport, ssrc, pt), info in sorted(
            streams.items(), key=lambda x: (-x[1]["count"], x[0])
        ):
            rows.append({
                "src_ip": sip, "src_port": sport,
                "dst_ip": dip, "dst_port": dport,
                "ssrc": ssrc, "pt": pt, "packets": info["count"]
            })

        by_dst = defaultdict(int)
        for r in rows:
            by_dst[(r["src_ip"], r["dst_ip"], r["dst_port"])] += r["packets"]

        return rows, by_dst

    # ---------- UDP 備援 ----------
    def count_udp_packets(self, src_ip, dst_ip, dst_port):
        """當 RTP 解不出來時，用純 UDP 計數作為備援。"""
        if not (src_ip and dst_ip and dst_port):
            return 0
        try:
            filt = f"ip.src=={src_ip} && ip.dst=={dst_ip} && udp.port=={dst_port} && !(sip)"
            cap = pyshark.FileCapture(
                self.pcap_path,
                display_filter=filt,
                keep_packets=False,
                use_json=True,
                tshark_path=self.tshark_path
            )
            cnt = 0
            for _ in cap:
                if self._stop.is_set():
                    break
                cnt += 1
            try:
                cap.close()
            except Exception:
                pass
            return cnt
        except Exception:
            return 0

    # ---------- SDP vs RTP 比對 ----------
    def compare_sdp_rtp(self, sdp_map, rtp_by_dst):
        """
        回傳 compare_rows: list(dict)
        欄位：
          方向, SDP_IP, SDP_Port, 實際目的IP, 實際目的Port(Top), RTP封包數, UDP封包數(備援), 一致性
        """
        rows = []
        for direction in ("A→B", "B→A"):
            if direction == "A→B":
                src_ip = self.ip_a; dst_ip = self.ip_b
            else:
                src_ip = self.ip_b; dst_ip = self.ip_a
            if not (src_ip and dst_ip):
                continue

            sdp = sdp_map.get(dst_ip)  # 對端宣告的接收位址（A 應送往 B 宣告）
            sdp_ip = sdp["conn_ip"] if sdp else ""
            sdp_port = sdp["audio_port"] if sdp else ""

            # 找此方向實際最多包的目的 port
            port_counts = Counter()
            for (sip, dip, dport), cnt in rtp_by_dst.items():
                if sip == src_ip and dip == dst_ip:
                    port_counts[dport] += cnt
            actual_port, rtp_cnt = (port_counts.most_common(1)[0] if port_counts else ("", 0))

            # UDP 備援
            udp_cnt = 0
            if sdp_ip and sdp_port:
                udp_cnt = self.count_udp_packets(src_ip, sdp_ip, sdp_port)

            match = (sdp_ip == dst_ip and sdp_port == actual_port and rtp_cnt > 0)
            verdict = "一致" if match else ("未見封包" if (rtp_cnt == 0 and udp_cnt == 0) else "不一致")

            rows.append({
                "方向": direction,
                "SDP_IP": sdp_ip,
                "SDP_Port": sdp_port,
                "實際目的IP": dst_ip if actual_port else "",
                "實際目的Port(Top)": actual_port,
                "RTP封包數": rtp_cnt,
                "UDP封包數(備援)": udp_cnt,
                "一致性": verdict
            })
        return rows

    # ---------- 主執行 ----------
    def run(self):
        # Windows + QThread：在子執行緒建立 asyncio event loop
        try:
            asyncio.set_event_loop(asyncio.new_event_loop())
        except Exception:
            pass

        if self._stop.is_set(): return
        if not os.path.exists(self.pcap_path):
            self.error.emit("找不到檔案"); return
        if not pyshark:
            self.error.emit(
                "找不到 pyshark。\n請先安裝 Wireshark（含 tshark），再 pip install pyshark。\n\n原始錯誤："
                + (_PYSHARK_ERR or "")
            ); return

        # 解析 SIP/SDP（含自訂埠與暴力掃）
        self.log.emit("開始解析 SIP/SDP...")
        sdp_map = self.collect_sip_sdps()
        if self._stop.is_set(): return
        self.progress.emit(20)

        # 解析 RTP
        self.log.emit("開始解析 RTP（自動）...")
        rtp_rows, rtp_by_dst = self.collect_rtp_streams()
        if self._stop.is_set(): return

        # 若 RTP 很少或為 0，嘗試 Decode-As（用 SDP 的 audio port）
        total_rtp = sum(rtp_by_dst.values())
        if total_rtp == 0 and sdp_map:
            self.log.emit("未偵測到 RTP，嘗試以 SDP 的 audio port 進行 Decode As RTP...")
            ports = sorted({v["audio_port"] for v in sdp_map.values() if v.get("audio_port")})
            if ports:
                r2_rows, r2_by_dst = self.collect_rtp_streams(decode_ports=ports)
                for k, v in r2_by_dst.items():
                    rtp_by_dst[k] += v
                rtp_rows.extend(r2_rows)
                self.log.emit(f"Decode-As 後 RTP 目的統計：{sum(rtp_by_dst.values())} 封包")
        self.progress.emit(70)

        # SDP vs RTP 比對
        compare_rows = self.compare_sdp_rtp(sdp_map, rtp_by_dst)

        # 自動結論 + NAT/ALG 提示
        if self.ip_a and self.ip_b:
            self.log.emit(f"🔎 A↔B 方向檢查：A={self.ip_a}  B={self.ip_b}")
            a_row = next((r for r in compare_rows if r["方向"] == "A→B"), None)
            b_row = next((r for r in compare_rows if r["方向"] == "B→A"), None)

            self.log.emit("— 比對結果 —")
            if a_row:
                self.log.emit(f"A→B：SDP {a_row['SDP_IP']}:{a_row['SDP_Port']} | "
                              f"實際 {a_row['實際目的IP']}:{a_row['實際目的Port(Top)']} | "
                              f"RTP={a_row['RTP封包數']} UDP={a_row['UDP封包數(備援)']} | {a_row['一致性']}")
            if b_row:
                self.log.emit(f"B→A：SDP {b_row['SDP_IP']}:{b_row['SDP_Port']} | "
                              f"實際 {b_row['實際目的IP']}:{b_row['實際目的Port(Top)']} | "
                              f"RTP={b_row['RTP封包數']} UDP={b_row['UDP封包數(備援)']} | {b_row['一致性']}")

            self.log.emit("\n📌 自動結論：")
            a_any = (a_row and (a_row["RTP封包數"] > 0 or a_row["UDP封包數(備援)"] > 0))
            b_any = (b_row and (b_row["RTP封包數"] > 0 or b_row["UDP封包數(備援)"] > 0))
            if a_any and b_any:
                self.log.emit("✅ 偵測到 A↔B 雙向皆有語音封包抵達對端。")
                self.log.emit("➡️  較可能：編解碼不匹配、播放端/音量/音訊裝置問題、或 SSRC 切換。")
            elif a_any and not b_any:
                self.log.emit("❗ 單向：只看到 A→B，有 B→A 幾乎沒有。")
                self.log.emit("➡️  檢查 B 的 SDP 公布位址、B→A 的防火牆/NAT、或 B 是否有送。")
            elif not a_any and b_any:
                self.log.emit("❗ 單向：只看到 B→A，有 A→B 幾乎沒有。")
                self.log.emit("➡️  檢查 A 的 SDP 公布位址、A→B 的防火牆/NAT、或 A 是否有送。")
            else:
                self.log.emit("⛔  A↔B 都沒看到語音封包。")
                self.log.emit("➡️  可能：pcap 未含語音段、封包未被解碼（已嘗試 Decode-As）、或被中間設備擋。")

            # NAT/ALG 可能性提示
            sus = []
            for r in compare_rows:
                if r["一致性"] == "不一致":
                    if (r["SDP_IP"] and self.ip_a and self.ip_b and
                        ((r["方向"] == "A→B" and r["SDP_IP"] != self.ip_b) or
                         (r["方向"] == "B→A" and r["SDP_IP"] != self.ip_a) or
                         (r["SDP_Port"] and r["實際目的Port(Top)"] and r["SDP_Port"] != r["實際目的Port(Top)"]))):
                        sus.append(r)
            if sus:
                self.log.emit("\n⚠️ 疑似 NAT/ALG 不一致（SDP 公布與實際不符）：")
                for r in sus:
                    self.log.emit(f"  {r['方向']}  SDP {r['SDP_IP']}:{r['SDP_Port']}  "
                                  f"vs 實際 {r['實際目的IP']}:{r['實際目的Port(Top)']}  "
                                  f"(RTP={r['RTP封包數']} UDP={r['UDP封包數(備援)']})")

        self.progress.emit(100)
        self.done.emit(sdp_map, rtp_rows, rtp_by_dst, compare_rows)


class MainUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SIP / RTP 單向無聲分析工具（含自訂SIP埠、暴力掃SDP、Decode-As）")
        self.resize(1120, 780)

        # 上方：選檔 + A/B IP + SIP 埠
        top = QHBoxLayout()
        self.ed_path = QLineEdit()
        btn_browse = QPushButton("選擇 pcap/pcapng"); btn_browse.clicked.connect(self.on_browse)
        top.addWidget(QLabel("封包檔：")); top.addWidget(self.ed_path, 1); top.addWidget(btn_browse)

        ipbox = QHBoxLayout()
        self.ed_a = QLineEdit(); self.ed_b = QLineEdit()
        self.ed_a.setPlaceholderText("A 端 IP（例如 192.168.8.92）")
        self.ed_b.setPlaceholderText("B 端 IP（例如 192.168.9.70）")
        ipbox.addWidget(QLabel("A：")); ipbox.addWidget(self.ed_a)
        ipbox.addWidget(QLabel("B：")); ipbox.addWidget(self.ed_b)

        sipbox = QHBoxLayout()
        self.ed_sip_ports = QLineEdit("5060,5080,6060")
        self.ed_sip_ports.setToolTip("用逗號分隔；會同時對 TCP/UDP 進行 Decode-As SIP")
        sipbox.addWidget(QLabel("SIP 埠（TCP/UDP）："))
        sipbox.addWidget(self.ed_sip_ports)

        # 可選：手動指定 tshark.exe 路徑
        tsh = QHBoxLayout()
        self.ed_tshark = QLineEdit()
        self.ed_tshark.setPlaceholderText(r"（選填）tshark.exe 路徑，例如 C:\Program Files\Wireshark\tshark.exe")
        btn_tshark = QPushButton("選擇 tshark.exe"); btn_tshark.clicked.connect(self.on_browse_tshark)
        tsh.addWidget(QLabel("tshark：")); tsh.addWidget(self.ed_tshark, 1); tsh.addWidget(btn_tshark)

        # 控制列
        ctrl = QHBoxLayout()
        self.btn_start = QPushButton("開始分析"); self.btn_stop = QPushButton("停止")
        self.btn_export = QPushButton("匯出 RTP CSV"); self.btn_export.setEnabled(False)
        self.chk_autosave = QCheckBox("分析完自動匯出 CSV")
        self.btn_start.clicked.connect(self.on_start)
        self.btn_stop.clicked.connect(self.on_stop)
        self.btn_export.clicked.connect(self.on_export)
        ctrl.addWidget(self.btn_start); ctrl.addWidget(self.btn_stop); ctrl.addStretch(1)
        ctrl.addWidget(self.chk_autosave); ctrl.addWidget(self.btn_export)

        # 進度 + 視圖（分割）
        self.bar = QProgressBar(); self.bar.setRange(0, 100); self.bar.setValue(0)
        self.log = QTextEdit(); self.log.setReadOnly(True)

        self.tbl_rtp = QTableWidget(0, 7)
        self.tbl_rtp.setHorizontalHeaderLabels(["來源IP","來源埠","目的IP","目的埠","SSRC","PT(載荷)","封包數"])
        self.tbl_rtp.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tbl_rtp.setEditTriggers(QTableWidget.NoEditTriggers)
        self.tbl_rtp.setSelectionBehavior(QTableWidget.SelectRows)

        self.tbl_cmp = QTableWidget(0, 8)
        self.tbl_cmp.setHorizontalHeaderLabels(
            ["方向","SDP_IP","SDP_Port","實際目的IP","實際目的Port(Top)","RTP封包數","UDP封包數(備援)","一致性"]
        )
        self.tbl_cmp.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tbl_cmp.setEditTriggers(QTableWidget.NoEditTriggers)

        split = QSplitter(Qt.Vertical)
        box_top = QWidget(); lt = QVBoxLayout(box_top); lt.addWidget(QLabel("分析日誌")); lt.addWidget(self.log)
        box_mid = QWidget(); lm = QVBoxLayout(box_mid); lm.addWidget(QLabel("SDP 公布 vs 實際 RTP 比對")); lm.addWidget(self.tbl_cmp)
        box_bot = QWidget(); lb = QVBoxLayout(box_bot); lb.addWidget(QLabel("RTP 串流總覽")); lb.addWidget(self.tbl_rtp)
        split.addWidget(box_top); split.addWidget(box_mid); split.addWidget(box_bot)
        split.setSizes([240, 200, 280])

        layout = QVBoxLayout(self)
        layout.addLayout(top); layout.addLayout(ipbox); layout.addLayout(sipbox)
        layout.addLayout(tsh); layout.addLayout(ctrl)
        layout.addWidget(self.bar); layout.addWidget(split, 1)

        self.worker = None
        self._last_rtp_rows = []

        if _PYSHARK_ERR is not None:
            self.append_log("⚠️ 尚未安裝 pyshark 或無法載入。")
            self.append_log("請先安裝 Wireshark（含 tshark），再 pip install pyshark。")
            self.append_log("原始錯誤：" + _PYSHARK_ERR)

    def append_log(self, text): self.log.append(text)

    def on_browse(self):
        path, _ = QFileDialog.getOpenFileName(self, "選擇封包檔", "", "PCAP Files (*.pcap *.pcapng);;All Files (*)")
        if path: self.ed_path.setText(path)

    def on_browse_tshark(self):
        path, _ = QFileDialog.getOpenFileName(self, "選擇 tshark.exe", "", "tshark.exe (tshark.exe);;All Files (*)")
        if path: self.ed_tshark.setText(path)

    def on_start(self):
        path = self.ed_path.text().strip()
        if not path: return human_err("請先選擇 .pcap / .pcapng 檔。")
        if not os.path.exists(path): return human_err("檔案不存在。")

        self.tbl_rtp.setRowCount(0); self.tbl_cmp.setRowCount(0)
        self.log.clear(); self.bar.setValue(0)
        tshark_path = self.ed_tshark.text().strip() or None

        sip_ports = [p.strip() for p in self.ed_sip_ports.text().split(",") if p.strip()]
        self.worker = AnalyzerThread(path, self.ed_a.text(), self.ed_b.text(), sip_ports, tshark_path=tshark_path)
        self.worker.progress.connect(self.bar.setValue)
        self.worker.log.connect(self.append_log)
        self.worker.error.connect(lambda m: human_err(m))
        self.worker.done.connect(self.on_done)
        self.worker.start()
        self.append_log(f"開始分析：{path}")

    def on_stop(self):
        if self.worker and self.worker.isRunning():
            self.worker.stop(); self.append_log("已送出停止要求，請稍候...")
        else:
            self.append_log("沒有正在執行的分析。")

    def on_done(self, sdp_map, rtp_rows, rtp_by_dst, compare_rows):
        self._last_rtp_rows = rtp_rows
        self.btn_export.setEnabled(True)

        # 填 RTP 表
        self.tbl_rtp.setRowCount(len(rtp_rows))
        for i, r in enumerate(rtp_rows):
            self.tbl_rtp.setItem(i, 0, QTableWidgetItem(str(r["src_ip"])))
            self.tbl_rtp.setItem(i, 1, QTableWidgetItem(str(r["src_port"])))
            self.tbl_rtp.setItem(i, 2, QTableWidgetItem(str(r["dst_ip"])))
            self.tbl_rtp.setItem(i, 3, QTableWidgetItem(str(r["dst_port"])))
            self.tbl_rtp.setItem(i, 4, QTableWidgetItem(str(r["ssrc"])))
            self.tbl_rtp.setItem(i, 5, QTableWidgetItem(str(r["pt"])))
            self.tbl_rtp.setItem(i, 6, QTableWidgetItem(str(r["packets"])))

        # A→B 醒目
        ip_a = self.findChild(QLineEdit, None).text() if self.findChild(QLineEdit, None) else ""
        # 保留先前的醒目法：直接用當前欄位
        ip_a = self.findChildren(QLineEdit)[1].text().strip() if len(self.findChildren(QLineEdit))>1 else ""
        ip_b = self.findChildren(QLineEdit)[2].text().strip() if len(self.findChildren(QLineEdit))>2 else ""
        brush = QBrush(QColor(255, 252, 200)); bold = QFont(); bold.setBold(True)
        for i in range(self.tbl_rtp.rowCount()):
            if self.tbl_rtp.item(i,0).text()==ip_a and self.tbl_rtp.item(i,2).text()==ip_b:
                for c in range(self.tbl_rtp.columnCount()):
                    item = self.tbl_rtp.item(i,c); item.setBackground(brush); item.setFont(bold)

        # 比對表
        self.tbl_cmp.setRowCount(len(compare_rows))
        for i, r in enumerate(compare_rows):
            cols = ["方向","SDP_IP","SDP_Port","實際目的IP","實際目的Port(Top)","RTP封包數","UDP封包數(備援)","一致性"]
            for c,k in enumerate(cols):
                self.tbl_cmp.setItem(i, c, QTableWidgetItem(str(r[k])))
            verdict = r["一致性"]
            color = QColor(208,255,208) if verdict=="一致" else (QColor(255,230,200) if verdict=="不一致" else QColor(255,210,210))
            for c in range(self.tbl_cmp.columnCount()):
                self.tbl_cmp.item(i,c).setBackground(QBrush(color))

        # SDP 摘要
        self.append_log("=" * 60)
        self.append_log("SDP 公布（依來源 IP）：")
        if not sdp_map:
            self.append_log("  （沒抓到 SDP，可能 pcap 未包含 200 OK/answer，或 SIP 走 TLS）")
        for sip, s in sdp_map.items():
            self.append_log(f"  {sip} 公布 c={s['conn_ip']}  m=audio {s['audio_port']}  fmt={s['payloads']}")

        if self.chk_autosave.isChecked(): self.on_export()
        self.append_log("\n完成。")

    def on_export(self):
        if not self._last_rtp_rows:
            return human_err("沒有可匯出的 RTP 資料。先執行分析。")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path, _ = QFileDialog.getSaveFileName(self, "匯出 CSV", f"rtp_streams_{ts}.csv", "CSV (*.csv)")
        if not path: return
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=["來源IP","來源埠","目的IP","目的埠","SSRC","PT(載荷)","封包數"])
                w.writeheader()
                for r in self._last_rtp_rows:
                    w.writerow({
                        "來源IP": r["src_ip"], "來源埠": r["src_port"],
                        "目的IP": r["dst_ip"], "目的埠": r["dst_port"],
                        "SSRC": r["ssrc"], "PT(載荷)": r["pt"], "封包數": r["packets"]
                    })
            self.append_log(f"已匯出：{path}")
        except Exception as e:
            human_err(f"匯出失敗：{e}")


def main():
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    app = QApplication(sys.argv)
    ui = MainUI(); ui.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
