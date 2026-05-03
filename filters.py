'''
@ASSESSME.USERID:nk3899
@ASSESSME.AUTHOR: Natko Kolbas
@ASSESSME.DESCRIPTION: Programming Project
@ASSESSME.ANALYZE: YES
@ASSESSME.INTENSITY:LOW
'''

import tkinter as tk
from tkinter import scrolledtext, ttk
from scapy.all import TCP, UDP, ICMP, ARP, IP

class Filters: 
    def __init__(self, parent):
        self.parent = parent
        self.apply_callback = None
        self._make_gui()
        
    def _make_gui(self):
        filter_box = tk.LabelFrame(self.parent, text="Filter", font=("Arial", 10, "bold"))  
        filter_box.pack(fill=tk.X, padx=10, pady=10)
                        
        def _row(label_text):
            row = tk.Frame(filter_box)
            row.pack(fill=tk.X, padx=5, pady=3)
            tk.Label(row, text=label_text, width=10, anchor="w").pack(side=tk.LEFT)
            entry = tk.Entry(row, width=18)
            entry.pack(side=tk.LEFT)
            return entry
        '''
part copied from ther last repository
'''
        proto_row = tk.Frame(filter_box)
        proto_row.pack(fill=tk.X, padx=5, pady=3)
        tk.Label(proto_row, text="Protocol:", width=10, anchor="w").pack(side=tk.LEFT)
        self.protocol = tk.StringVar(value="All")
        tk.OptionMenu(proto_row, self.protocol, "All", "TCP", "UDP", "ICMP", "ARP").pack(side=tk.LEFT)
        
        self.src_ip = _row("Src IP:")
        self.dst_ip = _row("Dst IP:")
        self.port   = _row("Port:")
        
        btn_row = tk.Frame(filter_box)
        btn_row.pack(fill=tk.X, padx=5, pady=6)
        ttk.Button(btn_row, text="Apply filter", command=self.apply).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(btn_row, text="Reset",command=self.reset).pack(side=tk.LEFT)
        
        status_box = tk.LabelFrame(self.parent, text="Statistics", font=("Arial", 10, "bold"))
        status_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.stats = scrolledtext.ScrolledText(status_box, width=28, height=20, font=("Courier",9 ))
        self.stats.pack(fill=tk.BOTH, expand=True)
        
        '''
part copied from ther last repository
'''
    def filter_packets(self,all_packets):
        proto_filter = self.protocol.get()
        src_filter = self.src_ip.get().strip()
        dst_filter = self.dst_ip.get().strip()
        port_filter = self.port.get().strip()
        _layer_map = {"TCP": TCP, "UDP": UDP, "ICMP": ICMP, "ARP": ARP}
        result = []
        for pkt in all_packets:
            if proto_filter != "All":
                if not pkt.haslayer(_layer_map[proto_filter]):
                    continue
            if src_filter:
                if not pkt.haslayer(IP) or src_filter not in pkt[IP].src:
                    continue
            if dst_filter:
                if not pkt.haslayer(IP) or dst_filter not in pkt[IP].dst:
                    continue
            if port_filter:
                try:
                    p = int(port_filter)
                    matched = False
                    if pkt.haslayer(TCP):
                        matched = pkt[TCP].sport == p or pkt[TCP].dport == p
                    elif pkt.haslayer(UDP):
                        matched = pkt[UDP].sport == p or pkt[UDP].dport == p
                    if not matched:
                        continue
                except ValueError:
                    pass
            result.append(pkt)
        return result
    
    def show_stats(self, packets):
        self.stats.delete(1.0, tk.END)
        total = len(packets)
        total_bytes = sum(len(p) for p in packets)
        
        self.stats.insert(tk.END, f"Total Packets: {total}\n")
        self.stats.insert(tk.END, f"Total Bytes: {total_bytes}\n")
        if total == 0:
            return 
        counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "Other": 0}
        for p in packets:
            if p.haslayer(TCP):
                counts["TCP"] += 1
            elif p.haslayer(UDP):
                counts["UDP"] += 1
            elif p.haslayer(ICMP):
                counts["ICMP"] += 1
            elif p.haslayer(ARP):
                counts["ARP"] += 1
            else:
                counts["OTHERS"] += 1
        self.stats.insert(tk.END, "Protocol Breakdown:\n")
        self.stats.insert(tk.END, "-" * 24 + "\n")
        for proto, cnt in counts.items():
            pct = cnt / total * 100
            self.stats.insert(tk.END, f" {proto:<6}: {cnt:>5}  ({pct:.1f}%)\n")
                
    def apply(self):
        if self.apply_callback:
            self.apply_callback()
            
    def reset(self):
        self.protocol.set("All")
        self.src_ip.delete(0, tk.END)
        self.dst_ip.delete(0, tk.END)
        self.port.delete(0, tk.END)
        if self.apply_callback:
            self.apply_callback()
            
    def set_apply_callback(self, func):
        self.apply_callback = func