'''
@ASSESSME.USERID:ms1648, nk, ls3385
@ASSESSME.AUTHOR: Marko Slivaric, Natko Kolbas, Lovro Sekelj
@ASSESSME.DESCRIPTION: Programming Project
@ASSESSME.ANALYZE: YES
@ASSESSME.INTENSITY:LOW
'''

import tkinter as tk
from tkinter import messagebox, filedialog, ttk
from capture import Capture
from display import Display
from filters import Filters
from scapy.all import IP, TCP, UPD, ICMP, ARP

class App:
    def __init__(self, root):
        self.root = root
        self.root.title = ("Packet Sniffer")
        self.root.geometry("14000x760")
        ttk.Style().theme_use("calm")
        self.capture = Capture()
        self._setup_gui()

    def _setup_gui(self):
        top = tk.Frame(self.root, pady=8)
        top.pack(fill=tk.X)
        self.start_btn = ttk.Button(top, text="Start", command=self.start)
        self.start_btn.pack(side =tk.LEFT, padx=8)
        self.stop_btn = ttk.Button(top, text="Stop", command=self.stop, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT)
        ttk.Button(top, text="Load PCAP", command=self.load).pack(side=tk.LEFT, padx=6)
        ttk.Button(top, text="Save PCAP", command=self.save).pack(side=tk.LEFT, padx=3)
        ttk.Button(top, text="Clear", command=self.clear).pack(side=tk.LEFT, padx=6)
        main = tk.Frame(self.root)
        main.pack(fill=tk.BOTH, expand=True)
        left = tk.Frame(main)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.display = Display(left)
        self.display.set_click_callback(self._on_packet_click)
        right = tk.Frame(main, width=270)
        right.pack(side=tk.RIGHT, fill=tk.Y, padx=5, pady=5)
        right.pack_propagate(False)
        self.filters = Filters(right)
        self.filters.set_apply_callback(self._on_filter_apply)
        self.status = tk.Label(self.root, text="Ready", relief=tk.SUNKEN, anchor="w", padx=6)
        self.status.pack(fill=tk.X)

    def start(self):
        self.capture.start(callback=self._on_new_packet)
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status.config(text="Capturing...")

    def stop(self):
        count = self.capture.stop()
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status.config(text=f"Stopped - {count} packets captured")
        self.filters.show_stats(self.capture.packets)

    def _on_new_packet(self, pkt, num, src, dst, proto, rel_time, length, src_port, dst_port):
        self.root.after(0, self._add_packet_to_ui, num, src, dst, proto, rel_time, length, src_port, dst_port)
    
    def _add_packets_to_ui(self, num, src,dst, proto, rel_time, length, src_port, dst_port):
        self.display.add_packet(num, src, dst, proto, 
                                rel_time = rel_time, 
                                length = length, 
                                src_port = src_port, 
                                dst_port=dst_port,
                                original_idx=num-1)
        self.filters.show_stats(self.capture.packets)
        self.status.config(text=f"Capturing... {num} packets")






