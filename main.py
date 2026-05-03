'''
@ASSESSME.USERID:ms1648, nk3899, ls3385
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
from scapy.all import IP, TCP, UDP, ICMP, ARP


class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")
        self.root.geometry("1400x760")

        self.capture = Capture()
        self._setup_gui()

    def _setup_gui(self):
        top = tk.Frame(self.root, pady=8)
        top.pack(fill=tk.X)

        self.start_btn = ttk.Button(top, text="Start", command=self.start)
        self.start_btn.pack(side=tk.LEFT, padx=8)

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
        self.root.after(
            0,
            self._add_packet_to_ui,
            num,
            src,
            dst,
            proto,
            rel_time,
            length,
            src_port,
            dst_port
        )

    def _add_packet_to_ui(self, num, src, dst, proto, rel_time, length, src_port, dst_port):
        self.display.add_packet(
            num,
            src,
            dst,
            proto,
            rel_time=rel_time,
            length=length,
            src_port=src_port,
            dst_port=dst_port,
            original_idx=num - 1
        )

        self.filters.show_stats(self.capture.packets)
        self.status.config(text=f"Capturing... {num} packets")

    def _on_packet_click(self, original_idx):
        pkt = self.capture.packets[original_idx]

        if pkt:
            self.display.show_details(pkt)

    def _on_filter_apply(self):
        filtered = self.filters.filter_packets(self.capture.packets)

        self.display.clear_table()

        idx_map = {id(p): i for i, p in enumerate(self.capture.packets)}

        for row_num, pkt in enumerate(filtered, 1):
            original_idx = idx_map.get(id(pkt), row_num - 1)

            src = pkt[IP].src if pkt.haslayer(IP) else "N/A"
            dst = pkt[IP].dst if pkt.haslayer(IP) else "N/A"
            proto = self._proto(pkt)

            src_port = pkt[TCP].sport if pkt.haslayer(TCP) else (
                pkt[UDP].sport if pkt.haslayer(UDP) else "N/A"
            )

            dst_port = pkt[TCP].dport if pkt.haslayer(TCP) else (
                pkt[UDP].dport if pkt.haslayer(UDP) else "N/A"
            )

            self.display.add_packet(
                row_num,
                src,
                dst,
                proto,
                length=len(pkt),
                src_port=src_port,
                dst_port=dst_port,
                original_idx=original_idx
            )

        self.filters.show_stats(filtered)
        self.status.config(text=f"Showing {len(filtered)} filtered packets")

    def load(self):
        file = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap")])

        if file:
            packets = self.capture.load(file)

            self.display.clear_table()

            for num, pkt in enumerate(packets, 1):
                src = pkt[IP].src if pkt.haslayer(IP) else "N/A"
                dst = pkt[IP].dst if pkt.haslayer(IP) else "N/A"
                proto = self._proto(pkt)

                src_port = pkt[TCP].sport if pkt.haslayer(TCP) else (
                    pkt[UDP].sport if pkt.haslayer(UDP) else "N/A"
                )

                dst_port = pkt[TCP].dport if pkt.haslayer(TCP) else (
                    pkt[UDP].dport if pkt.haslayer(UDP) else "N/A"
                )

                self.display.add_packet(
                    num,
                    src,
                    dst,
                    proto,
                    length=len(pkt),
                    src_port=src_port,
                    dst_port=dst_port,
                    original_idx=num - 1
                )

            self.filters.show_stats(packets)
            self.status.config(text=f"Loaded {len(packets)} packets from the file")
            messagebox.showinfo("Load", f"Loaded {len(packets)} packets.")

    def save(self):
        if not self.capture.packets:
            messagebox.showwarning("Save", "Nothing to save!")
            return

        file = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap")]
        )

        if file:
            self.capture.save(file)
            messagebox.showinfo("Saved", f"Saved {len(self.capture.packets)} packets.")

    def clear(self):
        if self.capture.capturing:
            messagebox.showwarning("Capturing", "Stop capturing first!")
            return

        self.capture.clear()
        self.display.clear_table()
        self.display.clear_details()
        self.filters.show_stats([])
        self.status.config(text="Cleared")

    @staticmethod
    def _proto(pkt):
        if pkt.haslayer(TCP):
            return "TCP"
        if pkt.haslayer(UDP):
            return "UDP"
        if pkt.haslayer(ICMP):
            return "ICMP"
        if pkt.haslayer(ARP):
            return "ARP"
        return "Other"


if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()