'''
@ASSESSME.USERID:ms1648
@ASSESSME.AUTHOR: Marko Slivaric
@ASSESSME.DESCRIPTION: Programming Project
@ASSESSME.ANALYZE: YES
@ASSESSME.INTENSITY:LOW
'''

import tkinter as tk
from tkinter import ttk, scrolledtext

__PROTO_COLORS = {
    "TCP" : "#dff0d8",
    "UDP" : "#d9edf7",
    "ICMP" : "fcf8e3",
    "ARP" : "#f2dede",
    "Other" : "#f5f5f5"
}

_COLUMNS = ( "No", "Time", "Source IP", "Dest IP", "Src Port", "Dist Port", "Protocol", "Lenght")
_COL_WIDTHS = {"No" : 45, "Time" : 75, "Source IP" : 130, "Dest IP" : 130, "Src Port" : 70, "Dist Port" : 70, "Protocol" : 70, "Lenght" : 60}

class Display:
    def __init__(self, parent):
        self.parent = parent
        self.click_callback = None
        self._make_gui()

    def _make_gui(self):
        tk.Label(self.parent, text = "Packets", font=("Arial", 12, "bold")).pack()
        table_frame = tk.Frame(self.parent)
        table_frame.pack(fill=tk.BOTH, expand=True)
        scroll_y = ttk.Scrollback(table_frame, orient = tk.VERTICAL)
        scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        self.table = ttk.Treeview(table_frame, columns = _COLUMNS, show="headings", height=15, yscrollcommand = scroll_y.set)

        scroll_y.config(command = self.table.yview)
        for col in _COLUMNS:
            self.table.heading(col, text=col)
            self.table.column(col, width = _COL_WIDTHS[col], anchor=tk.CENTER)
        for proto, color in __PROTO_COLORS.items():
            self.table.tag_configure(proto, background=color)
        self.table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.table.bind("<<TreeviewSelect>>", self._clicked)
        tk.Label(self.parent, text="Packet Details", font=("Arial", 12, "bold")).pack()
        self.details = scrolledtext.ScrolledText(self.parent, height=15, font=("Courier", 9))
        self.details.pack(fill=tk.BOTH, expand=True)
        
    def add_packet(self, num, src, dst, proto, time_rel="", length="", src_port="",dst_port="", original_idx = None ):
        if original_idx is None:
            original_idx = num-1
        time_str = f"{time_rel:.3f}" if isinstance(time_rel, float) else str(time_rel)
        values = (num, time_str, src, dst,
                  src_port if src_port != "" else "-",
                  dst_port if dst_port != "" else "-",
                  proto, length)
        proto_tag = proto if proto in __PROTO_COLORS else "Other"
        self.table.insert("", tk.END, values=values, tags=(proto_tag, str(original_idx)))

    def clear_table(self):
        for item in self.table.get_children():
            self.table.delete(item)

    def clear_details(self):
        self.details.delete(1.0, tk.END)

    def show_details(self, pkt):
        self.details.delete(1.0, tk.END)
        self.details.insert(tk.END, "=== PACKET DETAILS ===\n\n")
        self.details.insert(tk.END, pkt.show(dump=True))
        self.details.insert(tk.END, "\n\n=== HEX + ASCII PAYLOAD === \n\n")
        data = bytes(pkt)
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            self.details.insert(tk.END, f"{i:04x} {hex_part:<47} {ascii_part}\n")

    def _clicicked(self, event):
        sel = self.table.selection()
        if not sel or not self.click_callback:
            return
        tags = self.table.item(sel[0], "tags")
        if len(tags) >2:
            original_idx = int(tags[1])
        else:
            original_idx = int(self.table.item(sel[0])["values"][0]) -1
        self.click_callback(original_idx)

    def set_click_callback(self,func):
        self.click_callback = func