'''
@ASSESSME.USERID:ms1648
@ASSESSME.AUTHOR: Marko Slivaric
@ASSESSME.DESCRIPTION: Programming Project
@ASSESSME.ANALYZE: YES
@ASSESSME.INTENSITY:LOW
'''

"""
display.py - packet tavle + details panel UI

Two stacked widgets:
1. ttk.Treeview that lists every packet with its key fields
2. ScrolledText panel that, when a row is clicked, shows the full layered breakdown from Scapy plus a Wireshark-style hex/ASCII dump of the raw bytes

Rows are tinted by protovol for quick visual scanning
"""

import tkinter as tk
from tkinter import ttk, scrolledtext

#Background tint applied to each row based on its protocol
#Keys must match the strings produced by capture.py / main.py._proto()

PROTO_COLORS = {
    "TCP": "#1f7a1f",   # dark green
    "UDP": "#1f4e79",   # dark blue
    "ICMP": "#8a6d1d",  # dark yellow/brown
    "ARP": "#7a1f1f",   # dark red
    "Other": "#444444"  # dark gray
}

#Column order for the packet tavle
#Changing this also changes the order of values that must be passes into add_packet()
_COLUMNS = ( "No", "Time", "Source IP", "Dest IP", "Src Port", "Dest Port", "Protocol", "Length")
#Pixel widths for each column - tuned so IPv4 addresses fit comfortably
_COL_WIDTHS = {"No" : 45, "Time" : 75, "Source IP" : 130, "Dest IP" : 130, "Src Port" : 70, "Dest Port" : 70, "Protocol" : 70, "Length" : 60}

class Display:
    """
    Owns the packet table (Treeview) and the details/hex panel
    """
    def __init__(self, parent):
        self.parent = parent
        #Set later via set_click_callback() - called when the user clicks a row with the original packet index as argument
        self.click_callback = None
        self._make_gui()

    def _make_gui(self):
        """
        Build the table on top, details panel underneath
        """
        # Header label for the packet table
        tk.Label(self.parent, text = "Packets", font=("Arial", 12, "bold"), bg="#3498db", fg="white", pady=5).pack(fill=tk.X)
        #Frame holds the table + its bertical scrollbar side by side
        table_frame = tk.Frame(self.parent, bg="white")
        table_frame.pack(fill=tk.BOTH, expand=True)
        scroll_y = ttk.Scrollbar(table_frame, orient = tk.VERTICAL)
        scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        #show="headings" hides the default empty first column the Treeview adds for a tree icon - we only want flat rows
        self.table = ttk.Treeview(table_frame, columns = _COLUMNS, show="headings", height=15, yscrollcommand = scroll_y.set)

        #wire the scrollbar to drive the table view
        scroll_y.config(command = self.table.yview)

        #Apply column headers and widths from the constants above
        for col in _COLUMNS:
            self.table.heading(col, text=col)
            self.table.column(col, width = _COL_WIDTHS[col], anchor=tk.CENTER)

            #Register a tag per protocol so we can tint rows by setting tags
        for proto, color in PROTO_COLORS.items():
            self.table.tag_configure(proto, background=color)
        self.table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        #Fire _clicked whenever the user selects a different row

        self.table.bind("<<TreeviewSelect>>", self._clicked)
        
        #Header label for the details panel
        tk.Label(self.parent, text="Packet Details", font=("Arial", 12, "bold"), bg="#3498db", fg="white", pady=5).pack(fill=tk.X)
        #Monospace font so the hex dump columns line up correctly
        self.details = scrolledtext.ScrolledText(
            self.parent,
            height=15,
            font=("Courier New", 10),
            bg="#0f172a",
            fg="#e2e8f0",
            insertbackground="white"
        )
        self.details.pack(fill=tk.BOTH, expand=True)
        
    def add_packet(self, num, src, dst, proto, time_rel="", length="", src_port="",dst_port="", original_idx = None ):
        """
        Insert one packet as a new row in the table.

        original_idx = the packet's index in capture.packets
        Stored as a row tag so that even after filtering reorders or hides rows, clicking still resolves to the right Scapy object
        Defaults to (num-1) for live capture
        """
        if original_idx is None:
            original_idx = num-1

            #format the relative timestampt to milliseconds when it's a float
        time_str = f"{time_rel:.3f}" if isinstance(time_rel, float) else str(time_rel)

        #replace empty port strings with "-" so the column never looks blank
        values = (num, time_str, src, dst,
                  src_port if src_port != "" else "-",
                  dst_port if dst_port != "" else "-",
                  proto, length)
        
        #pick the color tag and stash original_idx as a second tag for the click handler
        proto_tag = proto if proto in PROTO_COLORS else "Other"
        self.table.insert("", tk.END, values=values, tags=(proto_tag, str(original_idx)))

    def clear_table(self):
        """
        Remove every row from the packet table
        """
        for item in self.table.get_children():
            self.table.delete(item)

    def clear_details(self):
        """
        Empty the details/hex panel
        """
        self.details.delete(1.0, tk.END)

    def show_details(self, pkt):
        """
        Render full details for one packet in the lower panel

        Two sections are written:
        1. Scapy's pkt.show(dump=True) output - human-readable layered breakdown of every header
        2. A hex/ASCII dump of the raw bytes, 16 bytes per row, in the same format Wireshark uses
        """
        self.details.delete(1.0, tk.END)
        self.details.insert(tk.END, "=== PACKET DETAILS ===\n\n")

        #dump=True returns the formatted layer breakdown as a string instead of printing it to stdout
        self.details.insert(tk.END, pkt.show(dump=True))
        self.details.insert(tk.END, "\n\n=== HEX + ASCII PAYLOAD === \n\n")
        #bytes(pkt) returns the raw on-the-wire octets including all headers - this is what would actually travel over the network
        data = bytes(pkt)
        #walk the byte buffer 16 at a time
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            #hex column: each byte as twi lowercase hex digits, space-separated
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            #ASCII column - printable bytes(32-126) shown as their character,
            #everything else replaced with "." so the output stays one line tall
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            #Layout - 4 digit offset, hex padded to 47 chars, then ASCII
            self.details.insert(tk.END, f"{i:04x} {hex_part:<47} {ascii_part}\n")

    def _clicked(self, event):
        """
        Treeview selection handler - forwards the click to main.py
        """
        sel = self.table.selection()
        if not sel or not self.click_callback:
            return
        
        #the first tag is the protocol color, the second is the original packet index we stored in add_packet()
        tags = self.table.item(sel[0], "tags")
        if len(tags) >1:
            original_idx = int(tags[1])
        else:
            #fallback for vary old rows that might not have the index tag
            original_idx = int(self.table.item(sel[0])["values"][0]) -1
        self.click_callback(original_idx)

    def set_click_callback(self,func):

        """
        Register the function called when a packet row is clicked
        """
        self.click_callback = func