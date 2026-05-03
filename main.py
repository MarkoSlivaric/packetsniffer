'''
@ASSESSME.USERID:ms1648, nk3899, ls3385
@ASSESSME.AUTHOR: Marko Slivaric, Natko Kolbas, Lovro Sekelj
@ASSESSME.DESCRIPTION: Programming Project
@ASSESSME.ANALYZE: YES
@ASSESSME.INTENSITY:LOW
'''

"""
main.py - entry point to the application

wires together the three components of the program:
-capture.py : background thread that shiffs packets with scapy
-display.py : packet table + details/hex panel
-filters.py : protocol/IP/port filter UI + statistics panel

the app class owns the tk root window, the toolbar(Start / Stop / Load / Save / Clear)
and the callbacks taht move data between the capture thread and the GUI on the main thread
"""

import tkinter as tk
from tkinter import messagebox, filedialog, ttk
from capture import Capture
from display import Display
from filters import Filters
# Scapy layer classes - used here only for protocol detection
# and pulling fields lik IP.src, TCP.sport, etc.
from scapy.all import IP, TCP, UDP, ICMP, ARP


class App:
    """
    Builds the GUI layout and acts as a controller between the Capture backend (which runs on a separate thread)
    adn the DIsplay/Filters widgets (which live on the Tk main thread)
    """
    def __init__(self, root):
        #store the Tk root window so other methods can schedule UI updates
        self.root = root
        self.root.title("Packet Sniffer")
        self.root.geometry("1400x760")

        #Capture object holds the packet buffer and runs the sniff loop
        self.capture = Capture()
        self._setup_gui()

    def _setup_gui(self):
        """
        Build the main layout: toolbar on rop, table + filters below
        """
        # Top Toolbar
        top = tk.Frame(self.root, pady=8)
        top.pack(fill=tk.X)

        #Start/Stop pair - stop is disabled until capture is running

        self.start_btn = ttk.Button(top, text="Start", command=self.start)
        self.start_btn.pack(side=tk.LEFT, padx=8)

        self.stop_btn = ttk.Button(top, text="Stop", command=self.stop, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT)

        #Load = open a savec .pcap, Save = write current packets to .pcak, Clear = drop the in-memory buffer

        ttk.Button(top, text="Load PCAP", command=self.load).pack(side=tk.LEFT, padx=6)
        ttk.Button(top, text="Save PCAP", command=self.save).pack(side=tk.LEFT, padx=3)
        ttk.Button(top, text="Clear", command=self.clear).pack(side=tk.LEFT, padx=6)

        # Main split
        main = tk.Frame(self.root)
        main.pack(fill=tk.BOTH, expand=True)

        # Left side: the Display widget(packet table + details/hex panel)
        left = tk.Frame(main)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.display = Display(left)
        # Hook up: when the user clicks a row, _on_packet_click is called with the packet's index in capture.packets
        self.display.set_click_callback(self._on_packet_click)

        # Right side: filters + stats, fixed width so it doesn't get squeezed
        right = tk.Frame(main, width=270)
        right.pack(side=tk.RIGHT, fill=tk.Y, padx=5, pady=5)
        right.pack_propagate(False)

        self.filters = Filters(right)
        #When the user clicks "Apply filter" the FIlters widget calls us back so we can re-render the table with only matching packets
        self.filters.set_apply_callback(self._on_filter_apply)

        # Status bar
        self.status = tk.Label(self.root, text="Ready", relief=tk.SUNKEN, anchor="w", padx=6)
        self.status.pack(fill=tk.X)

    def start(self):
        """
        Begin live packet capture and update button states
        """
        #_on_new_packet will be invoked on the capture thread for each packet
        self.capture.start(callback=self._on_new_packet)
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status.config(text="Capturing...")

    def stop(self):
        """
        Stop the capture thread and refresh statistics
        """
        count = self.capture.stop()
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status.config(text=f"Stopped - {count} packets captured")
        #Final stats refresh once capture has stopped
        self.filters.show_stats(self.capture.packets)

    def _on_new_packet(self, pkt, num, src, dst, proto, rel_time, length, src_port, dst_port):
        """
        Callback invoked by the capture thread for each new packet.
        TK widgets are NOT thread-safe so we cannot touch the GUI directly from this thread
        .root.after(0,...) schedules _add_packet_to_ui to run on the main thread as soon as it's idle
        """
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
        """
        Runs on the main thread - safe;y adds the packet to the table
        """
        self.display.add_packet(
            num,
            src,
            dst,
            proto,
            time_rel=rel_time,
            length=length,
            src_port=src_port,
            dst_port=dst_port,
            #original_idx maps a row back to its position in capture.packets which matters one filtering reorders or hides rows
            original_idx=num - 1
        )

        #Refresh stats and status bar live as packets stream in
        self.filters.show_stats(self.capture.packets)
        self.status.config(text=f"Capturing... {num} packets")

    def _on_packet_click(self, original_idx):
        """
        Show full details for the clicked packet
        """
        #Look up the original Scapy packet object using the inx that Display stored as a row tag
        pkt = self.capture.packets[original_idx]

        if pkt:
            self.display.show_details(pkt)

    def _on_filter_apply(self):
        """
        Re-render the table showing only packets that match the filter
        """
        # Filters returns a NEW list containing only packets that pass
        filtered = self.filters.filter_packets(self.capture.packets)

        #Wipe the table first so we don't double-up rows
        self.display.clear_table()

        #Map id(packet) -> position in the original list, we need this because filtering may drop or reorder
        # packets, withouth the map clicking a filtered row would open the wrong packet's details

        idx_map = {id(p): i for i, p in enumerate(self.capture.packets)}

        #Re-insert only the matching packets, re-numbered from 1
        for row_num, pkt in enumerate(filtered, 1):
            original_idx = idx_map.get(id(pkt), row_num - 1)

            #Pull header fields out of the packet(same logis as capture.py)

            src = pkt[IP].src if pkt.haslayer(IP) else "N/A"
            dst = pkt[IP].dst if pkt.haslayer(IP) else "N/A"
            proto = self._proto(pkt)

            #TCP and UDP both have .sport / .dport
            # ICMP / ARP don't have the concept of ports so we show "N/A"

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

            #Stats update to reflect the filtered subset, not the full buffer

        self.filters.show_stats(filtered)
        self.status.config(text=f"Showing {len(filtered)} filtered packets")

    def load(self):
        """
        Load a saved .pcap file from disk and populate the table
        """
        file = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap")])

        if file:
            #Capture.load() replaces the current buffet with file contents
            packets = self.capture.load(file)

            self.display.clear_table()

            # Same parsing pattern as live capture - extract IP, ports, proto

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
        """
        Write the current packet buffer to a .pcap file
        """
        #Guard - nothing useful wo save if bufer is empty
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
        """
        Empty the packets buffer and reset all panels
        """
        #Refuse if capture is still running - clearing mid-capture would cause confusing index mismatches
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
        """
        Return a short string label for the highest-level protocol present
        We check from most specific to least specific
        TCP/UDP is on top of IP, so they're cheched before falling back to "Other"
        """
        if pkt.haslayer(TCP):
            return "TCP"
        if pkt.haslayer(UDP):
            return "UDP"
        if pkt.haslayer(ICMP):
            return "ICMP"
        if pkt.haslayer(ARP):
            return "ARP"
        return "Other"

#standard python entry-point guard - only run the GUI when this file is executed directly
if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()