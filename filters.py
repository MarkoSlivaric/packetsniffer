'''
@ASSESSME.USERID:nk3899
@ASSESSME.AUTHOR: Natko Kolbas
@ASSESSME.DESCRIPTION: Programming Project
@ASSESSME.ANALYZE: YES
@ASSESSME.INTENSITY:LOW
'''

"""
filters.py - filter UI + statistics panel

Right-hand sidebar of the application. 
Two main sections:
1. Filter box - protocol dropdown + Src IP / Dst IP / Port text fields, plus Apply and Reset buttons
2. Statistics - live packet count, byte total, and per-protocol breakdown(TCP / UDP / ICMP / ARP / Other)

filter_packets() does the actual filtering logic - given the full packet buffer, returns a new list
containing only the packets that match every non-empty filter criterion(logical AND across all fields)
"""

import tkinter as tk
from tkinter import scrolledtext, ttk
from scapy.all import TCP, UDP, ICMP, ARP, IP

class Filters: 
    """
    Builds the filter inputs + stats panel and exposes filter logic
    """
    def __init__(self, parent):
        self.parent = parent
        #Hooked up by main.py - called when user clicks Apply or Reset so the table can re-render with the filtered packets
        self.apply_callback = None
        self._make_gui()
        
    def _make_gui(self):
        """
        Build the two LabelFrames(Filter on top, Statistics below)
        """
        filter_box = tk.LabelFrame(self.parent, text="Filter", font=("Arial", 10, "bold"))  
        filter_box.pack(fill=tk.X, padx=10, pady=10)

        #Helper - make a lebeled text-entry row inside the filter box
        #Returns the Entry widget so we can read its value late
                        
        def _row(label_text):
            row = tk.Frame(filter_box)
            row.pack(fill=tk.X, padx=5, pady=3)
            tk.Label(row, text=label_text, width=10, anchor="w").pack(side=tk.LEFT)
            entry = tk.Entry(row, width=18)
            entry.pack(side=tk.LEFT)
            return entry
        '''
part copied from the last repository
'''
        proto_row = tk.Frame(filter_box)
        proto_row.pack(fill=tk.X, padx=5, pady=3)
        tk.Label(proto_row, text="Protocol:", width=10, anchor="w").pack(side=tk.LEFT)
        self.protocol = tk.StringVar(value="All")
        tk.OptionMenu(proto_row, self.protocol, "All", "TCP", "UDP", "ICMP", "ARP").pack(side=tk.LEFT)

        #Three text-entry filters. Empty string = filter not applied
        
        self.src_ip = _row("Src IP:")
        self.dst_ip = _row("Dst IP:")
        self.port   = _row("Port:")

        #Apply / Reset buttons. Apply runs the user's filter, Reset clears all fields back to defaults and re-applies
        
        btn_row = tk.Frame(filter_box)
        btn_row.pack(fill=tk.X, padx=5, pady=6)
        ttk.Button(btn_row, text="Apply filter", command=self.apply).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(btn_row, text="Reset",command=self.reset).pack(side=tk.LEFT)
        
        # Statistics panel (read-only scrolled text)
        status_box = tk.LabelFrame(self.parent, text="Statistics", font=("Arial", 10, "bold"))
        status_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        #Monospace font so the protocol breakdown columns line up
        self.stats = scrolledtext.ScrolledText(status_box, width=28, height=20, font=("Courier",9 ))
        self.stats.pack(fill=tk.BOTH, expand=True)
        
        '''
part copied from the last repository
'''
    def filter_packets(self,all_packets):
        """
        Return a new list containing only packets that match the filter

        Filter fields combine with logical AND - a packet must satisfy every non-empty criteria to be included
        Empty fields are skipped

        Criteria:
        Protocol - packet must have chosen Scapy layer
        Src IP - substring match against the IP header's src field
        Dst IP - substring match agains the IP header's dst field
        Port - exact match against TCP or UDP src OR dst port
        """
        #Read current filter values once at the start - avoids re-reading TK variables in the inner loop
        proto_filter = self.protocol.get()
        src_filter = self.src_ip.get().strip()
        dst_filter = self.dst_ip.get().strip()
        port_filter = self.port.get().strip()

        #Map protocol name -> Scapy layer class for the haslayer() check
        _layer_map = {"TCP": TCP, "UDP": UDP, "ICMP": ICMP, "ARP": ARP}
        result = []
        for pkt in all_packets:
            # Protocol filter
            if proto_filter != "All":
                if not pkt.haslayer(_layer_map[proto_filter]):
                    continue # skip packets without the requested layer
                #Source IP filter
                #Substring match
                #Packets without an IP header(like ARP) auto-fail this check
            if src_filter:
                if not pkt.haslayer(IP) or src_filter not in pkt[IP].src:
                    continue
                #Destination IP filter
            if dst_filter:
                if not pkt.haslayer(IP) or dst_filter not in pkt[IP].dst:
                    continue
                #Port filter
                #Matches if the port number appears as either the source or destination port
                #Only TCP/UDP have ports, everything else is excluded when a port filter is set
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
                    #User typed a non-numeric port - silently ignore the port field rather than crashing
                    pass
                #Made it through every filter - keep this packet
            result.append(pkt)
        return result
    
    def show_stats(self, packets):
        """
        Refresh teh statistics panel for the given packet list
        Called both during live capture and after applying a filter, so the displayed numbers always reflect what's currently visible in the table
        """
        self.stats.delete(1.0, tk.END)
        total = len(packets)
        #len(p) on a Scapy packet returns its on-the-wire size in bytes
        total_bytes = sum(len(p) for p in packets)
        
        self.stats.insert(tk.END, f"Total Packets: {total}\n")
        self.stats.insert(tk.END, f"Total Bytes: {total_bytes}\n")

        #Nothing else to show if the list is empty
        if total == 0:
            return 
        
        #Tally each protocol. "Other" catches anything that isn't one of the four we explicitly check
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
                counts["OTHER"] += 1
        #Pretty-printed breakdown with percentages
        self.stats.insert(tk.END, "Protocol Breakdown:\n")
        self.stats.insert(tk.END, "-" * 24 + "\n")
        for proto, cnt in counts.items():
            pct = cnt / total * 100
            self.stats.insert(tk.END, f" {proto:<6}: {cnt:>5}  ({pct:.1f}%)\n")
                
    def apply(self):
        """
        Apply button handler - asks main.py to re-render the table
        """
        if self.apply_callback:
            self.apply_callback()
            
    def reset(self):
        """
        Clear every filter field and re-apply
        """
        self.protocol.set("All")
        self.src_ip.delete(0, tk.END)
        self.dst_ip.delete(0, tk.END)
        self.port.delete(0, tk.END)
        if self.apply_callback:
            self.apply_callback()
            
    def set_apply_callback(self, func):
        """
        Register the function called whenever the filter changes
        """
        self.apply_callback = func