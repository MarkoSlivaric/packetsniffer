'''
@ASSESSME.USERID:ls3385
@ASSESSME.AUTHOR: Lovro Sekelj
@ASSESSME.DESCRIPTION: Programming Project
@ASSESSME.ANALYZE: YES
@ASSESSME.INTENSITY:LOW
'''


"""
capture.py - live packet capture and pcap file I/O

Wraps Scapy's sniff() in a background thread so the Tkinter GUI stays responsive
For every captured packet, parses the key header fields and pushes them to a callback provided by the GUI layer

Protocol header fields handled:
Ethernet - src MAC, dst MAC, EtherType
IP - src IP, dst IP, TTL, fragmentation flags, protocol number
TCP - src port, dst port, seq/ack numbers, control flags
UDP - src port, dst port, length
ICMP - type, code (no ports)
ARP - opcode, sender/target hardware + protocol addresses
"""

import time
import threading
#scapy.sniff -> live capture from a network interface
#scapy.wrpcap -> write packets to a .pcap file
#scapy.rdpcap ->read packets from a .pcap file
# IP/TCP/UDP/ICMP/ARP are layer classes used with haslayer()
from scapy.all import sniff, wrpcap, rdpcap, IP, TCP, UDP, ICMP, ARP

class Capture:
    """
    Owns the packet buffer and runs the sniff loop on a worker theread
    Attributes:
    packets - list of every Scapy packet captured this session
    capturing - flag the worker thread checks each loop iteration
    _callback - function invoked on the worker thread for each packet
    _start_time - wall-clock start of the current capture, userd for relative rimestamps show in the GUI
    """
    def __init__(self):
        self.packets = []
        self.capturing = False
        self._callback = None
        self._start_time = None

    def start(self, callback):
        """
        Spin up the background sniff thread.

        callback - called for every packet with parsed fields
        It runs on the worker thread, so the GUI side must marshal back to the main thread
        """
        self.capturing = True
        self._callback = callback
        #record start time so we can report each packet's relative arrival
        self._start_time = time.time()
        #daemon=True means the thread dies automatically when the main program exits - no orphaned sniffers left behind
        thread = threading.Thread(target=self._capture_loop, daemon=True)
        thread.start()

    def _capture_loop(self):
        """
        Run sniff() in 1-second bursts so Stop is responsive

        Scapy's sniff() blocks until its stop_filter returns True or its timeout fires
        Looping with timeout=1 means a Stop request takes effect within -1 second insted of waiting indefinitely
        """
        while self.capturing:
            sniff(prn=self._got_packet, store=0, timeout=1, stop_filter=lambda x:not self.capturing)

    def _got_packet(self, pkt):
        """
        Called by Scapy for every captuder packet
        Parses out the fields th GUI cares about and invokes the callback
        Note this runs one the worker thread - do NOT touch TK widgets here
        """

        #late stop - a packet may arrive between Stop bein pressed and sniff() exiting
        #Drop it so we don't store stale data
        if not self.capturing:
            return
        
        #keep a reference to the full Scapy packet so we can re-display it in detail when clicked
        self.packets.append(pkt)
        num = len(self.packets)
        rel_time = time.time() - self._start_time

        # IP header
        #src/dst IP only exist if there's an IP layer
        #Non-IP traffic like ARP gets "N/A" so the table still has something to show
        src = pkt[IP].src if pkt.haslayer(IP) else "N/A"
        dst = pkt[IP].dst if pkt.haslayer(IP) else "N/A"

        # Protocol identification
        #Check from most specific transport protocol down
        #order matters because TCP/UDP encapsulate iside IP - check the first
        if pkt.haslayer(TCP):
            proto = "TCP"
        elif pkt.haslayer(UDP):
            proto = "UDP"
        elif pkt.haslayer(ICMP):
            proto = "ICMP"
        elif pkt.haslayer(ARP):
            proto = "ARP"
        else:
            proto = "Other"

            # Transport ports
            #Only TCP and UDP define source/destionation ports(16-bit each)
            #ICMP/ARP have no port concept, so blank out those columns
        if pkt.haslayer(TCP):
            src_port, dst_port = pkt[TCP].sport, pkt[TCP].dport
        elif pkt.haslayer(UDP):
            src_port, dst_port = pkt[UDP].sport, pkt[UDP].dport
        else:
            src_port, dst_port = "", ""

        #Forward everything to the GUI layer
        #the packet object itself is also passed in case the GUI wants to inspect more fields
        self._callback(pkt, num, src, dst, proto, rel_time, len(pkt), src_port, dst_port)

    def stop(self):
        """
        Signal the sniff loop to exit
        Returns total packets captured
        """
        #The capture thread polls this flag every ~1s and exits cleanly
        self.capturing = False
        return len(self.packets)
    
    def get_packet(self, index):
        """
        Safely fetch a packet by its index in the buffer
        """
        if 0 <= index < len(self.packets):
            return self.packets[index]
        return None
    
    def save(self, filename):
        """
        Write the current buffer to a libpcap-format file
        """
        #wrpcap is Scapy's built-in pcap writer - compatible with Wireshark
        wrpcap(filename, self.packets)

    def load(self, filename):
        """
        Replace the current buffer with packets read from a pcap file
        """
        #rdpcap returns a PacketList, cast to list so indexing/len behave like the live-capture buffer
        self.packets = list(rdpcap(filename))
        return self.packets
    
    def clear(self):
        """
        Wipe the packet buffer
        """
        self.packets = []
        self._start_time = None
