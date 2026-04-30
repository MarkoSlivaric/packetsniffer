'''
@ASSESSME.USERID:ls3385
@ASSESSME.AUTHOR: Lovro Sekelj
@ASSESSME.DESCRIPTION: Programming Project
@ASSESSME.ANALYZE: YES
@ASSESSME.INTENSITY:LOW
'''

import time
import threading
from scapy.all import sniff, wrpcap, rdpcap, IP, TCP, UDP, ICMP, ARP

class Capture:
    def __init__(self):
        self.packets = []
        self.capturing = False
        self._callback = None
        self._start_time = None

    def start(self, callback):
        self.capturing = True
        self._callback = callback
        self._start_time = time.time()
        thread = threading.Thread(target=self._capture_loop, daemon=True)
        thread.start()

    def _capture_loop(self):
        while self.capturing:
            sniff(prn=self._got_packet, store=0, timeout=1, stop_filter=lambda x:not self.capturing)

    def _got_packet(self, pkt):
        if not self.capturing:
            return
        self.packets.append(pkt)
        num = len(self.packets)
        rel_time = time.time() - self._start_time
        src = pkt[IP].src if pkt.haslayer(IP) else "N/A"
        dst = pkt[IP].dst if pkt.haslayer(IP) else "N/A"
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
        if pkt.haslayer(TCP):
            src_port, dst_port = pkt[TCP].sport, pkt[TCP].dport
        elif pkt.haslayer(UDP):
            src_port, dst_port = pkt[UDP].sport, pkt[UDP].dport
        else:
            src_port, dst_port = "", ""
        self._callback(pkt, num, src, dst, proto, rel_time, len(pkt), src_port, dst_port)

    def stop(self):
        self.capturing = False
        return len(self.packets)
    
    def get_packet(self, index):
        if 0 <= index < len(self.packets):
            return self.packets[index]
        return None
    
    def save(self, filename):
        wrpcap(filename, self.packets)

    def load(self, filename):
        self.packets = list(rdpcap(filename))
        return self.packets
    
    def clear(self):
        self.packets = []
        self._start_time = None