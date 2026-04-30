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