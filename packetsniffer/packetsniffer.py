import threading
import tkinter as tk
from tkinter import ttk
from scapy.all import sniff, get_if_list
from datetime import datetime
import requests

stop_sniffing = False
sniffer_thread = None
ip_cache = {}

def get_readable_interfaces():
    # Use the simpler get_if_list fallback; might show some device GUIDs
    return get_if_list()

def get_ip_country(ip):
    if ip in ip_cache:
        return ip_cache[ip]
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        data = res.json()
        country = data.get("country", "Unknown")
        ip_cache[ip] = country
        return country
    except:
        ip_cache[ip] = "Unknown"
        return "Unknown"

def packet_callback(packet):
    if 'IP' in packet:
        ip_src = packet['IP'].src
        ip_dst = packet['IP'].dst
        proto_num = packet.proto

        proto_name = "Other"
        sport = ""
        dport = ""

        if packet.haslayer('TCP'):
            proto_name = "TCP"
            sport = packet['TCP'].sport
            dport = packet['TCP'].dport
        elif packet.haslayer('UDP'):
            proto_name = "UDP"
            sport = packet['UDP'].sport
            dport = packet['UDP'].dport
        else:
            proto_name = str(proto_num)

        time_str = datetime.now().strftime('%H:%M:%S')

        src_country = get_ip_country(ip_src)
        dst_country = get_ip_country(ip_dst)

        src_display = f"{ip_src}:{sport}" if sport else ip_src
        dst_display = f"{ip_dst}:{dport}" if dport else ip_dst

        log = (f"[{time_str}] {src_display} ({src_country}) → "
               f"{dst_display} ({dst_country}) | Protocol: {proto_name}\n")

        output_text.insert(tk.END, log)
        output_text.see(tk.END)

def start_sniffing():
    global stop_sniffing, sniffer_thread
    stop_sniffing = False
    iface = iface_var.get()
    output_text.insert(tk.END, f"Sniffing on: {iface}\n")

    def sniff_packets():
        sniff(iface=iface, prn=packet_callback, store=False, stop_filter=lambda x: stop_sniffing)

    sniffer_thread = threading.Thread(target=sniff_packets, daemon=True)
    sniffer_thread.start()

def stop_sniffing_func():
    global stop_sniffing
    stop_sniffing = True
    output_text.insert(tk.END, "Sniffing stopped.\n")

# GUI Setup
root = tk.Tk()
root.title("Packet Sniffer with Geolocation and Ports")
root.geometry("850x600")

frame = ttk.Frame(root, padding=10)
frame.pack(fill=tk.BOTH, expand=True)

iface_label = ttk.Label(frame, text="Select Network Interface:")
iface_label.pack(anchor="w")

iface_var = tk.StringVar()
iface_dropdown = ttk.Combobox(frame, textvariable=iface_var, values=get_readable_interfaces(), state="readonly", width=90)
iface_dropdown.pack(fill=tk.X)
iface_dropdown.current(0)

button_frame = ttk.Frame(frame)
button_frame.pack(pady=10)

start_btn = ttk.Button(button_frame, text="Start Sniffing", command=start_sniffing)
start_btn.pack(side=tk.LEFT, padx=10)

stop_btn = ttk.Button(button_frame, text="Stop Sniffing", command=stop_sniffing_func)
stop_btn.pack(side=tk.LEFT, padx=10)

output_text = tk.Text(frame, height=30, wrap=tk.WORD)
output_text.pack(fill=tk.BOTH, expand=True)

root.mainloop()

