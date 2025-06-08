#!/usr/bin/env python3

import argparse
import sys
import time
import os
from scapy.all import IP, Ether, Raw, sendp, get_if_hwaddr

def send_packets(destination_ip, iface, packet_size):
    """
    Sends network packets of a given size to a destination IP as fast as possible.

    Args:
        destination_ip (str): The IP address of the destination.
        packet_size (int): The desired size of the packets in bytes.
    """

    if packet_size < 64:
        print("Packet size must be at least 64 bytes. Setting to 64 bytes.")
        packet_size = 64

    payload_size = packet_size - 20  # Account for IP header
    if payload_size < 0:
        payload_size = 0
        
    mac = get_if_hwaddr(iface) 
    print(f"MAC ADRESS TO IFACE {iface}: {mac}")

    # packet = Ether(dst=mac) / IP(dst=destination_ip) / Raw(load=b'\x00' * payload_size)
    packet = Ether(dst=mac)

    print(f"Sending packets of size {packet_size} bytes to {destination_ip}...")
    print("Press Ctrl+C to stop.")

    try:
        while True:
            sendp(packet, iface=iface, verbose=0)
    except KeyboardInterrupt:
        print("\nPacket sending stopped.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Send network packets of a given size to a destination IP.")
    parser.add_argument("destination_ip", type=str, help="The IP address of the destination.")
    parser.add_argument("iface", type=str, help="The interface of the destination.")
    parser.add_argument("packet_size", type=int, help="The size of the packets in bytes (min 64).")

    args = parser.parse_args()

    if sys.platform.startswith('linux') or sys.platform == 'darwin':
        if os.geteuid() != 0:
            print("This script must be run as root.")
            sys.exit(1)

    send_packets(args.destination_ip, args.iface, args.packet_size)
