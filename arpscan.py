from scapy.all import ARP, Ether, srp

def normalize_mac(mac_address):
    mac_parts = mac_address.replace(":", "").replace(" ", "").upper()
    return mac_parts
def get_device_type(mac_address, oui_database):
    oui = normalize_mac(mac_address)[:6]
    with open(oui_database, "r") as f:
        for line in f:  
            if oui  in line:
                return line.split("\t")[2].strip()
    return "unknown"

def scan_network(ip_range, oui_database):
    arp_packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
    
    result = srp(arp_packet, timeout=2, verbose=False)[0]

    devices = []

    for sent, received in result:
        devices.append({"ip": received.psrc, "mac": normalize_mac(received.hwsrc), "type": get_device_type(received.hwsrc, oui_database)})

    return devices

if __name__ == "__main__":
    network_range =  input("Enter network range : example 192.168.1.0/24 ")

    oui_db_file = "oui.txt"

    scan_result = scan_network(network_range, oui_db_file)

    print("detected devices :")
    print("-------------------")
    for device in scan_result:
        print(f"IP: {device['ip']} - MAC: {device['mac']} - Device type: {device['type']}")
