from scapy.all import ICMP, IP, sr1

def scan_network(network_range, timeout=1):
    hosts = []
    for i in range(1, 255):  # Scan from x.x.x.1 to x.x.x.254
        ip = f"{network_range}.{i}"
        packet = IP(dst=ip)/ICMP()
        response = sr1(packet, timeout=timeout, verbose=0)
        if response:
            hosts.append(ip)
            print(f"Host ativo: {ip}")
    return hosts

if __name__ == "__main__":
    network_range = input("Digite o range da rede (exemplo: 192.168.1): ")
    scan_network(network_range)
