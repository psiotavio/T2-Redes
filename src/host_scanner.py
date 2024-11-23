from scapy.all import sr1, IP, ICMP
import time
import ipaddress

def scan_network(network, timeout=1):
    hosts = []
    network = ipaddress.IPv4Network(network, strict=False)
    print(f"[INFO] Escaneando a rede {network}...")
    start_time = time.time()

    for ip in network:
        ip = str(ip)
        packet = IP(dst=ip) / ICMP()
        response = sr1(packet, timeout=timeout, verbose=0)
        if response:
            latency = round((time.time() - start_time) * 1000, 2)  # Em ms
            hosts.append((ip, latency))
            print(f"Host ativo: {ip} - Latência: {latency}ms")

    total_time = round(time.time() - start_time, 2)
    print(f"[INFO] Total de hosts ativos: {len(hosts)}")
    print(f"[INFO] Tempo total de varredura: {total_time}s")
    return hosts

if __name__ == "__main__":
    network_range = input("Digite o range da rede (exemplo: 192.168.1.0/24): ")
    scan_network(network_range)
