import os
import socket
import struct
import time
import ipaddress
from typing import List, Tuple


def calculate_checksum(packet: bytes) -> int:
    if len(packet) % 2 == 1:
        packet += b'\0'
    checksum = sum(struct.unpack('!H', packet[i:i + 2])[0] for i in range(0, len(packet), 2))
    checksum = (checksum >> 16) + (checksum & 0xffff)
    checksum += checksum >> 16
    return ~checksum & 0xffff


def create_icmp_packet(identifier: int, sequence: int) -> bytes:
    icmp_type = 8  # Echo Request
    code = 0
    checksum = 0
    header = struct.pack('!BBHHH', icmp_type, code, checksum, identifier, sequence)
    payload = b'NetworkScanner'
    checksum = calculate_checksum(header + payload)
    header = struct.pack('!BBHHH', icmp_type, code, checksum, identifier, sequence)
    return header + payload


def send_and_receive_icmp(host: str, timeout: int, identifier: int) -> float:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
            sock.settimeout(timeout / 1000)
            packet = create_icmp_packet(identifier, 1)
            start_time = time.time()
            sock.sendto(packet, (host, 1))
            sock.recvfrom(1024)
            return (time.time() - start_time) * 1000
    except socket.timeout:
        return -1


def get_mac_address(ip: str) -> str:
    """
    Obtém o endereço MAC do cache ARP do sistema para o IP fornecido.
    Ignora entradas inválidas como nomes de interfaces.
    """
    try:
        with os.popen(f"arp -n {ip}") as arp_output:
            lines = arp_output.readlines()
            for line in lines:
                if ip in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        mac = parts[2]
                        # Verifica se a string é um endereço MAC válido
                        if len(mac) == 17 and all(c in "0123456789abcdefABCDEF:" for c in mac):
                            return mac
    except Exception as e:
        pass
    return "MAC não encontrado"



def scan_network(network: str, timeout: int) -> None:
    """
    Realiza a varredura de rede e retorna apenas os hosts com endereço MAC.
    """
    network_obj = ipaddress.ip_network(network, strict=False)
    active_hosts_with_mac: List[Tuple[str, str, float]] = []
    total_hosts = len(list(network_obj.hosts()))
    start_scan = time.time()

    print(f"Iniciando a varredura na rede {network} com timeout de {timeout}ms...")
    
    for i, host in enumerate(network_obj.hosts(), start=1):
        try:
            print(f"Verificando host {host} ({i}/{total_hosts})...")
            response_time = send_and_receive_icmp(str(host), timeout, identifier=12345)
            if response_time >= 0:
                mac_address = get_mac_address(str(host))
                if mac_address != "MAC não encontrado":
                    active_hosts_with_mac.append((str(host), mac_address, response_time))
        except KeyboardInterrupt:
            print("\nVarredura interrompida pelo usuário!")
            break

    end_scan = time.time()
    total_time = end_scan - start_scan

    # Relatório final
    print("\nRelatório de varredura:")
    print(f"Total de máquinas na rede: {total_hosts}")
    print(f"Máquinas ativas com MAC encontradas: {len(active_hosts_with_mac)}")
    print(f"Tempo total de varredura: {total_time:.2f} segundos\n")
    print("Hosts ativos com MAC:")
    print(f"{'IP':<15} {'MAC':<20} {'Tempo de resposta':<10}")
    for host, mac, time_ms in active_hosts_with_mac:
        print(f"{host:<15} {mac:<20} {time_ms:.2f} ms")


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3:
        print("Uso: python host_scanner.py <rede/máscara> <timeout (ms)>")
        print("Exemplo: python host_scanner.py 192.168.1.0/24 1000")
        sys.exit(1)

    network = sys.argv[1]
    timeout = int(sys.argv[2])
    scan_network(network, timeout)