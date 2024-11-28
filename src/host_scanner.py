# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# =                          -                                   -=
# =    SCAN DE REDE                                              -=
# =                          -                                   -=
# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

import socket
import struct
import time
import ipaddress
from typing import List, Tuple

# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# Função para calcular o checksum do pacote ICMP
# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
def calculate_checksum(packet: bytes) -> int:
    """
    Calcula o checksum para o pacote ICMP.
    """
    if len(packet) % 2 == 1:
        packet += b'\0'
    checksum = sum(struct.unpack('!H', packet[i:i + 2])[0] for i in range(0, len(packet), 2))
    checksum = (checksum >> 16) + (checksum & 0xffff)
    checksum += checksum >> 16
    return ~checksum & 0xffff

# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# Função para criar um pacote ICMP Echo Request
# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
def create_icmp_packet(identifier: int, sequence: int) -> bytes:
    """
    Cria um pacote ICMP Echo Request.
    """
    icmp_type = 8  # Echo Request
    code = 0
    checksum = 0
    header = struct.pack('!BBHHH', icmp_type, code, checksum, identifier, sequence)
    payload = b'NetworkScanner'  # Dados arbitrários
    checksum = calculate_checksum(header + payload)
    header = struct.pack('!BBHHH', icmp_type, code, checksum, identifier, sequence)
    return header + payload

# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# Função para realizar o envio e recebimento de pacotes ICMP
# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
def send_and_receive_icmp(host: str, timeout: int, identifier: int) -> float:
    """
    Envia um pacote ICMP Echo Request e aguarda o Echo Reply.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
            sock.settimeout(timeout / 1000)
            packet = create_icmp_packet(identifier, 1)
            start_time = time.time()
            sock.sendto(packet, (host, 1))
            sock.recvfrom(1024)
            return (time.time() - start_time) * 1000  # Tempo em milissegundos
    except socket.timeout:
        return -1  # Nenhuma resposta

# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# Função principal para varrer a rede
# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
def scan_network(network: str, timeout: int) -> None:
    """
    Realiza a varredura de rede para identificar hosts ativos.
    """
    network_obj = ipaddress.ip_network(network, strict=False)
    active_hosts: List[Tuple[str, float]] = []
    total_hosts = len(list(network_obj.hosts()))
    start_scan = time.time()

    print(f"Iniciando a varredura na rede {network} com timeout de {timeout}ms...")
    
    for i, host in enumerate(network_obj.hosts(), start=1):
        try:
            print(f"Verificando host {host} ({i}/{total_hosts})...")
            response_time = send_and_receive_icmp(str(host), timeout, identifier=12345)
            if response_time >= 0:
                active_hosts.append((str(host), response_time))
        except KeyboardInterrupt:
            print("\nVarredura interrompida pelo usuário!")
            break

    end_scan = time.time()
    total_time = end_scan - start_scan

    # Relatório final
    print("\nRelatório de varredura:")
    print(f"Total de máquinas na rede: {total_hosts}")
    print(f"Máquinas ativas encontradas: {len(active_hosts)}")
    print(f"Tempo total de varredura: {total_time:.2f} segundos\n")
    print("Hosts ativos:")
    for host, time_ms in active_hosts:
        print(f"{host} - Tempo de resposta: {time_ms:.2f} ms")


# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# Entrada principal do programa
# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3:
        print("Uso: python host_scanner.py <rede/máscara> <timeout (ms)>")
        print("Exemplo: python host_scanner.py 192.168.1.0/24 1000")
        sys.exit(1)

    network = sys.argv[1]
    timeout = int(sys.argv[2])
    scan_network(network, timeout)
