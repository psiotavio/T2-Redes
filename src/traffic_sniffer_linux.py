# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# =                          -                                   -=
# =    TRAFFIC SNIFFER                                           -=
# =                          -                                   -=
# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

import socket
import struct
import datetime
from typing import Optional

# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# Função para criar o arquivo HTML do histórico de navegação
# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
def generate_html(history: list, output_file: str) -> None:
    """
    Gera um arquivo HTML com o histórico de navegação.
    """
    with open(output_file, "w") as f:
        f.write("<html>\n<header>\n<title>Historico de Navegacao</title>\n</header>\n<body>\n<ul>\n")
        for entry in history:
            date_time, ip, url = entry
            f.write(f'<li>{date_time} - {ip} - <a href="{url}">{url}</a></li>\n')
        f.write("</ul>\n</body>\n</html>")

# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# Função para processar pacotes DNS
# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
def process_dns_packet(data: bytes) -> Optional[str]:
    """
    Processa um pacote DNS e retorna o nome do domínio requisitado, se encontrado.
    """
    try:
        transaction_id, flags, questions, answer_rrs, authority_rrs, additional_rrs = struct.unpack(
            "!HHHHHH", data[:12]
        )
        domain_name = []
        i = 12
        while True:
            length = data[i]
            if length == 0:
                break
            domain_name.append(data[i + 1 : i + 1 + length].decode())
            i += length + 1
        return ".".join(domain_name)
    except Exception:
        return None

# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# Função para processar pacotes HTTP
# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
def process_http_packet(data: bytes) -> Optional[str]:
    """
    Processa um pacote HTTP e retorna a URL requisitada, se encontrada.
    """
    try:
        http_data = data.decode(errors="ignore")
        if "GET" in http_data or "POST" in http_data:
            lines = http_data.split("\r\n")
            for line in lines:
                if line.startswith("Host:"):
                    host = line.split(": ")[1]
                    return f"http://{host}"
        return None
    except Exception:
        return None

# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# Função principal para capturar e analisar pacotes
# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
def sniff_traffic(interface: str, output_file: str) -> None:
    """
    Captura pacotes DNS e HTTP usando sockets RAW e registra o histórico de navegação.
    """
    try:
        # Criando socket RAW para capturar pacotes
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
        sock.bind((interface, 0))
        print(f"Capturando pacotes na interface {interface}...")

        history = []

        while True:
            packet, _ = sock.recvfrom(65535)

            # Processa cabeçalho Ethernet
            eth_header = packet[:14]
            eth_data = struct.unpack("!6s6sH", eth_header)
            eth_protocol = eth_data[2]

            # Se o protocolo não for IPv4, ignore
            if eth_protocol != 0x0800:
                continue

            # Processa cabeçalho IPv4
            ip_header = packet[14:34]
            iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
            protocol = iph[6]
            source_ip = socket.inet_ntoa(iph[8])
            dest_ip = socket.inet_ntoa(iph[9])

            # Se for UDP (DNS)
            if protocol == 17:  # UDP
                udp_header = packet[34:42]
                src_port, dest_port, length, checksum = struct.unpack("!HHHH", udp_header)

                # DNS está na porta 53
                if src_port == 53 or dest_port == 53:
                    dns_data = packet[42:]
                    domain = process_dns_packet(dns_data)
                    if domain:
                        now = datetime.datetime.now().strftime("%d/%m/%Y %H:%M")
                        history.append((now, source_ip, f"http://{domain}"))
                        print(f"DNS: {domain} de {source_ip}")

            # Se for TCP (HTTP)
            elif protocol == 6:  # TCP
                tcp_header = packet[34:54]
                src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack(
                    "!HHLLH", tcp_header
                )
                tcp_data = packet[54:]

                # HTTP normalmente usa porta 80
                if src_port == 80 or dest_port == 80:
                    url = process_http_packet(tcp_data)
                    if url:
                        now = datetime.datetime.now().strftime("%d/%m/%Y %H:%M")
                        history.append((now, source_ip, url))
                        print(f"HTTP: {url} de {source_ip}")

            # Atualiza o arquivo HTML
            generate_html(history, output_file)

    except KeyboardInterrupt:
        print("\nSniffer interrompido pelo usuário.")
    except Exception as e:
        print(f"Erro: {e}")
    finally:
        sock.close()

# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# Entrada principal do programa
# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3:
        print("Uso: sudo python3 traffic_sniffer.py <interface> <arquivo_saida.html>")
        print("Exemplo: sudo python3 traffic_sniffer.py en0 historico.html")
        sys.exit(1)

    interface = sys.argv[1]
    output_file = sys.argv[2]

    sniff_traffic(interface, output_file)
