import socket
import struct
import datetime
from typing import Optional

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

def process_http_packet(data: bytes) -> Optional[str]:
    """
    Processa um pacote HTTP e retorna a URL requisitada, se encontrada.
    """
    try:
        request = data.decode(errors="ignore")
        if "Host:" in request:
            lines = request.split("\r\n")
            host = None
            for line in lines:
                if line.startswith("Host:"):
                    host = line.split(": ", 1)[1].strip()
            if host:
                return f"http://{host}"
        return None
    except Exception:
        return None

def process_dns_packet(data: bytes) -> Optional[str]:
    """
    Processa um pacote DNS e retorna o nome do domínio requisitado, se encontrado.
    """
    try:
        i = 12  # Início do campo "Questions"
        domain_name = []
        while True:
            length = data[i]
            if length == 0:
                break
            i += 1
            domain_name.append(data[i:i + length].decode())
            i += length
        return ".".join(domain_name)
    except Exception:
        return None

def sniff_traffic(interface: str, output_file: str) -> None:
    """
    Captura pacotes DNS e HTTP usando sockets RAW e registra o histórico de navegação.
    """
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
        sock.bind((interface, 0))
        print(f"Capturando pacotes na interface {interface}...")

        history = []

        while True:
            packet, _ = sock.recvfrom(65535)

            if len(packet) < 14:
                continue

            eth_header = packet[:14]
            eth_protocol = struct.unpack("!6s6sH", eth_header)[2]

            if eth_protocol != 0x0800:  # Apenas IPv4
                continue

            if len(packet) < 34:
                continue

            ip_header = packet[14:34]
            iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
            protocol = iph[6]
            source_ip = socket.inet_ntoa(iph[8])

            if protocol == 17:  # UDP
                if len(packet) < 42:
                    continue
                udp_header = packet[34:42]
                src_port, dest_port = struct.unpack("!HH", udp_header[:4])

                if src_port == 53 or dest_port == 53:  # DNS
                    dns_data = packet[42:]
                    domain = process_dns_packet(dns_data)
                    if domain:
                        now = datetime.datetime.now().strftime("%d/%m/%Y %H:%M")
                        history.append((now, source_ip, f"http://{domain}"))
                        print(f"DNS: {domain} de {source_ip}")

            elif protocol == 6:  # TCP
                if len(packet) < 54:
                    continue
                tcp_header = packet[34:54]
                src_port, dest_port = struct.unpack("!HH", tcp_header[:4])

                if src_port == 80 or dest_port == 80:  # HTTP
                    http_data = packet[54:]
                    url = process_http_packet(http_data)
                    if url:
                        now = datetime.datetime.now().strftime("%d/%m/%Y %H:%M")
                        history.append((now, source_ip, url))
                        print(f"HTTP: {url} de {source_ip}")

            generate_html(history, output_file)

    except KeyboardInterrupt:
        print("\nSniffer interrompido pelo usuário.")
    except Exception as e:
        print(f"Erro: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3:
        print("Uso: sudo python3 traffic_sniffer.py <interface> <arquivo_saida.html>")
        print("Exemplo: sudo python3 traffic_sniffer.py en0 historico.html")
        sys.exit(1)

    interface = sys.argv[1]
    output_file = sys.argv[2]

    sniff_traffic(interface, output_file)
