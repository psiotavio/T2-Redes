import socket
import struct
import datetime

def generate_html(history, output_file):
    """
    Gera um arquivo HTML com o histórico de navegação.
    """
    with open(output_file, "w") as f:
        f.write("<html>\n<header>\n<title>Historico de Navegacao</title>\n</header>\n<body>\n<ul>\n")
        for entry in history:
            date_time, ip, url = entry
            f.write(f'<li>{date_time} - {ip} - <a href="{url}">{url}</a></li>\n')
        f.write("</ul>\n</body>\n</html>")

def parse_packet(packet):
    """
    Analisa um pacote bruto para extrair informações DNS e HTTP.
    """
    try:
        # Extrai cabeçalho IP
        ip_header = packet[0:20]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

        protocol = iph[6]
        src_ip = socket.inet_ntoa(iph[8])

        # Protocolos HTTP e DNS
        if protocol == 6:  # TCP
            # Extração de HTTP (porta 80)
            tcp_header = packet[20:40]
            tcph = struct.unpack('!HHLLBBHHH', tcp_header)
            src_port = tcph[0]
            if src_port == 80:
                http_data = packet[40:].decode(errors='ignore')
                if 'Host:' in http_data:
                    host_line = [line for line in http_data.split('\n') if 'Host:' in line]
                    if host_line:
                        host = host_line[0].split(': ')[1].strip()
                        return src_ip, host

        elif protocol == 17:  # UDP
            # Extração de DNS (porta 53)
            dns_header = packet[20:28]
            dnsh = struct.unpack('!HHHHHH', dns_header)
            dns_data = packet[28:]
            domain = parse_dns_query(dns_data)
            if domain:
                return src_ip, domain

    except Exception as e:
        pass
    return None

def parse_dns_query(data):
    """
    Extrai o domínio de uma consulta DNS.
    """
    try:
        domain_parts = []
        i = 0
        while True:
            length = data[i]
            if length == 0:
                break
            i += 1
            domain_parts.append(data[i:i + length].decode())
            i += length
        return '.'.join(domain_parts)
    except Exception as e:
        return None

def sniff_traffic(interface, output_file):
    """
    Captura tráfego de pacotes usando sockets brutos.
    """
    history = []

    try:
        print(f"Capturando pacotes na interface {interface}...")
        # Cria um socket bruto
        raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        raw_socket.bind((interface, 0))

        while True:
            packet, _ = raw_socket.recvfrom(65565)
            result = parse_packet(packet)
            if result:
                src_ip, url = result
                timestamp = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
                history.append((timestamp, src_ip, url))
                print(f"{timestamp} - {src_ip} - {url}")
                # Atualiza o HTML
                generate_html(history, output_file)

    except KeyboardInterrupt:
        print("\nSniffer interrompido pelo usuário.")
    except PermissionError:
        print("Erro: Execute o script como superusuário (sudo).")

if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3:
        print("Uso: sudo python3 traffic_sniffer_raw.py <interface> <arquivo_saida.html>")
        print("Exemplo: sudo python3 traffic_sniffer_raw.py en0 historico.html")
        sys.exit(1)

    interface = sys.argv[1]
    output_file = sys.argv[2]

    sniff_traffic(interface, output_file)
