import pyshark
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

def sniff_traffic(interface, output_file):
    """
    Captura tráfego de pacotes DNS e HTTP usando pyshark.
    """
    print(f"Capturando pacotes na interface {interface}...")

    history = []

    try:
        # Inicia a captura na interface especificada
        capture = pyshark.LiveCapture(interface=interface)
        for packet in capture.sniff_continuously():
            try:
                # DNS Packet
                if 'DNS' in packet:
                    timestamp = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
                    src_ip = packet.ip.src
                    domain = packet.dns.qry_name
                    history.append((timestamp, src_ip, domain))
                    print(f"DNS: {domain} de {src_ip}")

                # HTTP Packet
                elif 'HTTP' in packet:
                    timestamp = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
                    src_ip = packet.ip.src
                    host = packet.http.host
                    history.append((timestamp, src_ip, host))
                    print(f"HTTP: {host} de {src_ip}")

                # Atualiza o HTML
                generate_html(history, output_file)

            except AttributeError:
                continue

    except KeyboardInterrupt:
        print("\nSniffer interrompido pelo usuário.")

if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3:
        print("Uso: sudo python3 traffic_sniffer.py <interface> <arquivo_saida.html>")
        print("Exemplo: sudo python3 traffic_sniffer.py en0 historico.html")
        sys.exit(1)

    interface = sys.argv[1]
    output_file = sys.argv[2]

    sniff_traffic(interface, output_file)
