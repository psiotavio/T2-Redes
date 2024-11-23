from scapy.all import sniff
from scapy.layers.http import HTTPRequest
from scapy.layers.dns import DNSQR
from datetime import datetime

def process_packet(packet):
    log_file = "historico_navegacao.html"
    with open(log_file, "a") as f:
        if packet.haslayer(HTTPRequest):
            host = packet[HTTPRequest].Host.decode()
            path = packet[HTTPRequest].Path.decode()
            url = f"http://{host}{path}"
            time_stamp = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
            f.write(f"<li>{time_stamp} - {packet[IP].src} - <a href='{url}'>{url}</a></li>\n")
            print(f"[HTTP] {packet[IP].src} -> {url}")
        elif packet.haslayer(DNSQR):
            query = packet[DNSQR].qname.decode()
            time_stamp = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
            f.write(f"<li>{time_stamp} - {packet[IP].src} - DNS Query: {query}</li>\n")
            print(f"[DNS] {packet[IP].src} -> {query}")

def start_sniffer(interface):
    print("[INFO] Iniciando o sniffer...")
    sniff(iface=interface, store=False, prn=process_packet)

if __name__ == "__main__":
    interface = input("Digite a interface de rede (exemplo: eth0): ")
    start_sniffer(interface)
