from scapy.all import sniff
from scapy.layers.http import HTTPRequest
from scapy.layers.dns import DNSQR
import netifaces

def detect_default_interface():
    """
    Detecta a interface de rede padrão.
    """
    gateways = netifaces.gateways()
    default_interface = gateways['default'][netifaces.AF_INET][1]
    print(f"[INFO] Interface padrão detectada: {default_interface}")
    return default_interface

def process_packet(packet):
    """
    Processa pacotes capturados para exibir consultas DNS e requisições HTTP.
    """
    if packet.haslayer(HTTPRequest):
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        print(f"HTTP Request: {url}")
    elif packet.haslayer(DNSQR):
        query = packet[DNSQR].qname.decode()
        print(f"DNS Query: {query}")

def start_sniffer(interface=None):
    """
    Inicia o sniffer na interface especificada.
    """
    if not interface:
        interface = detect_default_interface()
    print(f"[INFO] Iniciando o sniffer na interface {interface}...")
    sniff(iface=interface, store=False, prn=process_packet)

if __name__ == "__main__":
    try:
        interface = input("Digite a interface de rede (ou pressione Enter para detectar automaticamente): ").strip()
        start_sniffer(interface if interface else None)
    except ValueError as e:
        print(f"[ERRO] {e}")
    except KeyboardInterrupt:
        print("\n[INFO] Sniffer interrompido.")
