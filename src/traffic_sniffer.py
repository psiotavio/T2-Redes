# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# =                          -                                   -=
# =    DETECTA INTERFACE PADRÃO                                  -=
# =                          -                                   -=
# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
def detect_default_interface():
    """
    Detecta a interface de rede padrão.
    """
    # Obtém os gateways configurados no sistema
    gateways = netifaces.gateways()

    # Identifica a interface padrão usada para o tráfego IPv4
    default_interface = gateways['default'][netifaces.AF_INET][1]

    # Exibe a interface padrão detectada
    print(f"[INFO] Interface padrão detectada: {default_interface}")
    
    # Retorna o nome da interface
    return default_interface


# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# =                          -                                   -=
# =    PROCESSA PACOTES                                          -=
# =                          -                                   -=
# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
def process_packet(packet):
    """
    Processa pacotes capturados para exibir consultas DNS e requisições HTTP.
    """
    # Verifica se o pacote contém uma requisição HTTP
    if packet.haslayer(HTTPRequest):
        # Extrai e exibe a URL da requisição HTTP
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        print(f"HTTP Request: {url}")
    # Verifica se o pacote contém uma consulta DNS
    elif packet.haslayer(DNSQR):
        # Extrai e exibe o nome da consulta DNS
        query = packet[DNSQR].qname.decode()
        print(f"DNS Query: {query}")


# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# =                          -                                   -=
# =    INICIA O SNIFFER                                          -=
# =                          -                                   -=
# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
def start_sniffer(interface=None):
    """
    Inicia o sniffer na interface especificada.
    """
    # Detecta automaticamente a interface padrão, se nenhuma for especificada
    if not interface:
        interface = detect_default_interface()
    
    # Informa ao usuário que o sniffer está sendo iniciado
    print(f"[INFO] Iniciando o sniffer na interface {interface}...")

    # Inicia a captura de pacotes na interface selecionada
    sniff(iface=interface, store=False, prn=process_packet)


# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# =                          -                                   -=
# =    EXECUÇÃO PRINCIPAL                                        -=
# =                          -                                   -=
# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
if __name__ == "__main__":
    try:
        # Solicita ao usuário a interface de rede ou detecta automaticamente
        interface = input("Digite a interface de rede (ou pressione Enter para detectar automaticamente): ").strip()

        # Inicia o sniffer com a interface fornecida ou detectada
        start_sniffer(interface if interface else None)

    except ValueError as e:
        # Trata erros relacionados a valores inválidos
        print(f"[ERRO] {e}")
    except KeyboardInterrupt:
        # Trata interrupções manuais pelo usuário (Ctrl + C)
        print("\n[INFO] Sniffer interrompido.")
