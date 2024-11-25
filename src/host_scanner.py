# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# =                          -                                   -=
# =    SCAN DE REDE                                              -=
# =                          -                                   -=
# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
def scan_network(network_range, timeout=1):
    """
    Escaneia a rede fornecida para identificar hosts ativos.
    """
    # Lista para armazenar os IPs dos hosts ativos
    hosts = []

    # Itera pelos IPs no range fornecido (de x.x.x.1 a x.x.x.254)
    for i in range(1, 255):
        # Monta o IP atual
        ip = f"{network_range}.{i}"

        # Cria um pacote ICMP (ping) para o IP
        packet = IP(dst=ip)/ICMP()

        # Envia o pacote e aguarda uma resposta
        response = sr1(packet, timeout=timeout, verbose=0)

        # Adiciona o IP à lista de hosts se houver resposta
        if response:
            hosts.append(ip)
            print(f"Host ativo: {ip}")
    
    # Retorna a lista de hosts ativos encontrados
    return hosts


# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# =                          -                                   -=
# =    EXECUÇÃO PRINCIPAL                                        -=
# =                          -                                   -=
# =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
if __name__ == "__main__":
    # Solicita o range da rede ao usuário (ex.: 192.168.1)
    network_range = input("Digite o range da rede (exemplo: 192.168.1): ")

    # Executa o scan de rede
    scan_network(network_range)
