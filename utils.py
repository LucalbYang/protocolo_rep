# utils.py
import sys
import os
import random
import socket
import subprocess

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

def generate_cpf():
    """Gera um CPF válido aleatoriamente."""
    def calculate_digit(digits):
        weight = len(digits) + 1
        total = sum(d * (weight - i) for i, d in enumerate(digits))
        remainder = total % 11
        return 0 if remainder < 2 else 11 - remainder

    cpf_base = [random.randint(0, 9) for _ in range(9)]
    cpf_base.append(calculate_digit(cpf_base))
    cpf_base.append(calculate_digit(cpf_base))
    return "".join(map(str, cpf_base))

def generate_random_name():
    first_names = [
        "Daniel", "Sophia", "Pedro", "Lucas", "Mariana", "Julia", "Enzo", "Valentina", "Gabriel", "Isabella",
        "João", "Maria", "Ana", "Carlos", "Rafael", "Beatriz", "Mateus", "Laura", "Felipe", "Letícia",
        "Thiago", "Camila", "Bruno", "Amanda", "Gustavo", "Carolina", "Leonardo", "Bruna", "Rodrigo", "Fernanda",
        "Marcelo", "Alice", "Guilherme", "Helena", "Arthur", "Lorena", "Ricardo", "Lívia", "Diego", "Manuela"
    ]
    last_names = [
        "Silva", "Martinez", "Carvalho", "Fonseca", "Oliveira", "Souza", "Pereira", "Costa", "Rodrigues", "Almeida",
        "Santos", "Ferreira", "Gomes", "Rocha", "Ribeiro", "Alves", "Monteiro", "Mendes", "Barros", "Lima",
        "Teixeira", "Cavalcanti", "Moraes", "Nunes", "Dias", "Cardoso", "Castro", "Cunha", "Melo", "Pinto",
        "Farias", "Machado", "Araújo", "Freitas", "Borges", "Batista", "Moreira", "Marques", "Neves", "Correia"
    ]
    return f"{random.choice(first_names)} {random.choice(last_names)}"

def list_all_local_ips():
    """Retorna uma lista de todos os endereços IPv4 ativos nas interfaces de rede (ETH, WIFI, etc)."""
    ips = set()
    
    # 1. Método ultra-rápido via socket.getaddrinfo (nativo Python)
    try:
        # Puxa todas as interfaces de rede conhecidas pelo OS
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith("127.") and not ip.startswith("169.254."):
                ips.add(ip)
    except:
        pass

    # 2. Complemento via hostname_ex
    try:
        hostname = socket.gethostname()
        for ip in socket.gethostbyname_ex(hostname)[2]:
            if not ip.startswith("127.") and not ip.startswith("169.254."):
                ips.add(ip)
    except:
        pass

    # 3. Fallback PowerShell (lento, só se os acima falharem em achar algo útil)
    if not ips:
        try:
            ps_cmd = (
                "Get-NetIPAddress -AddressFamily IPv4 | "
                "Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } | "
                "Select-Object -ExpandProperty IPAddress"
            )
            output = subprocess.check_output(["powershell", "-Command", ps_cmd], 
                                           shell=True, timeout=2).decode('utf-8', errors='ignore').strip()
            if output:
                for line in output.split('\n'):
                    ip = line.strip()
                    if ip: ips.add(ip)
        except:
            pass

    # 4. Caso extremo: Conexão UDP fake para descobrir IP de saída
    if not ips:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0)
            s.connect(('10.254.254.254', 1))
            ips.add(s.getsockname()[0])
            s.close()
        except:
            ips.add("127.0.0.1")

    return sorted(list(ips))

def get_local_ip():
    """Obtém o IP local priorizando interfaces do tipo Ethernet (cabo) via PowerShell."""
    try:
        ps_cmd = (
            "Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and ($_.Name -like '*Ethernet*' -or $_.InterfaceDescription -like '*Ethernet*' -or $_.Name -like '*Local Area*') } "
            "| Get-NetIPAddress -AddressFamily IPv4 | Select-Object -ExpandProperty IPAddress"
        )
        output = subprocess.check_output(["powershell", "-Command", ps_cmd], shell=True).decode('utf-8').strip()

        if output:
            ips = output.split('\r\n')
            if ips:
                return ips[0].strip()

        ps_cmd_fallback = (
            "Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike '*Wi-Fi*' -and $_.IPAddress -notlike '127.*' } "
            "| Select-Object -ExpandProperty IPAddress"
        )
        output_fallback = subprocess.check_output(["powershell", "-Command", ps_cmd_fallback], shell=True).decode('utf-8').strip()
        if output_fallback:
            return output_fallback.split('\r\n')[0].strip()

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        try:
            return socket.gethostbyname(socket.gethostname())
        except:
            return "127.0.0.1"
