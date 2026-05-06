import sys
import os
import socket
import base64
import traceback
import time
from comandos import COMMANDS_REGISTRY

from PyQt6.QtCore import QThread, pyqtSignal, QSettings, QTimer, Qt, QEvent
from PyQt6.QtWidgets import (QApplication, QGridLayout, QLabel, QLineEdit,
                             QPushButton, QTextEdit, QWidget, QStackedWidget,
                             QGroupBox, QVBoxLayout, QHBoxLayout, QMessageBox,
                             QComboBox, QFormLayout, QScrollArea, QCheckBox, QFrame)

# Prefer pycryptodome, fallback para cryptography se necessário.
try:
    from Crypto.Cipher import PKCS1_v1_5, AES
    from Crypto.PublicKey import RSA
    from Crypto import Random
    from Crypto.Util.Padding import pad, unpad
    CRYPTO_BACKEND = "pycryptodome"
except ModuleNotFoundError:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_der_public_key
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding as sym_padding
    CRYPTO_BACKEND = "cryptography"

# 🔹 REQUISITO 1: Classe Customizada para bloquear Scroll e Setas nos ComboBox
class NoScrollComboBox(QComboBox):
    """QComboBox que ignora scroll do mouse e teclas de seta para evitar mudanças acidentais."""
    def wheelEvent(self, event):
        event.ignore()

    def keyPressEvent(self, event):
        if event.key() in (Qt.Key.Key_Up, Qt.Key.Key_Down):
            event.ignore()
        else:
            super().keyPressEvent(event)


class EvoRepProtocol:
    SB = 0x02
    EB = 0x03

    @staticmethod
    def _calc_cs(length_bytes: bytes, payload_bytes: bytes) -> int:
        cs = 0
        for b in length_bytes:
            cs ^= b
        for b in payload_bytes:
            cs ^= b
        return cs

    @classmethod
    def pack(cls, payload) -> bytes:
        if isinstance(payload, str):
            payload = payload.encode('utf-8')
        length = len(payload)
        length_bytes = length.to_bytes(2, byteorder="little")
        cs = cls._calc_cs(length_bytes, payload).to_bytes(1, byteorder="little")
        packet = bytes([cls.SB]) + length_bytes + payload + cs + bytes([cls.EB])
        return packet

    @classmethod
    def unpack(cls, packet: bytes) -> bytes:
        if len(packet) < 5:
            raise ValueError("Pacote muito curto")
        if packet[0] != cls.SB or packet[-1] != cls.EB:
            raise ValueError("Delimitador SB/EB inválido")

        length = int.from_bytes(packet[1:3], byteorder="little")
        payload_bytes = packet[3:3 + length]
        cs_received = packet[3 + length]
        cs_calc = cls._calc_cs(packet[1:3], payload_bytes)
        
        if cs_received != cs_calc:
            raise ValueError(f"Checksum inválido: recebido {cs_received:02X}, calculado {cs_calc:02X}")

        return payload_bytes

    @classmethod
    def receive_full(cls, sock: socket.socket, timeout: float = 15.0) -> bytes:
        sock.settimeout(timeout)
        header = b""
        while len(header) < 3:
            chunk = sock.recv(3 - len(header))
            if not chunk:
                raise ConnectionError("Conexão encerrada prematuramente durante o cabeçalho")
            header += chunk

        if header[0] != cls.SB:
            raise ValueError("Start byte inválido")

        payload_len = int.from_bytes(header[1:3], "little")
        remaining = payload_len + 2
        payload_cs_eb = b""
        
        while len(payload_cs_eb) < remaining:
            chunk = sock.recv(remaining - len(payload_cs_eb))
            if not chunk:
                raise ConnectionError("Conexão encerrada prematuramente durante os dados")
            payload_cs_eb += chunk

        packet = header + payload_cs_eb
        if packet[-1] != cls.EB:
            raise ValueError("End byte inválido")

        return packet


class EvoRepCrypto:
    
    @staticmethod
    def extract_rsa_key_from_payload(payload) -> tuple[int, int, str]:
        if isinstance(payload, bytes):
            payload = payload.decode('utf-8', errors='ignore')

        segmentos = payload.split("+", 3)
        if len(segmentos) < 4:
            raise ValueError("Payload RA malformado.")

        key_data = segmentos[3]
        if "]" not in key_data:
            raise ValueError("Separador ] não encontrado no payload RA.")

        mod_b64, exp_b64 = key_data.split("]", 1)
        mod_b64 = mod_b64.strip()
        exp_b64 = exp_b64.strip()

        mod_bytes = base64.b64decode(mod_b64)
        exp_bytes = base64.b64decode(exp_b64)

        n = int.from_bytes(mod_bytes, byteorder='big')
        e = int.from_bytes(exp_bytes, byteorder='big')

        return n, e, mod_b64

    @staticmethod
    def format_modulus_to_b32(mod_b64: str) -> str:
        try:
            mod_bytes = base64.b64decode(mod_b64)
            # O formato solicitado parece ser Base32 sem padding
            b32_mod = base64.b32encode(mod_bytes).decode('utf-8').replace('=', '')
            return b32_mod
        except Exception:
            return "Erro ao formatar chave"

    @staticmethod
    def generate_aes_key() -> bytes:
        return os.urandom(16)

    @staticmethod
    def encrypt_aes(key: bytes, plaintext: str) -> bytes:
        data = plaintext.encode('utf-8')
        iv = os.urandom(16)
        
        # Zero Padding: completa o bloco de 16 bytes com zeros
        pad_len = (16 - (len(data) % 16)) % 16
        padded_data = data + (b'\x00' * pad_len)
        
        if CRYPTO_BACKEND == "pycryptodome":
            cipher = AES.new(key, AES.MODE_CBC, iv)
            ciphertext = cipher.encrypt(padded_data)
            return iv + ciphertext
        else:
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            return iv + ciphertext

    @staticmethod
    def decrypt_aes(key: bytes, ciphertext: bytes) -> str:
        if not key: # Caso especial para F3 (sem criptografia)
            return ciphertext.decode('utf-8', errors='ignore')

        if len(ciphertext) < 16 or len(ciphertext) % 16 != 0:
            return ciphertext.decode('utf-8', errors='ignore')
            
        iv = ciphertext[:16]
        actual_ciphertext = ciphertext[16:]
        
        if CRYPTO_BACKEND == "pycryptodome":
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(actual_ciphertext)
            # Remove zeros do final (Zero Padding)
            return decrypted.rstrip(b'\x00').decode('utf-8', errors='replace')
        else:
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(actual_ciphertext) + decryptor.finalize()
            # Remove zeros do final (Zero Padding)
            return decrypted.rstrip(b'\x00').decode('utf-8', errors='replace')

    @staticmethod
    def encrypt_credentials_with_rsa(pubkey_data, credentials: str) -> bytes:
        data = credentials.encode("utf-8")

        if CRYPTO_BACKEND == "pycryptodome":
            if isinstance(pubkey_data, tuple):
                key = RSA.construct(pubkey_data)
            else:
                key = RSA.import_key(pubkey_data)
            cipher = PKCS1_v1_5.new(key)
            encrypted = cipher.encrypt(data)
            return encrypted

        if isinstance(pubkey_data, tuple):
            n, e = pubkey_data
            pubkey = rsa.RSAPublicNumbers(e, n).public_key(default_backend())
        else:
            pubkey = load_pem_public_key(pubkey_data.encode("utf-8"), backend=default_backend())
            
        encrypted = pubkey.encrypt(
            data,
            padding.PKCS1v15()
        )
        return encrypted


class NetworkWorker(QThread):
    log_signal = pyqtSignal(str)
    # emitimos True/False, mensagem, o socket e a session_key se sucesso
    finished_signal = pyqtSignal(bool, str, object, bytes)

    def __init__(self, ip: str, port: int, user: str, password: str, parent=None):
        super().__init__(parent)
        self.ip = ip
        self.port = port
        self.user = user
        self.password = password
        self.running = True

    def stop(self):
        self.running = False

    def run(self):
        start_time = time.time()
        timeout_limit = 10.0
        last_error = "Tempo esgotado"

        while self.running and (time.time() - start_time) < timeout_limit:
            sock = None
            try:
                self.log_signal.emit(f"Tentando conectar a {self.ip}:{self.port}...")
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.settimeout(2)
                sock.connect((self.ip, self.port))

                self.log_signal.emit("Conexão estabelecida. Iniciando handshake...")
                
                ra_payload = "01+RA+00"
                ra_packet = EvoRepProtocol.pack(ra_payload)
                sock.sendall(ra_packet)

                resp_data = EvoRepProtocol.receive_full(sock)
                payload_ra = EvoRepProtocol.unpack(resp_data).decode('utf-8', errors='ignore')
                self.log_signal.emit(f"Payload RA recebido: {payload_ra}")

                rsa_pubkey_data = EvoRepCrypto.extract_rsa_key_from_payload(payload_ra)
                n, e, mod_b64 = rsa_pubkey_data
                
                # Logar a chave pública no formato solicitado (Base32)
                public_key_b32 = EvoRepCrypto.format_modulus_to_b32(mod_b64)
                self.log_signal.emit(f"Chave Pública do equipamento: {public_key_b32}")

                session_key = EvoRepCrypto.generate_aes_key()
                # Remoção do log da session_key a pedido do usuário

                session_key_b64 = base64.b64encode(session_key).decode("utf-8")
                credential = f"1]{self.user}]{self.password}]{session_key_b64}"

                encrypted = EvoRepCrypto.encrypt_credentials_with_rsa((n, e), credential)
                encrypted_b64 = base64.b64encode(encrypted).decode("utf-8")

                ea_payload = f"01+EA+00+{encrypted_b64}"
                ea_packet = EvoRepProtocol.pack(ea_payload)
                sock.sendall(ea_packet)

                resp_ea = EvoRepProtocol.receive_full(sock)
                payload_ea = EvoRepProtocol.unpack(resp_ea).decode('utf-8', errors='ignore')
                self.log_signal.emit(f"Payload EA recebido: {payload_ea}")

                if payload_ea.startswith("01+EA+000"):
                    self.finished_signal.emit(True, "Autenticação EA realizada com sucesso.", sock, session_key)
                    return
                elif payload_ea.startswith("01+EA+009"):
                    self.finished_signal.emit(False, "Usuário ou senha inválidos.", None, b"")
                    sock.close()
                    return
                else:
                    raise Exception(f"Falha na autenticação (EA): {payload_ea}")

            except Exception as e:
                last_error = str(e)
                if self.running:
                    self.log_signal.emit(f"Falha na tentativa: {e}. Retentando em 350ms...")
                if sock:
                    try: sock.close()
                    except: pass
                
                # Aguarda 350ms em pequenos pedaços para responder ao stop() mais rápido
                for _ in range(7):
                    if not self.running: break
                    time.sleep(0.05)

        if not self.running:
            self.finished_signal.emit(False, "Operação cancelada pelo usuário.", None, b"")
        else:
            self.finished_signal.emit(False, f"Incapaz de conectar: {last_error}", None, b"")


class ClientNetworkWorker(QThread):
    log_signal = pyqtSignal(str)
    # emitimos True/False, mensagem, o socket e a session_key se sucesso
    finished_signal = pyqtSignal(bool, str, object, bytes)

    def __init__(self, ip: str, port: int, user: str, password: str, parent=None):
        super().__init__(parent)
        self.ip = ip
        self.port = port
        self.user = user
        self.password = password
        self.server_sock = None
        self.running = True

    def stop(self):
        self.running = False
        if self.server_sock:
            try:
                self.server_sock.close()
            except:
                pass

    def run(self):
        try:
            self.log_signal.emit(f"Iniciando servidor em {self.ip}:{self.port}...")
            self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_sock.bind((self.ip, self.port))
            self.server_sock.listen(1)
            self.server_sock.settimeout(None) # Aguarda indefinidamente a menos que seja parado

            self.log_signal.emit("Aguardando conexão do equipamento...")
            try:
                sock, addr = self.server_sock.accept()
                # 🔹 REQUISITO: Fechar o socket servidor imediatamente após aceitar a conexão
                # Isso libera a porta para outras aplicações enquanto atendemos este cliente.
                if self.server_sock:
                    self.server_sock.close()
                    self.server_sock = None
            except Exception as e:
                if self.running:
                    self.finished_signal.emit(False, f"Erro ao aceitar conexão: {e}", None, b"")
                else:
                    self.finished_signal.emit(False, "Servidor parado pelo usuário.", None, b"")
                return

            self.log_signal.emit(f"Conexão recebida de {addr}. Iniciando handshake...")
            
            ra_payload = "01+RA+00"
            ra_packet = EvoRepProtocol.pack(ra_payload)
            sock.sendall(ra_packet)

            resp_data = EvoRepProtocol.receive_full(sock)
            payload_ra = EvoRepProtocol.unpack(resp_data).decode('utf-8', errors='ignore')
            self.log_signal.emit(f"Payload RA recebido: {payload_ra}")

            rsa_pubkey_data = EvoRepCrypto.extract_rsa_key_from_payload(payload_ra)
            n, e, mod_b64 = rsa_pubkey_data
            
            public_key_b32 = EvoRepCrypto.format_modulus_to_b32(mod_b64)
            self.log_signal.emit(f"Chave Pública do equipamento: {public_key_b32}")

            session_key = EvoRepCrypto.generate_aes_key()
            session_key_b64 = base64.b64encode(session_key).decode("utf-8")
            credential = f"1]{self.user}]{self.password}]{session_key_b64}"

            encrypted = EvoRepCrypto.encrypt_credentials_with_rsa((n, e), credential)
            encrypted_b64 = base64.b64encode(encrypted).decode("utf-8")

            ea_payload = f"01+EA+00+{encrypted_b64}"
            ea_packet = EvoRepProtocol.pack(ea_payload)
            sock.sendall(ea_packet)

            resp_ea = EvoRepProtocol.receive_full(sock)
            payload_ea = EvoRepProtocol.unpack(resp_ea).decode('utf-8', errors='ignore')
            self.log_signal.emit(f"Payload EA recebido: {payload_ea}")

            if payload_ea.startswith("01+EA+000"):
                self.finished_signal.emit(True, "Autenticação EA realizada com sucesso.", sock, session_key)
            elif payload_ea.startswith("01+EA+009"):
                self.finished_signal.emit(False, "Usuário ou senha inválidos.", None, b"")
                sock.close()
            else:
                self.finished_signal.emit(False, f"Falha na autenticação (EA): {payload_ea}", None, b"")
                sock.close()

        except Exception as e:
            if self.running:
                self.log_signal.emit(f"Erro no modo cliente: {e}")
                self.finished_signal.emit(False, str(e), None, b"")
        finally:
            if self.server_sock:
                try: self.server_sock.close()
                except: pass


class F3NetworkWorker(QThread):
    log_signal = pyqtSignal(str)
    # emitimos True/False, mensagem, o socket e None (sem session key)
    finished_signal = pyqtSignal(bool, str, object, bytes)
    auto_sent_signal = pyqtSignal(str, bytes) # Para enviar RB automaticamente

    def __init__(self, ip: str, port: int, parent=None):
        super().__init__(parent)
        self.ip = ip
        self.port = port
        self.running = True

    def stop(self):
        self.running = False

    def run(self):
        sock = None
        try:
            self.log_signal.emit(f"F3: Tentando conectar a {self.ip}:{self.port} (Sem criptografia)...")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(5)
            sock.connect((self.ip, self.port))

            self.log_signal.emit("F3: Conectado. Enviando string automática...")
            
            # Enviar apenas 01+RB
            rb_payload = "01+RB"
            rb_packet = EvoRepProtocol.pack(rb_payload)
            sock.sendall(rb_packet)
            self.auto_sent_signal.emit(rb_payload, rb_packet)

            self.finished_signal.emit(True, "Conexão F3 estabelecida com sucesso.", sock, b"")

        except Exception as e:
            if self.running:
                self.log_signal.emit(f"F3: Falha na conexão: {e}")
                self.finished_signal.emit(False, str(e), None, b"")
            if sock:
                try: sock.close()
                except: pass


class CommandWorker(QThread):
    sent_signal = pyqtSignal(str)
    sent_bytes_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(bool, str)

    def __init__(self, sock: socket.socket, command: str, session_key: bytes, parent=None):
        super().__init__(parent)
        self.sock = sock
        self.command = command
        self.session_key = session_key

    def run(self):
        try:
            if self.session_key:
                # Com criptografia (Aba F1/F2)
                encrypted_command = EvoRepCrypto.encrypt_aes(self.session_key, self.command)
                packet = EvoRepProtocol.pack(encrypted_command)
            else:
                # Sem criptografia (Aba F3)
                packet = EvoRepProtocol.pack(self.command)
            
            self.sent_signal.emit(self.command)
            self.sent_bytes_signal.emit(packet.hex(' '))
            
            self.sock.sendall(packet)
            self.finished_signal.emit(True, 'Comando enviado. Aguardando resposta em tempo real...')
        except Exception as e:
            self.finished_signal.emit(False, f'Erro ao enviar comando: {e}')


class ListenerWorker(QThread):
    received_signal = pyqtSignal(str)
    received_bytes_signal = pyqtSignal(str)
    error_signal = pyqtSignal(str)

    def __init__(self, sock: socket.socket, session_key: bytes, parent=None):
        super().__init__(parent)
        self.sock = sock
        self.session_key = session_key
        self.running = True

    def stop(self):
        self.running = False

    def run(self):
        while self.running:
            try:
                # O receive_full aguarda dados. O timeout de 2s permite que o loop
                # verifique se self.running ainda é True periodicamente.
                data = EvoRepProtocol.receive_full(self.sock, timeout=2.0)
                if not data:
                    continue
                
                # Desempacota e descriptografa o que chegou
                payload_raw = EvoRepProtocol.unpack(data)
                
                if self.session_key:
                    payload = EvoRepCrypto.decrypt_aes(self.session_key, payload_raw)
                else:
                    payload = payload_raw.decode('utf-8', errors='ignore')
                
                self.received_signal.emit(payload)
                self.received_bytes_signal.emit(data.hex(' '))
            except socket.timeout:
                # Timeout normal do loop, apenas continua
                continue
            except Exception as e:
                if self.running:
                    self.error_signal.emit(str(e))
                break


def get_local_ip():
    """
    Obtém o IP local priorizando interfaces do tipo Ethernet (cabo) via PowerShell.
    """
    import subprocess
    try:
        # Comando PowerShell para buscar IPs de interfaces Ethernet que estejam ativas (Up)
        ps_cmd = (
            "Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and ($_.Name -like '*Ethernet*' -or $_.InterfaceDescription -like '*Ethernet*' -or $_.Name -like '*Local Area*') } "
            "| Get-NetIPAddress -AddressFamily IPv4 | Select-Object -ExpandProperty IPAddress"
        )
        output = subprocess.check_output(["powershell", "-Command", ps_cmd], shell=True).decode('utf-8').strip()
        
        if output:
            # Se retornar múltiplos IPs (ex: máquinas virtuais), pegamos o primeiro
            ips = output.split('\r\n')
            if ips:
                return ips[0].strip()

        # Fallback 1: Se o comando específico falhou, tenta pegar qualquer IP IPv4 que não seja WiFi
        ps_cmd_fallback = (
            "Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike '*Wi-Fi*' -and $_.IPAddress -notlike '127.*' } "
            "| Select-Object -ExpandProperty IPAddress"
        )
        output_fallback = subprocess.check_output(["powershell", "-Command", ps_cmd_fallback], shell=True).decode('utf-8').strip()
        if output_fallback:
            return output_fallback.split('\r\n')[0].strip()

        # Fallback 2: Método clássico do socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        # Fallback de emergência
        try:
            return socket.gethostbyname(socket.gethostname())
        except:
            return "127.0.0.1"


# Dicionário de escolhas para o comando EC (Enviar Configuração)
EC_VAL_CHOICES = {
    "LEITOR_VER_DIG": [{"label": "H - Habilitado", "value": "H"}, {"label": "D - Desabilitado", "value": "D"}],
    "EVENTO_ON": [{"label": "H - Habilitado", "value": "H"}, {"label": "D - Desabilitado", "value": "D"}],
    "EXP_NR_REP": [{"label": "H - Habilitado", "value": "H"}, {"label": "D - Desabilitado", "value": "D"}],
    "TECLADO_MANUT": [{"label": "H - Habilitado", "value": "H"}, {"label": "D - Desabilitado", "value": "D"}],
    "SENSOR_CORTE": [{"label": "H - Habilitado", "value": "H"}, {"label": "D - Desabilitado", "value": "D"}],
    "FEW_PAPER": [{"label": "H - Habilitado", "value": "H"}, {"label": "D - Desabilitado", "value": "D"}],
    "DIGITO_OCULTO": [{"label": "H - Habilitado", "value": "H"}, {"label": "D - Desabilitado", "value": "D"}],
    "ACENTOS": [{"label": "H - Habilitado", "value": "H"}, {"label": "D - Desabilitado", "value": "D"}],
    "NOBREAK": [{"label": "H - Habilitado", "value": "H"}, {"label": "D - Desabilitado", "value": "D"}],
    "BEEP_TECLADO": [{"label": "H - Habilitado", "value": "H"}, {"label": "D - Desabilitado", "value": "D"}],
    "BIO_PREVIEW": [{"label": "H - Habilitado", "value": "H"}, {"label": "D - Desabilitado", "value": "D"}],
    "CON_SEGURA": [{"label": "H - Habilitado", "value": "H"}, {"label": "D - Desabilitado", "value": "D"}],
    "RECONEXAO_IMEDIATA": [{"label": "H - Habilitado", "value": "H"}, {"label": "D - Desabilitado", "value": "D"}],
    "NTP": [{"label": "H - Habilitado", "value": "H"}, {"label": "D - Desabilitado", "value": "D"}],
    "CON_SEGURA_W": [{"label": "H - Habilitado", "value": "H"}, {"label": "D - Desabilitado", "value": "D"}],
    "RECONEXAO_IMEDIATA_W": [{"label": "H - Habilitado", "value": "H"}, {"label": "D - Desabilitado", "value": "D"}],
    "USAR_DNS_W": [{"label": "H - Habilitado", "value": "H"}, {"label": "D - Desabilitado", "value": "D"}],
    "MODO_CADASTRO[P]": [{"label": "P - Padrão", "value": "P"}, {"label": "D - Dinâmico", "value": "D"}],
    "COR_SENSOR[G]": [{"label": "G - Green", "value": "G"}, {"label": "R - Red", "value": "R"}, {"label": "B - Blue", "value": "B"}],
    "TEMPLATE[P]": [{"label": "P - Padrão", "value": "P"}, {"label": "I - ISO", "value": "I"}, {"label": "A - ANSI", "value": "A"}],
    "VEL_SERIAL": [{"label": "9600", "value": "9600"}, {"label": "19200", "value": "19200"}, {"label": "57600", "value": "57600"}, {"label": "115200", "value": "115200"}],
    "TIPO_COM": [{"label": "S - Serial", "value": "S"}, {"label": "T - TCP", "value": "T"}],
    "MODE": [{"label": "C - Cliente", "value": "C"}, {"label": "S - Servidor", "value": "S"}],
    "MODE_W": [{"label": "C - Cliente", "value": "C"}, {"label": "S - Servidor", "value": "S"}],
}


class EvoRepAuthApp(QWidget):
    def __init__(self):
        super().__init__()
        # Estado independente por aba
        self.tab_data = {
            "main_": {
                "persistent_sock": None,
                "session_key": None,
                "connected": False,
                "worker": None,
                "listener_worker": None,
                "last_sent_text": "",
                "last_sent_bytes": "",
                "last_received_text": "",
                "last_received_bytes": "",
            },
            "client_": {
                "persistent_sock": None,
                "session_key": None,
                "connected": False,
                "worker": None,
                "listener_worker": None,
                "last_sent_text": "",
                "last_sent_bytes": "",
                "last_received_text": "",
                "last_received_bytes": "",
            },
            "f3_": {
                "persistent_sock": None,
                "session_key": None, # F3 não usa criptografia
                "connected": False,
                "worker": None,
                "listener_worker": None,
                "last_sent_text": "",
                "last_sent_bytes": "",
                "last_received_text": "",
                "last_received_bytes": "",
            }
        }
        
        self.show_bytes = False
        self.settings = QSettings("EvoRep", "EvoRepAuthApp")
        
        # Variáveis para histórico do modo manual
        self.manual_history = []
        self.history_index = -1
        self.last_manual_command = "01+RH+00"
        
        self.connect_timer = QTimer()
        self.connect_timer.timeout.connect(self.animate_connecting_button)
        self.dot_count = 0
        
        self.param_inputs = {}  # Guarda referências dos QLineEdit gerados
        
        self._setup_ui()
        self.load_config()
        
        self.setCursor(Qt.CursorShape.ArrowCursor)
        QApplication.processEvents()
        
        # Aciona manualmente o evento pela primeira vez para exibir o painel custom/manual
        self.on_command_selected(0)

    def closeEvent(self, event):
        """Salva todas as configurações e desconecta sockets ao fechar."""
        self.save_config()
        # Garantir fechamento de todos os sockets ativos
        self.disconnect("main_")
        self.disconnect("client_")
        self.disconnect("f3_")
        
        # Salva posição e tamanho da janela
        self.settings.setValue("geometry", self.saveGeometry())
        # Salva a aba atual
        self.settings.setValue("active_tab", self.stacked_widget.currentIndex())
        super().closeEvent(event)

    def _setup_ui(self):
        self.setWindowTitle("Protocolo EVO REP-A/C")
        self.stacked_widget = QStackedWidget(self)

        # Aba Principal (F1)
        self.main_tab = self._create_rep_tab(prefix="main_")
        # Aba de Log (F7)
        self.log_tab = self._create_log_tab()
        # Aba Modo Cliente (F2)
        self.client_tab = self._create_rep_tab(prefix="client_")
        # Aba F3 (Sem criptografia)
        self.f3_tab = self._create_rep_tab(prefix="f3_")

        self.stacked_widget.addWidget(self.main_tab)   # Index 0
        self.stacked_widget.addWidget(self.log_tab)    # Index 1
        self.stacked_widget.addWidget(self.client_tab) # Index 2
        self.stacked_widget.addWidget(self.f3_tab)     # Index 3

        root_layout = QVBoxLayout()
        root_layout.addWidget(self.stacked_widget)
        self.setLayout(root_layout)
        
        self.setMinimumSize(850, 600)
        self.resize(850, 600)

    def _create_rep_tab(self, prefix="main_"):
        is_client_mode = (prefix == "client_")
        is_f3 = (prefix == "f3_")
        
        tab = QWidget()
        layout = QVBoxLayout()

        # --- ÁREA SUPERIOR: DIVISÃO (Login) vs (Comandos) ---
        top_layout = QHBoxLayout()
        
        # Painel de Conexão
        conn_widget = QWidget()
        conn_layout = QGridLayout()
        conn_layout.setContentsMargins(0, 0, 0, 0)

        conn_layout.addWidget(QLabel(""), 0, 0, 1, 2) # Spacer topo
        conn_layout.addWidget(QLabel("IP:"), 1, 0)
        
        ip_val = get_local_ip() if is_client_mode else "192.168.60.71"
        ip_input = QLineEdit(ip_val)
        conn_layout.addWidget(ip_input, 1, 1)

        conn_layout.addWidget(QLabel("Porta:"), 2, 0)
        port_input = QLineEdit("3000")
        conn_layout.addWidget(port_input, 2, 1)

        if not is_f3:
            conn_layout.addWidget(QLabel("Usuário:"), 3, 0)
            user_input = QLineEdit("teste fabrica")
            conn_layout.addWidget(user_input, 3, 1)

            conn_layout.addWidget(QLabel("Senha:"), 4, 0)
            password_input = QLineEdit("111111")
            password_input.setEchoMode(QLineEdit.EchoMode.Password)
            password_input.setMaxLength(6)
            conn_layout.addWidget(password_input, 4, 1)

        # 🔹 REQUISITO 2: Refatoração dos Botões da Aba F2 (Modo Cliente)
        if is_client_mode:
            self.client_btn_server_control = QPushButton("Iniciar Servidor")
            self.client_btn_client_state = QPushButton("Aguardando Conexão")
            self.client_btn_client_state.setEnabled(False)
            
            client_btns_layout = QHBoxLayout()
            client_btns_layout.addWidget(self.client_btn_server_control)
            client_btns_layout.addWidget(self.client_btn_client_state)
            conn_layout.addLayout(client_btns_layout, 5, 0, 1, 2)
            
            self.client_btn_server_control.clicked.connect(self.on_connect_clicked)
            self.client_btn_client_state.clicked.connect(self.on_connect_clicked)
        elif is_f3:
            self.f3_connect_button = QPushButton("Conectar")
            self.f3_connect_button.clicked.connect(self.on_connect_clicked)
            conn_layout.addWidget(self.f3_connect_button, 5, 0, 1, 2)
        else:
            self.main_connect_button = QPushButton("Conectar")
            self.main_connect_button.clicked.connect(self.on_connect_clicked)
            conn_layout.addWidget(self.main_connect_button, 5, 0, 1, 2)

        conn_layout.setRowStretch(6, 1) 
        conn_widget.setLayout(conn_layout)

        # Painel de Comandos (ou Identificação no F3)
        if is_f3:
            cmds_group = QGroupBox("Identificação do Equipamento")
            cmds_group_layout = QFormLayout(cmds_group)
            
            self.f3_rep_num_field = QLineEdit()
            self.f3_rep_num_field.setReadOnly(True)
            self.f3_rep_num_field.setPlaceholderText("Aguardando conexão...")
            
            self.f3_unlock_code_field = QLineEdit()
            self.f3_unlock_code_field.setReadOnly(True)
            self.f3_unlock_code_field.setPlaceholderText("Aguardando conexão...")
            
            cmds_group_layout.addRow("Número do REP:", self.f3_rep_num_field)
            cmds_group_layout.addRow("Código de Bloqueio:", self.f3_unlock_code_field)

            cmds_group_layout.addRow(QLabel("")) # Spacer para separar
            cmds_group_layout.addRow(QLabel("Código de Desbloqueio:"))
            self.f3_unlock_input_field = QLineEdit()
            self.f3_unlock_input_field.setPlaceholderText("Cole ou digite o código de desbloqueio aqui")
            cmds_group_layout.addRow(self.f3_unlock_input_field)

            self.f3_unlock_button = QPushButton("Desbloquear")
            self.f3_unlock_button.setEnabled(False) # Desabilitado até conectar
            cmds_group_layout.addRow(self.f3_unlock_button)
            
            # Adiciona um widget invisível para manter as referências esperadas por outras funções
            command_combo = NoScrollComboBox()
            command_combo.setVisible(False)
            dynamic_layout = QFormLayout()
            send_button = QPushButton() # Este será o send_button para F3
            send_button.setVisible(False)
            cmd_description_label = QLabel()
            cmd_description_label.setVisible(False)
        else:
            cmds_group = QGroupBox("Construção de Comandos")
            cmds_group_layout = QVBoxLayout(cmds_group)


            combo_layout = QHBoxLayout()
            combo_layout.addWidget(QLabel("Selecionar:"))
            
            command_combo = NoScrollComboBox()
            command_combo.addItem("Modo Manual / Custom", None)
            for code, cmd_def in COMMANDS_REGISTRY.items():
                if code in ["RR_MEMORIA", "RR_NSR", "RR_DATA"]: continue
                resumo = cmd_def.description.split(':')[0] if ':' in cmd_def.description else cmd_def.description.split('.')[0]
                command_combo.addItem(f"{code} - {resumo}", code)
            combo_layout.addWidget(command_combo)
            cmds_group_layout.addLayout(combo_layout)

            cmd_description_label = QLabel("")
            cmd_description_label.setWordWrap(True)
            cmd_description_label.setStyleSheet("color: #666; font-style: italic;")
            cmds_group_layout.addWidget(cmd_description_label)

            params_scroll = QScrollArea()
            params_scroll.setWidgetResizable(True)
            params_scroll.setFrameShape(QFrame.Shape.NoFrame)
            dynamic_params_widget = QWidget()
            dynamic_layout = QFormLayout(dynamic_params_widget)
            params_scroll.setWidget(dynamic_params_widget)
            cmds_group_layout.addWidget(params_scroll)
            
            send_button = QPushButton("Enviar comando")
            send_button.setEnabled(False)
            cmds_group_layout.addWidget(send_button)

        top_layout.addWidget(conn_widget, 1)
        top_layout.addWidget(cmds_group, 3)
        layout.addLayout(top_layout)

        # --- ÁREA INFERIOR: LOG DE COMUNICAÇÃO ---
        sent_layout = QVBoxLayout()
        sent_layout.addWidget(QLabel("String enviada:"))
        sent_output = QTextEdit()
        sent_output.setReadOnly(True)
        sent_layout.addWidget(sent_output)

        received_layout = QVBoxLayout()
        received_layout.addWidget(QLabel("String recebida:"))
        received_output = QTextEdit()
        received_output.setReadOnly(True)
        received_layout.addWidget(received_output)

        boxes_layout = QHBoxLayout()
        boxes_layout.addLayout(sent_layout)
        boxes_layout.addLayout(received_layout)
        layout.addLayout(boxes_layout)

        control_layout = QHBoxLayout()
        clear_button = QPushButton("Limpar")
        control_layout.addWidget(clear_button)

        toggle_mode_button = QPushButton("Exibir em bytes")
        control_layout.addWidget(toggle_mode_button)
        layout.addLayout(control_layout)

        tab.setLayout(layout)

        # Armazenar referências
        setattr(self, f"{prefix}ip_input", ip_input)
        setattr(self, f"{prefix}port_input", port_input)
        if not is_f3:
            setattr(self, f"{prefix}user_input", user_input)
            setattr(self, f"{prefix}password_input", password_input)
            password_input.textChanged.connect(self.validate_password_input)
            password_input.returnPressed.connect(self.on_enter_pressed)
            user_input.returnPressed.connect(self.on_enter_pressed)

        setattr(self, f"{prefix}command_combo", command_combo)
        setattr(self, f"{prefix}dynamic_layout", dynamic_layout)
        setattr(self, f"{prefix}send_button", send_button)
        setattr(self, f"{prefix}sent_output", sent_output)
        setattr(self, f"{prefix}received_output", received_output)
        setattr(self, f"{prefix}clear_button", clear_button)
        setattr(self, f"{prefix}toggle_mode_button", toggle_mode_button)
        setattr(self, f"{prefix}cmd_description_label", cmd_description_label)

        # Conectar sinais comuns
        ip_input.returnPressed.connect(self.on_enter_pressed)
        port_input.returnPressed.connect(self.on_enter_pressed)
        command_combo.currentIndexChanged.connect(self.on_command_selected)
        send_button.clicked.connect(self.on_send_command_clicked)
        clear_button.clicked.connect(self.on_clear_clicked)
        toggle_mode_button.clicked.connect(self.on_toggle_display_mode)

        if is_f3:
            self.f3_unlock_button.clicked.connect(self.on_f3_unlock_clicked)
            self.f3_unlock_input_field.returnPressed.connect(self.on_f3_unlock_clicked)
            # Habilitar/desabilitar o botão de desbloqueio com base na conexão
            self.f3_connect_button.clicked.connect(lambda: self.f3_unlock_button.setEnabled(self.tab_data["f3_"]["connected"]))


        return tab

    def _create_log_tab(self):
        log_tab = QWidget()
        log_layout = QVBoxLayout()
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        log_layout.addWidget(self.log_output)
        log_tab.setLayout(log_layout)
        return log_tab

    def _get_active_prefix(self):
        idx = self.stacked_widget.currentIndex()
        if idx == 0: return "main_"
        if idx == 2: return "client_"
        if idx == 3: return "f3_"
        return "main_" # Fallback

    def _get_widget(self, name):
        prefix = self._get_active_prefix()
        return getattr(self, f"{prefix}{name}")

    def on_command_selected(self, index):
        prefix = self._get_active_prefix()
        dynamic_layout = getattr(self, f"{prefix}dynamic_layout")
        command_combo = getattr(self, f"{prefix}command_combo")
        cmd_description_label = getattr(self, f"{prefix}cmd_description_label")

        while dynamic_layout.rowCount() > 0:
            dynamic_layout.removeRow(0)
        self.param_inputs.clear()

        cmd_code = command_combo.currentData()

        if cmd_code is None:
            cmd_description_label.setText("Modo Manual: Digite a string bruta do comando para enviá-la sem validação.")
            self.manual_input = QLineEdit(self.last_manual_command)
            self.manual_input.installEventFilter(self)
            self.manual_input.returnPressed.connect(self.on_enter_pressed)
            dynamic_layout.addRow("Comando Bruto:", self.manual_input)
            self.param_inputs["_manual"] = self.manual_input
        else:
            cmd_def = COMMANDS_REGISTRY[cmd_code]
            cmd_description_label.setText(cmd_def.description)
            
            pending_data_field = None
            pending_data_label = None
            
            for param in cmd_def.params:
                label_text = f"{param.name} {'' if param.required else '(opcional)'}:"

                if param.choices:
                    if cmd_code == "RC" and "config" in cmd_def.description.lower(): # Checklist apenas se for RC configuracao
                        checkboxes = []
                        for choice in param.choices:
                            cb = QCheckBox(choice['label'])
                            cb.setProperty("value", choice['value'])
                            dynamic_layout.addRow("", cb)
                            checkboxes.append(cb)
                        self.param_inputs[param.name] = checkboxes
                        continue
                    else:
                        input_field = NoScrollComboBox()
                        for choice in param.choices:
                            input_field.addItem(choice['label'], choice['value'])
                        dynamic_layout.addRow(label_text, input_field)
                        self.param_inputs[param.name] = input_field
                        
                        if cmd_code == "EC" and param.name == "Configuração":
                            input_field.currentIndexChanged.connect(self.update_ec_valor_field)
                        elif cmd_code == "RR" and param.name == "Tipo":
                            input_field.currentIndexChanged.connect(self.update_rr_fields)
                        continue
                else:
                    input_field = QLineEdit(str(param.default))
                    input_field.setPlaceholderText(param.description)
                    input_field.returnPressed.connect(self.on_enter_pressed)

                    if param.name.lower() == "data" or "dd/mm/aa" in param.description.lower():
                        input_field.setInputMask("99/99/99;_")
                        input_field.setText(time.strftime("%d/%m/%y"))
                    elif param.name.lower() == "hora" or "hh:mm:ss" in param.description.lower():
                        input_field.setInputMask("99:99:99;_")
                        input_field.setText(time.strftime("%H:%M:%S"))

                if param.name.lower() == "data" or "dd/mm/aa" in param.description.lower():
                    pending_data_field = input_field
                    pending_data_label = label_text
                    self.param_inputs[param.name] = input_field
                    continue
                elif (param.name.lower() == "hora" or "hh:mm:ss" in param.description.lower()) and pending_data_field is not None:
                    hbox = QHBoxLayout()
                    hbox.setContentsMargins(0, 0, 0, 0)
                    hbox.addWidget(pending_data_field)
                    label_hora = QLabel(label_text)
                    hbox.addWidget(label_hora)
                    hbox.addWidget(input_field)
                    dynamic_layout.addRow(pending_data_label, hbox)
                    self.param_inputs[param.name] = input_field
                    pending_data_field = None
                    continue

                dynamic_layout.addRow(label_text, input_field)
                self.param_inputs[param.name] = input_field

            if pending_data_field is not None:
                dynamic_layout.addRow(pending_data_label, pending_data_field)
            
            if cmd_code == "EC":
                self.update_ec_valor_field()
            elif cmd_code == "RR":
                self.update_rr_fields()

    def update_ec_valor_field(self):
        """Atualiza o campo 'Valor' do comando EC com base na 'Configuração' selecionada."""
        prefix = self._get_active_prefix()
        dynamic_layout = getattr(self, f"{prefix}dynamic_layout")
        config_combo = self.param_inputs.get("Configuração")
        if not config_combo: return
        
        config_key = config_combo.currentData()
        
        # Remove o campo Valor atual (se houver)
        old_valor_widget = self.param_inputs.get("Valor")
        if old_valor_widget:
            dynamic_layout.removeRow(old_valor_widget)
            
        choices = EC_VAL_CHOICES.get(config_key)
        
        if choices:
            new_input = NoScrollComboBox()
            for c in choices:
                new_input.addItem(c['label'], c['value'])
        else:
            new_input = QLineEdit()
            if config_key == "LOGIN": new_input.setPlaceholderText("Máx 16 caracteres")
            elif config_key == "SENHA_MENU": new_input.setPlaceholderText("6 dígitos")
            elif config_key == "MENSAGEM": new_input.setPlaceholderText("Máx 20 caracteres")
            elif config_key == "ACORDO_SIND": new_input.setPlaceholderText("17 dígitos")
            elif config_key == "TAM_BOB": new_input.setPlaceholderText("0 ~ 400")
            elif config_key == "TEMPO_LIB": new_input.setPlaceholderText("0 ~ 60")
            elif config_key == "NTP_TIMEOUT": new_input.setPlaceholderText("1 ~ 99")
            elif any(x in config_key for x in ["IP", "DNS", "GATEWAY", "SERVER_IP"]):
                new_input.setPlaceholderText("Ex: 192.168.1.100")
            elif "PORTA" in config_key or "SERVER_PORT" in config_key:
                new_input.setPlaceholderText("1000 ~ 65535")
        
        if hasattr(new_input, "returnPressed"):
            new_input.returnPressed.connect(self.on_enter_pressed)
            
        dynamic_layout.addRow("Valor:", new_input)
        self.param_inputs["Valor"] = new_input

    def update_rr_fields(self):
        """Atualiza os campos secundários do comando RR com base no 'Tipo' selecionado."""
        prefix = self._get_active_prefix()
        dynamic_layout = getattr(self, f"{prefix}dynamic_layout")
        tipo_combo = self.param_inputs.get("Tipo")
        if not tipo_combo: return
        
        sub_cmd_code = tipo_combo.currentData()
        sub_cmd_def = COMMANDS_REGISTRY.get(sub_cmd_code)
        
        while dynamic_layout.rowCount() > 1:
            dynamic_layout.removeRow(1)
            
        keys_to_remove = [k for k in self.param_inputs.keys() if k not in ["Tipo", "_manual"]]
        for k in keys_to_remove:
            del self.param_inputs[k]
            
        if not sub_cmd_def: return
        
        pending_data_field = None
        pending_data_label = None
        
        for param in sub_cmd_def.params:
            label_text = f"{param.name} {'' if param.required else '(opcional)'}:"
            input_field = QLineEdit(str(param.default))
            input_field.setPlaceholderText(param.description)
            input_field.returnPressed.connect(self.on_enter_pressed)

            if param.name.lower() == "data" or "dd/mm/aa" in param.description.lower():
                input_field.setInputMask("99/99/99;_")
                input_field.setText(time.strftime("%d/%m/%y"))
            elif param.name.lower() == "hora" or "hh:mm:ss" in param.description.lower():
                input_field.setInputMask("99:99:99;_")
                input_field.setText(time.strftime("%H:%M:%S"))

            if param.name.lower() == "data" or "dd/mm/aa" in param.description.lower():
                pending_data_field = input_field
                pending_data_label = label_text
                self.param_inputs[param.name] = input_field
                continue
            elif (param.name.lower() == "hora" or "hh:mm:ss" in param.description.lower()) and pending_data_field is not None:
                hbox = QHBoxLayout()
                hbox.setContentsMargins(0, 0, 0, 0)
                hbox.addWidget(pending_data_field)
                label_hora = QLabel(label_text)
                hbox.addWidget(label_hora)
                hbox.addWidget(input_field)
                dynamic_layout.addRow(pending_data_label, hbox)
                self.param_inputs[param.name] = input_field
                pending_data_field = None
                continue

            dynamic_layout.addRow(label_text, input_field)
            self.param_inputs[param.name] = input_field

        if pending_data_field is not None:
            dynamic_layout.addRow(pending_data_label, pending_data_field)

    def eventFilter(self, source, event):
        if source == getattr(self, "manual_input", None) and event.type() == QEvent.Type.KeyPress:
            if event.key() == Qt.Key.Key_Up:
                if self.manual_history:
                    if self.history_index > 0:
                        self.history_index -= 1
                        self.manual_input.setText(self.manual_history[self.history_index])
                    elif self.history_index == -1:
                        self.history_index = len(self.manual_history) - 1
                        self.manual_input.setText(self.manual_history[self.history_index])
                return True
            elif event.key() == Qt.Key.Key_Down:
                if self.manual_history:
                    if self.history_index < len(self.manual_history) - 1:
                        self.history_index += 1
                        self.manual_input.setText(self.manual_history[self.history_index])
                    else:
                        self.history_index = len(self.manual_history)
                        self.manual_input.setText(self.last_manual_command)
                return True
        return super().eventFilter(source, event)
                
    def on_send_command_clicked(self):
        prefix = self._get_active_prefix()
        state = self.tab_data[prefix]
        
        if not state["persistent_sock"]:
            self.append_log(f"Erro: Socket não disponível na aba {prefix}. Conecte primeiro.")
            return

        command_combo = self._get_widget("command_combo")
        cmd_code = command_combo.currentData()
        
        if cmd_code is None:
            command_str = self.param_inputs["_manual"].text().strip()
            if not command_str:
                self.append_log("Preencha o comando manual antes de enviar.")
                return
            self.last_manual_command = command_str
            if not self.manual_history or self.manual_history[-1] != command_str:
                self.manual_history.append(command_str)
                if len(self.manual_history) > 5:
                    self.manual_history.pop(0)
            self.history_index = -1
        else:
            if cmd_code == "RR":
                cmd_code = self.param_inputs["Tipo"].currentData()
                
            cmd_def = COMMANDS_REGISTRY[cmd_code]
            kwargs = {}
            for param_name, input_field in self.param_inputs.items():
                if isinstance(input_field, list):
                    selected_values = [cb.property("value") for cb in input_field if cb.isChecked()]
                    val = "]".join(selected_values)
                elif isinstance(input_field, QComboBox):
                    val = input_field.currentData()
                else:
                    val = input_field.text().strip()
                if cmd_code == "EU":
                    if param_name == "Matrícula2" and val: val = "}" + val
                    elif param_name == "Senha" and val: val = "[" + val
                kwargs[param_name] = val
            try:
                command_str = cmd_def.build(**kwargs)
            except ValueError as e:
                QMessageBox.warning(self, "Erro de Validação", str(e))
                self.append_log(f"Comando abortado: {e}")
                return

        send_button = self._get_widget("send_button")
        send_button.setEnabled(False)
        self.command_worker = CommandWorker(state["persistent_sock"], command_str, state["session_key"])
        self.command_worker.sent_signal.connect(lambda txt: self.append_sent(txt, prefix))
        self.command_worker.sent_bytes_signal.connect(lambda hex_txt: self.append_sent_bytes(hex_txt, prefix))
        self.command_worker.finished_signal.connect(self.on_send_command_finished)
        self.command_worker.start()

    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_F1:
            self.stacked_widget.setCurrentIndex(0)
            self.on_command_selected(0)
        elif event.key() == Qt.Key.Key_F7:
            self.stacked_widget.setCurrentIndex(1)
        elif event.key() == Qt.Key.Key_F2:
            self.stacked_widget.setCurrentIndex(2)
            self.on_command_selected(0)
        elif event.key() == Qt.Key.Key_F3:
            self.stacked_widget.setCurrentIndex(3)
            self.on_command_selected(0)
        elif event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            self.on_enter_pressed()
        else:
            super().keyPressEvent(event)

    def on_enter_pressed(self):
        prefix = self._get_active_prefix()
        if prefix == "main_":
            if self.main_connect_button.text() == "Conectar":
                if self.main_connect_button.isEnabled():
                    self.on_connect_clicked()
            elif self.main_connect_button.text() == "Desconectar":
                if self.main_send_button.isEnabled():
                    self.on_send_command_clicked()
        elif prefix == "client_":
            if self.client_btn_server_control.text() == "Iniciar Servidor":
                if self.client_btn_server_control.isEnabled():
                    self.on_connect_clicked()
            elif self.client_btn_client_state.text() == "Desconectar":
                if self.client_send_button.isEnabled():
                    self.on_send_command_clicked()
        elif prefix == "f3_":
            if self.f3_connect_button.text() == "Conectar":
                if self.f3_connect_button.isEnabled():
                    self.on_connect_clicked()
            elif self.f3_connect_button.text() == "Desconectar":
                if self.f3_send_button.isEnabled():
                    self.on_send_command_clicked()

    def validate_password_input(self):
        prefix = self._get_active_prefix()
        if prefix == "f3_": return
        state = self.tab_data[prefix]
        password_input = self._get_widget("password_input")
        password = password_input.text()
        
        if not state["connected"]:
            is_valid = len(password) == 6 and password.isdigit()
            if prefix == "main_":
                self.main_connect_button.setEnabled(is_valid if password else False)
            elif prefix == "client_":
                self.client_btn_server_control.setEnabled(is_valid if password else False)

    def set_inputs_enabled(self, enabled: bool, prefix=None):
        if prefix is None: prefix = self._get_active_prefix()
        getattr(self, f"{prefix}ip_input").setEnabled(enabled)
        getattr(self, f"{prefix}port_input").setEnabled(enabled)
        if prefix != "f3_":
            getattr(self, f"{prefix}user_input").setEnabled(enabled)
            getattr(self, f"{prefix}password_input").setEnabled(enabled)

    def load_config(self):
        geom = self.settings.value("geometry")
        if geom: self.restoreGeometry(geom)

        self.main_ip_input.setText(self.settings.value('ip', '192.168.60.83'))
        self.main_port_input.setText(str(self.settings.value('port', 3000)))
        self.main_user_input.setText(self.settings.value('user', 'teste fabrica'))
        self.main_password_input.setText(self.settings.value('password', '111111'))
        
        self.client_ip_input.setText(get_local_ip())
        self.client_port_input.setText(str(self.settings.value('client_port', 3000)))
        self.client_user_input.setText(self.settings.value('user', 'teste fabrica'))
        self.client_password_input.setText(self.settings.value('password', '111111'))

        self.f3_ip_input.setText(self.settings.value('f3_ip', '192.168.60.83'))
        self.f3_port_input.setText(str(self.settings.value('f3_port', 3000)))
        
        saved_history = self.settings.value('manual_history', [])
        if isinstance(saved_history, list): self.manual_history = saved_history
        self.last_manual_command = self.settings.value('last_manual_command', '01+RH+00')
        
        active_tab = self.settings.value("active_tab", 0)
        self.stacked_widget.setCurrentIndex(int(active_tab))
        
        self.validate_password_input()
        self.on_command_selected(0)

    def save_config(self):
        prefix = self._get_active_prefix()
        ip_input = getattr(self, f"{prefix}ip_input")
        port_input = getattr(self, f"{prefix}port_input")

        if prefix == "main_":
            self.settings.setValue('ip', ip_input.text())
            self.settings.setValue('port', port_input.text())
        elif prefix == "client_":
            self.settings.setValue('client_port', port_input.text())
        elif prefix == "f3_":
            self.settings.setValue('f3_ip', ip_input.text())
            self.settings.setValue('f3_port', port_input.text())
            
        if prefix != "f3_":
            self.settings.setValue('user', getattr(self, f"{prefix}user_input").text())
            self.settings.setValue('password', getattr(self, f"{prefix}password_input").text())
            
        self.settings.setValue('manual_history', self.manual_history)
        self.settings.setValue('last_manual_command', self.last_manual_command)
        self.settings.sync() 

    def append_log(self, message: str):
        self.log_output.append(message)

    def update_sent_received_output(self, prefix=None):
        if prefix is None: prefix = self._get_active_prefix()
        state = self.tab_data[prefix]
        sent_output = getattr(self, f"{prefix}sent_output")
        received_output = getattr(self, f"{prefix}received_output")

        if self.show_bytes:
            sent_output.setPlainText(state["last_sent_bytes"])
            received_output.setPlainText(state["last_received_bytes"])
        else:
            sent_output.setPlainText(state["last_sent_text"])
            received_output.setPlainText(state["last_received_text"])
            
        sent_output.verticalScrollBar().setValue(sent_output.verticalScrollBar().maximum())
        received_output.verticalScrollBar().setValue(received_output.verticalScrollBar().maximum())

    def append_sent(self, text: str, prefix=None):
        if prefix is None: prefix = self._get_active_prefix()
        state = self.tab_data[prefix]
        if state["last_sent_text"]: state["last_sent_text"] += "\n" + text
        else: state["last_sent_text"] = text
        self.update_sent_received_output(prefix)

    def append_sent_bytes(self, hex_text: str, prefix=None):
        if prefix is None: prefix = self._get_active_prefix()
        state = self.tab_data[prefix]
        if state["last_sent_bytes"]: state["last_sent_bytes"] += "\n" + hex_text
        else: state["last_sent_bytes"] = hex_text
        self.update_sent_received_output(prefix)
    
    def append_received(self, text: str, prefix=None):
        if prefix is None: prefix = self._get_active_prefix()
        state = self.tab_data[prefix]
        
        # 🔹 Lógica especial para processar resposta RB na aba F3
        if prefix == "f3_":
            if text.startswith("01+RB+000+"):
                try:
                    # Formato esperado: 01+RB+000+{CódigoDesbloqueio}]{numeroREP}
                    data_part = text[10:] # Pula o prefixo fixo
                    if "]" in data_part:
                        unlock_code, rep_num = data_part.split("]", 1)
                        unlock_code = unlock_code.strip()
                        rep_num = rep_num.strip()
                        
                        self.f3_unlock_code_field.setText(unlock_code)
                        self.f3_rep_num_field.setText(rep_num)
                        
                        # Salva nas variáveis de estado também
                        state["unlock_code"] = unlock_code
                        state["rep_num"] = rep_num

                        # 🔹 REQUISITO: Se o código de desbloqueio estiver vazio, o equipamento já está desbloqueado
                        if not unlock_code:
                            QMessageBox.information(self, "Conexão F3", "Equipamento já desbloqueado")
                except Exception as e:
                    self.append_log(f"F3: Erro ao processar dados de identificação: {e}")
            elif text.startswith("01+EB+000"):
                QMessageBox.information(self, "Desbloqueio F3", "Equipamento desbloqueado com sucesso!")
            elif text.startswith("01+EB+012"):
                QMessageBox.warning(self, "Desbloqueio F3", "Código de Desbloqueio Inválido")

        if state["last_received_text"]: state["last_received_text"] += "\n" + text
        else: state["last_received_text"] = text
        self.update_sent_received_output(prefix)

    def append_received_bytes(self, hex_text: str, prefix=None):
        if prefix is None: prefix = self._get_active_prefix()
        state = self.tab_data[prefix]
        if state["last_received_bytes"]: state["last_received_bytes"] += "\n" + hex_text
        else: state["last_received_bytes"] = hex_text
        self.update_sent_received_output(prefix)

    def on_toggle_display_mode(self):
        self.show_bytes = not self.show_bytes
        btn_text = "Exibir em string" if self.show_bytes else "Exibir em bytes"
        self.main_toggle_mode_button.setText(btn_text)
        self.client_toggle_mode_button.setText(btn_text)
        self.f3_toggle_mode_button.setText(btn_text)
        self.update_sent_received_output("main_")
        self.update_sent_received_output("client_")
        self.update_sent_received_output("f3_")

    def animate_connecting_button(self):
        self.dot_count = (self.dot_count + 1) % 4
        dots = "." * self.dot_count
        self.main_connect_button.setText(f"Conectando{dots}")

    def on_send_command_finished(self, success: bool, message: str):
        self.append_log(message)
        prefix = self._get_active_prefix()
        getattr(self, f"{prefix}send_button").setEnabled(True)

    def on_clear_clicked(self):
        prefix = self._get_active_prefix()
        state = self.tab_data[prefix]
        state["last_sent_text"] = ""
        state["last_sent_bytes"] = ""
        state["last_received_text"] = ""
        state["last_received_bytes"] = ""
        self.update_sent_received_output(prefix)
        self.append_log(f"Campos da aba {prefix} limpos.")

    def on_connect_clicked(self):
        prefix = self._get_active_prefix()
        state = self.tab_data[prefix]
        
        if state["connected"]:
            self.disconnect(prefix)
            return

        if prefix == "client_" and state["worker"] and state["worker"].isRunning():
            self.disconnect(prefix)
            return

        ip = getattr(self, f"{prefix}ip_input").text().strip()
        port_text = getattr(self, f"{prefix}port_input").text().strip()

        if prefix != "f3_":
            user = getattr(self, f"{prefix}user_input").text().strip()
            password = getattr(self, f"{prefix}password_input").text().strip()
            if not user or not password:
                self.append_log("Preencha usuário e senha.")
                return

        if not ip or not port_text:
            self.append_log("Preencha IP e Porta.")
            return

        try: port = int(port_text)
        except ValueError:
            self.append_log("Porta inválida.")
            return

        self.save_config()
        self.log_output.clear()

        if prefix == "main_":
            self.main_connect_button.setEnabled(False)
            self.connect_timer.start(350) 
            state["worker"] = NetworkWorker(ip, port, user, password)
        elif prefix == "client_":
            self.client_btn_server_control.setText("Desligar Servidor")
            self.client_btn_client_state.setText("Aguardando Conexão")
            self.client_btn_client_state.setEnabled(False)
            state["worker"] = ClientNetworkWorker(ip, port, user, password)
        elif prefix == "f3_":
            self.f3_connect_button.setEnabled(False)
            state["worker"] = F3NetworkWorker(ip, port)
            state["worker"].auto_sent_signal.connect(lambda txt, bts: self.on_f3_auto_sent(txt, bts))
            
        state["worker"].log_signal.connect(self.append_log)
        state["worker"].finished_signal.connect(lambda s, m, sk, key: self.on_finished(s, m, sk, key, prefix))
        state["worker"].start()

    def on_f3_auto_sent(self, text, packet_bytes):
        self.append_sent(text, "f3_")
        self.append_sent_bytes(packet_bytes.hex(' '), "f3_")

    def on_f3_unlock_clicked(self):
        prefix = "f3_"
        state = self.tab_data[prefix]

        if not state["connected"]:
            self.append_log("F3: Erro: Não conectado para enviar comando de desbloqueio.")
            return

        unlock_code = self.f3_unlock_input_field.text().strip()
        if not unlock_code:
            QMessageBox.warning(self, "Desbloqueio F3", "Por favor, insira o Código de Bloqueio.")
            return
        
        # Formato: 01+EB+00+{CódigoDesbloqueio}
        command_str = f"01+EB+00+{unlock_code}"
        self.append_log(f"F3: Enviando comando de desbloqueio: {command_str}")

        self.f3_unlock_button.setEnabled(False) # Desabilita o botão para evitar múltiplos cliques
        # Garantir que session_key seja None para F3 (sem criptografia)
        self.command_worker = CommandWorker(state["persistent_sock"], command_str, None)
        self.command_worker.sent_signal.connect(lambda txt: self.append_sent(txt, prefix))
        self.command_worker.sent_bytes_signal.connect(lambda hex_txt: self.append_sent_bytes(hex_txt, prefix))
        self.command_worker.finished_signal.connect(self.on_f3_unlock_command_finished)
        self.command_worker.start()

    def on_f3_unlock_command_finished(self, success: bool, message: str):
        self.append_log(f"F3 Desbloqueio: {message}")
        self.f3_unlock_button.setEnabled(True) # Reabilita o botão
        if not success:
            QMessageBox.critical(self, "Erro Desbloqueio F3", "Falha ao enviar comando de desbloqueio.")

    def disconnect(self, prefix=None):
        if prefix is None: prefix = self._get_active_prefix()
        state = self.tab_data[prefix]

        if state["listener_worker"]:
            state["listener_worker"].stop()
            if state["persistent_sock"]:
                try: state["persistent_sock"].shutdown(socket.SHUT_RDWR)
                except: pass
            state["listener_worker"].wait(500)
            state["listener_worker"] = None

        if state["worker"]:
            if hasattr(state["worker"], "stop"): state["worker"].stop()
            state["worker"].quit()
            if not state["worker"].wait(1000):
                state["worker"].terminate()
                state["worker"].wait()
            state["worker"] = None

        if state["persistent_sock"]:
            try:
                state["persistent_sock"].setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, bytes([1,0,0,0,0,0,0,0]))
                state["persistent_sock"].close()
            except: pass
            state["persistent_sock"] = None
        
        state["session_key"] = None
        state["connected"] = False
        
        if prefix == "main_":
            self.connect_timer.stop()
            self.main_connect_button.setText("Conectar")
            self.main_connect_button.setEnabled(True)
        elif prefix == "client_":
            self.client_btn_server_control.setText("Iniciar Servidor")
            self.client_btn_server_control.setEnabled(True)
            self.client_btn_client_state.setText("Aguardando Conexão")
            self.client_btn_client_state.setEnabled(False)
        elif prefix == "f3_":
            self.f3_connect_button.setText("Conectar")
            self.f3_connect_button.setEnabled(True)
            self.f3_unlock_button.setEnabled(False)

        getattr(self, f"{prefix}send_button").setEnabled(False)
        self.set_inputs_enabled(True, prefix)
        self.append_log(f"Estado resetado ({prefix}).")

    def on_listener_error(self, error_msg, prefix):
        self.append_log(f"Erro na escuta ({prefix}): {error_msg}")
        self.disconnect(prefix)

    def on_finished(self, success: bool, message: str, sock, session_key, prefix):
        if prefix == "main_":
            self.connect_timer.stop()
            self.dot_count = 0
        
        self.append_log(message)
        state = self.tab_data[prefix]
        
        if success:
            state["persistent_sock"] = sock
            state["session_key"] = session_key
            state["connected"] = True
            
            if prefix == "main_":
                self.main_connect_button.setText("Desconectar")
                self.main_connect_button.setEnabled(True)
            elif prefix == "client_":
                self.client_btn_client_state.setText("Desconectar")
                self.client_btn_client_state.setEnabled(True)
                self.client_btn_server_control.setText("Desligar Servidor")
            elif prefix == "f3_":
                self.f3_connect_button.setText("Desconectar")
                self.f3_connect_button.setEnabled(True)
                self.f3_unlock_button.setEnabled(True)

            getattr(self, f"{prefix}send_button").setEnabled(True)
            self.set_inputs_enabled(False, prefix)
            
            state["listener_worker"] = ListenerWorker(state["persistent_sock"], state["session_key"])
            state["listener_worker"].received_signal.connect(lambda txt: self.append_received(txt, prefix))
            state["listener_worker"].received_bytes_signal.connect(lambda hex_txt: self.append_received_bytes(hex_txt, prefix))
            state["listener_worker"].error_signal.connect(lambda err: self.on_listener_error(err, prefix))
            state["listener_worker"].start()
            
            if prefix != "f3_":
                QMessageBox.information(self, "Conexão", f"Conexão bem sucedida ({prefix})")
        else:
            state["connected"] = False
            if prefix == "main_":
                self.main_connect_button.setText("Conectar")
                self.main_connect_button.setEnabled(True)
            elif prefix == "client_":
                self.client_btn_server_control.setText("Iniciar Servidor")
                self.client_btn_client_state.setText("Aguardando Conexão")
                self.client_btn_client_state.setEnabled(False)
            elif prefix == "f3_":
                self.f3_connect_button.setText("Conectar")
                self.f3_connect_button.setEnabled(True)

            getattr(self, f"{prefix}send_button").setEnabled(False)
            self.set_inputs_enabled(True, prefix)
            
            if "10013" in message or "10048" in message:
                message = "Soquete em uso por outra aplicação"
            QMessageBox.critical(self, "Erro de Conexão", message)


def main():
    app = QApplication(sys.argv)
    window = EvoRepAuthApp()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
