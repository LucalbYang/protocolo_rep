# workers.py
import socket
import time
import base64
from PyQt6.QtCore import QThread, pyqtSignal
from evo_protocol import EvoRepProtocol
from evo_crypto import EvoRepCrypto

class NetworkWorker(QThread):
    log_signal      = pyqtSignal(str)
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

                for _ in range(7):
                    if not self.running: break
                    time.sleep(0.05)

        if not self.running:
            self.finished_signal.emit(False, "Operação cancelada pelo usuário.", None, b"")
        else:
            self.finished_signal.emit(False, f"Incapaz de conectar: {last_error}", None, b"")


class ClientNetworkWorker(QThread):
    log_signal      = pyqtSignal(str)
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
            
            while self.running:
                self.log_signal.emit("Aguardando conexão do equipamento...")
                self.server_sock.settimeout(2.0)
                try:
                    sock, addr = self.server_sock.accept()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        self.log_signal.emit(f"Erro no accept: {e}")
                    break

                try:
                    self.log_signal.emit(f"Conexão recebida de {addr}. Iniciando handshake...")

                    ra_payload = "01+RA+00"
                    ra_packet = EvoRepProtocol.pack(ra_payload)
                    sock.sendall(ra_packet)

                    resp_data = EvoRepProtocol.receive_full(sock)
                    payload_ra = EvoRepProtocol.unpack(resp_data).decode('utf-8', errors='ignore')
                    self.log_signal.emit(f"Payload RA recebido: {payload_ra}")

                    rsa_pubkey_data = EvoRepCrypto.extract_rsa_key_from_payload(payload_ra)
                    n, e, mod_b64 = rsa_pubkey_data

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
                        # Se sucesso, fechamos o server_sock (aceitamos apenas 1 por vez com persistência)
                        if self.server_sock:
                            self.server_sock.close()
                            self.server_sock = None
                        self.finished_signal.emit(True, "Autenticação EA realizada com sucesso.", sock, session_key)
                        return
                    elif payload_ea.startswith("01+EA+009"):
                        self.log_signal.emit("Erro: Usuário ou senha inválidos no equipamento.")
                        sock.close()
                    else:
                        self.log_signal.emit(f"Falha na autenticação (EA): {payload_ea}")
                        sock.close()

                except Exception as e:
                    self.log_signal.emit(f"Erro no handshake (RA/EA): {e}. Retentando aguardar nova conexão...")
                    try: sock.close()
                    except: pass
                    continue

        except Exception as e:
            if self.running:
                self.log_signal.emit(f"Erro fatal no servidor: {e}")
                self.finished_signal.emit(False, str(e), None, b"")
        finally:
            if self.server_sock:
                try: self.server_sock.close()
                except: pass


class F3NetworkWorker(QThread):
    log_signal      = pyqtSignal(str)
    finished_signal = pyqtSignal(bool, str, object, bytes)
    auto_sent_signal = pyqtSignal(str, bytes)

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
    sent_signal       = pyqtSignal(str)
    sent_bytes_signal = pyqtSignal(str)
    finished_signal   = pyqtSignal(bool, str)

    def __init__(self, sock: socket.socket, command: str, session_key: bytes, parent=None):
        super().__init__(parent)
        self.sock = sock
        self.command = command
        self.session_key = session_key

    def run(self):
        try:
            if self.session_key:
                encrypted_command = EvoRepCrypto.encrypt_aes(self.session_key, self.command)
                packet = EvoRepProtocol.pack(encrypted_command)
            else:
                packet = EvoRepProtocol.pack(self.command)

            self.sent_signal.emit(self.command)
            self.sent_bytes_signal.emit(packet.hex(' '))

            self.sock.sendall(packet)
            self.finished_signal.emit(True, 'Comando enviado. Aguardando resposta em tempo real...')
        except Exception as e:
            self.finished_signal.emit(False, f'Erro ao enviar comando: {e}')


class ListenerWorker(QThread):
    received_signal       = pyqtSignal(str)
    received_bytes_signal = pyqtSignal(str)
    error_signal          = pyqtSignal(str)

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
                data = EvoRepProtocol.receive_full(self.sock, timeout=2.0)
                if not data:
                    continue

                payload_raw = EvoRepProtocol.unpack(data)

                if self.session_key:
                    payload = EvoRepCrypto.decrypt_aes(self.session_key, payload_raw)
                else:
                    payload = payload_raw.decode('utf-8', errors='ignore')

                self.received_signal.emit(payload)
                self.received_bytes_signal.emit(data.hex(' '))
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    self.error_signal.emit(str(e))
                break
