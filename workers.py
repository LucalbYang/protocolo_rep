# workers.py
import socket
import time
import base64
from PyQt6.QtCore import QThread, pyqtSignal
from evo_protocol import EvoRepProtocol
from evo_crypto import EvoRepCrypto

class NetworkWorker(QThread):
    log_signal      = pyqtSignal(str)
    finished_signal = pyqtSignal(bool, str, object, bytes, object)
    sent_signal = pyqtSignal(str)
    sent_bytes_signal = pyqtSignal(str)
    received_signal = pyqtSignal(str)
    received_bytes_signal = pyqtSignal(str)

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
        rsa_key_data = None

        while self.running and (time.time() - start_time) < timeout_limit:
            sock = None
            try:
                self.log_signal.emit(f"Tentando conectar a {self.ip}:{self.port}...")
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.settimeout(1) # Reduzido para 1s para ser mais responsivo no handshake
                sock.connect((self.ip, self.port))

                self.log_signal.emit("Conexão estabelecida. Iniciando handshake...")

                # 🔹 Loop de retentativas para o comando RA dentro do mesmo socket
                payload_ra = ""
                for attempt in range(3):
                    # Verifica timeout global dentro do loop de RA
                    if not self.running or (time.time() - start_time) > timeout_limit: break
                    
                    try:
                        ra_payload = "01+RA+00"
                        ra_packet = EvoRepProtocol.pack(ra_payload)
                        self.sent_signal.emit(ra_payload)
                        self.sent_bytes_signal.emit(ra_packet.hex(' '))
                        sock.sendall(ra_packet)

                        # Usamos o timeout do socket (1s)
                        resp_data = EvoRepProtocol.receive_full(sock)
                        payload_ra = EvoRepProtocol.unpack(resp_data).decode('utf-8', errors='ignore')
                        self.received_signal.emit(payload_ra)
                        self.received_bytes_signal.emit(resp_data.hex(' '))

                        if payload_ra.startswith("01+RA+"):
                            break # Sucesso
                        else:
                            self.log_signal.emit(f"RA: Resposta inesperada '{payload_ra}'. Retentando RA ({attempt+1}/3)...")
                    except Exception as e:
                        self.log_signal.emit(f"RA: Erro na tentativa {attempt+1}/3: {e}")
                    
                    if attempt < 2: time.sleep(0.2)

                if not payload_ra.startswith("01+RA+"):
                    if payload_ra.strip() == "":
                        raise Exception("Equipamento já em conexão com outro comunicador.")
                    else:
                        raise Exception("Falha ao obter RA válido após 3 tentativas.")

                self.log_signal.emit(f"Payload RA recebido: {payload_ra}")

                if payload_ra.startswith("01+RA+047"):
                    self.finished_signal.emit(False, "Equipamento bloqueado (Erro 047)", None, b"", None)
                    sock.close()
                    return

                rsa_pubkey_data = EvoRepCrypto.extract_rsa_key_from_payload(payload_ra)
                n, e, mod_b64 = rsa_pubkey_data
                rsa_key_data = (n, e)

                session_key = EvoRepCrypto.generate_aes_key()

                session_key_b64 = base64.b64encode(session_key).decode("utf-8")
                credential = f"1]{self.user}]{self.password}]{session_key_b64}"

                encrypted = EvoRepCrypto.encrypt_credentials_with_rsa((n, e), credential)
                encrypted_b64 = base64.b64encode(encrypted).decode("utf-8")

                ea_payload = f"01+EA+00+{encrypted_b64}"
                ea_packet = EvoRepProtocol.pack(ea_payload)
                self.sent_signal.emit(ea_payload)
                self.sent_bytes_signal.emit(ea_packet.hex(' '))
                sock.sendall(ea_packet)

                resp_ea = EvoRepProtocol.receive_full(sock)
                payload_ea = EvoRepProtocol.unpack(resp_ea).decode('utf-8', errors='ignore')
                self.received_signal.emit(payload_ea)
                self.received_bytes_signal.emit(resp_ea.hex(' '))
                self.log_signal.emit(f"Payload EA recebido: {payload_ea}")

                if payload_ea.startswith("01+EA+000"):
                    self.finished_signal.emit(True, "Autenticação EA realizada com sucesso.", sock, session_key, rsa_key_data)
                    return
                elif payload_ea.startswith("01+EA+009"):
                    self.finished_signal.emit(False, "Usuário ou senha inválidos. (Erro 009)", None, b"", None)
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
            self.finished_signal.emit(False, "Operação cancelada pelo usuário.", None, b"", None)
        else:
            msg = f"Incapaz de conectar: {last_error}"
            if "timed out" in last_error.lower():
                msg = "Incapaz de conectar: IP não disponível para conexão. Verifique se o campo foi digitado corretamente e se o equipamento está devidamente conectado. O equipamento também pode estar sendo usado por outro comunicador. Se o erro persistir reinicie o REP."
            self.finished_signal.emit(False, msg, None, b"", None)


class ClientNetworkWorker(QThread):
    log_signal      = pyqtSignal(str)
    finished_signal = pyqtSignal(bool, str, object, bytes, object)
    sent_signal = pyqtSignal(str)
    sent_bytes_signal = pyqtSignal(str)
    received_signal = pyqtSignal(str)
    received_bytes_signal = pyqtSignal(str)

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

                    # 🔹 NOVO: Loop de retentativas para o comando RA dentro do mesmo socket
                    payload_ra = ""
                    for attempt in range(3):
                        if not self.running: break
                        try:
                            ra_payload = "01+RA+00"
                            ra_packet = EvoRepProtocol.pack(ra_payload)
                            self.sent_signal.emit(ra_payload)
                            self.sent_bytes_signal.emit(ra_packet.hex(' '))
                            sock.sendall(ra_packet)

                            resp_data = EvoRepProtocol.receive_full(sock)
                            payload_ra = EvoRepProtocol.unpack(resp_data).decode('utf-8', errors='ignore')
                            self.received_signal.emit(payload_ra)
                            self.received_bytes_signal.emit(resp_data.hex(' '))

                            if payload_ra.startswith("01+RA+"):
                                break # Sucesso
                            else:
                                self.log_signal.emit(f"RA: Resposta inesperada '{payload_ra}'. Retentando RA ({attempt+1}/3)...")
                        except Exception as e:
                            self.log_signal.emit(f"RA: Erro na tentativa {attempt+1}/3: {e}")
                        
                        if attempt < 2: time.sleep(0.2)

                    if not payload_ra.startswith("01+RA+"):
                        raise Exception("Falha ao obter RA válido após 3 tentativas.")

                    self.log_signal.emit(f"Payload RA recebido: {payload_ra}")

                    if payload_ra.startswith("01+RA+047"):
                        self.log_signal.emit("Equipamento bloqueado (Erro 047). Desligando servidor...")
                        if self.server_sock:
                            self.server_sock.close()
                            self.server_sock = None
                        self.finished_signal.emit(False, "Equipamento bloqueado (Erro 047)", None, b"", None)
                        sock.close()
                        return

                    rsa_pubkey_data = EvoRepCrypto.extract_rsa_key_from_payload(payload_ra)
                    n, e, mod_b64 = rsa_pubkey_data

                    session_key = EvoRepCrypto.generate_aes_key()

                    session_key_b64 = base64.b64encode(session_key).decode("utf-8")
                    credential = f"1]{self.user}]{self.password}]{session_key_b64}"

                    encrypted = EvoRepCrypto.encrypt_credentials_with_rsa((n, e), credential)
                    encrypted_b64 = base64.b64encode(encrypted).decode("utf-8")

                    ea_payload = f"01+EA+00+{encrypted_b64}"
                    ea_packet = EvoRepProtocol.pack(ea_payload)
                    self.sent_signal.emit(ea_payload)
                    self.sent_bytes_signal.emit(ea_packet.hex(' '))
                    sock.sendall(ea_packet)

                    resp_ea = EvoRepProtocol.receive_full(sock)
                    payload_ea = EvoRepProtocol.unpack(resp_ea).decode('utf-8', errors='ignore')
                    self.received_signal.emit(payload_ea)
                    self.received_bytes_signal.emit(resp_ea.hex(' '))
                    self.log_signal.emit(f"Payload EA recebido: {payload_ea}")

                    if payload_ea.startswith("01+EA+000"):
                        # Se sucesso, fechamos o server_sock (aceitamos apenas 1 por vez com persistência)
                        if self.server_sock:
                            self.server_sock.close()
                            self.server_sock = None
                        self.finished_signal.emit(True, "Autenticação EA realizada com sucesso.", sock, session_key, (n, e))
                        return
                    elif payload_ea.startswith("01+EA+009"):
                        self.finished_signal.emit(False, "Usuário ou senha inválidos. (Erro 009)", None, b"", None)
                        sock.close()
                        return
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
                self.finished_signal.emit(False, str(e), None, b"", None)
        finally:
            if self.server_sock:
                try: self.server_sock.close()
                except: pass


class F3NetworkWorker(QThread):
    log_signal      = pyqtSignal(str)
    finished_signal = pyqtSignal(bool, str, object, bytes, object)
    auto_sent_signal = pyqtSignal(str, bytes)
    received_signal = pyqtSignal(str)
    received_bytes_signal = pyqtSignal(str)

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

            # 🔹 REQUISITO: Aguardar resposta do RB por até 1s
            try:
                resp_data = EvoRepProtocol.receive_full(sock, timeout=1.0)
                if not resp_data:
                    raise Exception("Equipamento indisponível para conexão")
                
                payload_rb = EvoRepProtocol.unpack(resp_data).decode('utf-8', errors='ignore')
                self.received_signal.emit(payload_rb)
                self.received_bytes_signal.emit(resp_data.hex(' '))
                
                self.finished_signal.emit(True, "Conexão F3 estabelecida com sucesso.", sock, b"", None)
            except Exception:
                if sock:
                    try: sock.close()
                    except: pass
                self.finished_signal.emit(False, "Equipamento indisponível para conexão", None, b"", None)

        except Exception as e:
            if self.running:
                self.log_signal.emit(f"F3: Falha na conexão: {e}")
                err_str = str(e)
                if "timed out" in err_str.lower():
                    msg = "Incapaz de conectar: IP não disponível para conexão. Verifique se o campo foi digitado corretamente e se o equipamento está devidamente conectado. O equipamento também pode estar sendo usado por outro comunicador. Se o erro persistir reinicie o REP."
                else:
                    msg = f"Incapaz de conectar: {err_str}"
                self.finished_signal.emit(False, msg, None, b"", None)
            if sock:
                try: sock.close()
                except: pass


class CommandWorker(QThread):
    sent_signal       = pyqtSignal(str)
    sent_bytes_signal = pyqtSignal(str)
    finished_signal   = pyqtSignal(bool, str)

    def __init__(self, sock: socket.socket, command, session_key: bytes, parent=None):
        super().__init__(parent)
        self.sock = sock
        self.commands = command if isinstance(command, list) else [command]
        self.session_key = session_key

    def run(self):
        try:
            for cmd in self.commands:
                if self.session_key:
                    encrypted_command = EvoRepCrypto.encrypt_aes(self.session_key, cmd)
                    packet = EvoRepProtocol.pack(encrypted_command)
                else:
                    packet = EvoRepProtocol.pack(cmd)

                self.sent_signal.emit(cmd)
                self.sent_bytes_signal.emit(packet.hex(' '))

                self.sock.sendall(packet)
                time.sleep(0.1)  # small delay for sequential commands

            self.finished_signal.emit(True, 'Comando enviado. Aguardando resposta em tempo real...')
        except Exception as e:
            self.finished_signal.emit(False, f'Erro ao enviar comando: {e}')


class DeauthWorker(QThread):
    """
    Worker para realizar o Deauth antes da desconexão.
    Envia 01+EA+00+<rsa_blob> onde a credencial começa com '0]'.
    """
    sent_signal           = pyqtSignal(str)
    sent_bytes_signal     = pyqtSignal(str)
    finished_signal       = pyqtSignal()

    def __init__(self, sock: socket.socket, rsa_key: tuple, user: str, password: str, session_key: bytes, parent=None):
        super().__init__(parent)
        self.sock = sock
        self.rsa_key = rsa_key
        self.user = user
        self.password = password
        self.session_key = session_key

    def run(self):
        try:
            if not self.sock or not self.rsa_key:
                return

            session_key_b64 = base64.b64encode(self.session_key).decode("utf-8")
            # 🔹 REQUISITO: Prefixar com '0]' para finalizar comunicação criptografada
            credential = f"0]{self.user}]{self.password}]{session_key_b64}"

            encrypted = EvoRepCrypto.encrypt_credentials_with_rsa(self.rsa_key, credential)
            encrypted_b64 = base64.b64encode(encrypted).decode("utf-8")

            ea_payload = f"01+EA+00+{encrypted_b64}"
            ea_packet = EvoRepProtocol.pack(ea_payload)

            self.sent_signal.emit(ea_payload)
            self.sent_bytes_signal.emit(ea_packet.hex(' '))

            self.sock.settimeout(0.5)
            self.sock.sendall(ea_packet)
            
            # 🔹 REQUISITO: Ignora resposta e finaliza imediatamente
        except:
            pass
        finally:
            self.finished_signal.emit()


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
