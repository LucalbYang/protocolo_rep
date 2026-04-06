import sys
import os
import socket
import base64
import traceback
import time

from PyQt6.QtCore import QThread, pyqtSignal, QSettings, QTimer, Qt
from PyQt6.QtWidgets import (QApplication, QGridLayout, QLabel, QLineEdit,
                             QPushButton, QTextEdit, QWidget, QStackedWidget,
                             QGroupBox, QVBoxLayout, QHBoxLayout, QMessageBox)

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
    def extract_rsa_key_from_payload(payload) -> tuple[int, int]:
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

        return n, e

    @staticmethod
    def generate_aes_key() -> bytes:
        return os.urandom(16)

    @staticmethod
    def encrypt_aes(key: bytes, plaintext: str) -> bytes:
        data = plaintext.encode('utf-8')
        iv = os.urandom(16)
        
        pad_len = 16 - (len(data) % 16)
        if pad_len != 16:
            padded_data = data + (b'\x00' * pad_len)
        else:
            padded_data = data
        
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
        if len(ciphertext) < 16 or len(ciphertext) % 16 != 0:
            return ciphertext.decode('utf-8', errors='ignore')
            
        iv = ciphertext[:16]
        actual_ciphertext = ciphertext[16:]
        
        if CRYPTO_BACKEND == "pycryptodome":
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_padded = cipher.decrypt(actual_ciphertext)
            
            try:
                decrypted = unpad(decrypted_padded, AES.block_size)
            except ValueError:
                decrypted = decrypted_padded.rstrip(b'\x00')
                
            return decrypted.decode('utf-8', errors='replace')
        else:
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_padded = decryptor.update(actual_ciphertext) + decryptor.finalize()
            
            try:
                unpadder = sym_padding.PKCS7(128).unpadder()
                decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
            except ValueError:
                decrypted = decrypted_padded.rstrip(b'\x00')
                
            return decrypted.decode('utf-8', errors='replace')

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
    finished_signal = pyqtSignal(bool, str)

    def __init__(self, ip: str, port: int, user: str, password: str, parent=None):
        super().__init__(parent)
        self.ip = ip
        self.port = port
        self.user = user
        self.password = password

    def run(self):
        start_time = time.time()
        timeout_limit = 10.0
        last_error = "Tempo esgotado"

        while (time.time() - start_time) < timeout_limit:
            sock = None
            try:
                self.log_signal.emit(f"Tentando conectar a {self.ip}:{self.port}...")
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((self.ip, self.port))

                self.log_signal.emit("Conexão estabelecida. Iniciando handshake...")
                
                ra_payload = "01+RA+00"
                ra_packet = EvoRepProtocol.pack(ra_payload)
                sock.sendall(ra_packet)

                resp_data = EvoRepProtocol.receive_full(sock)
                payload_ra = EvoRepProtocol.unpack(resp_data).decode('utf-8', errors='ignore')
                self.log_signal.emit(f"Payload RA recebido: {payload_ra}")

                rsa_pubkey = EvoRepCrypto.extract_rsa_key_from_payload(payload_ra)

                session_key = b"1111111111111111"
                session_key_b64 = base64.b64encode(session_key).decode("utf-8")
                credential = f"1]{self.user}]{self.password}]{session_key_b64}"

                encrypted = EvoRepCrypto.encrypt_credentials_with_rsa(rsa_pubkey, credential)
                encrypted_b64 = base64.b64encode(encrypted).decode("utf-8")

                ea_payload = f"01+EA+00+{encrypted_b64}"
                ea_packet = EvoRepProtocol.pack(ea_payload)
                sock.sendall(ea_packet)

                resp_ea = EvoRepProtocol.receive_full(sock)
                payload_ea = EvoRepProtocol.unpack(resp_ea).decode('utf-8', errors='ignore')
                self.log_signal.emit(f"Payload EA recebido: {payload_ea}")

                if payload_ea.startswith("01+EA+000"):
                    self.finished_signal.emit(True, "Autenticação EA realizada com sucesso.")
                    sock.close()
                    return
                elif payload_ea.startswith("01+EA+009"):
                    self.finished_signal.emit(False, "Usuário ou senha inválidos.")
                    sock.close()
                    return
                else:
                    raise Exception(f"Falha na autenticação (EA): {payload_ea}")

            except Exception as e:
                last_error = str(e)
                self.log_signal.emit(f"Falha na tentativa: {e}. Retentando em 500ms...")
                if sock:
                    sock.close()
                time.sleep(0.5)

        self.finished_signal.emit(False, f"Incapaz de conectar: {last_error}")


class CommandWorker(QThread):
    sent_signal = pyqtSignal(str)
    sent_bytes_signal = pyqtSignal(str)
    received_signal = pyqtSignal(str)
    received_bytes_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(bool, str)

    def __init__(self, ip: str, port: int, command: str, session_key: bytes, parent=None):
        super().__init__(parent)
        self.ip = ip
        self.port = port
        self.command = command
        self.session_key = session_key

    def run(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5)
                sock.connect((self.ip, self.port))

                encrypted_command = EvoRepCrypto.encrypt_aes(self.session_key, self.command)
                packet = EvoRepProtocol.pack(encrypted_command)
                
                self.sent_signal.emit(self.command)
                self.sent_bytes_signal.emit(packet.hex(' '))
                
                sock.sendall(packet)

                resp_data = EvoRepProtocol.receive_full(sock)
                resp_payload_encrypted = EvoRepProtocol.unpack(resp_data)
                
                resp_payload = EvoRepCrypto.decrypt_aes(self.session_key, resp_payload_encrypted)
                
                self.received_signal.emit(resp_payload)
                self.received_bytes_signal.emit(resp_data.hex(' '))

                self.finished_signal.emit(True, 'Comando enviado com sucesso.')
        except Exception as e:
            self.finished_signal.emit(False, f'Erro ao enviar comando: {e}')


class EvoRepAuthApp(QWidget):
    def __init__(self):
        super().__init__()
        self._setup_ui()
        self.worker = None
        self.connected = False
        self.show_bytes = False
        self.last_sent_text = ""
        self.last_sent_bytes = ""
        self.last_received_text = ""
        self.last_received_bytes = ""
        self.settings = QSettings("EvoRep", "EvoRepAuthApp")
        
        self.connect_timer = QTimer()
        self.connect_timer.timeout.connect(self.animate_connecting_button)
        self.dot_count = 0
        self.load_config()
        
        self.setCursor(Qt.CursorShape.ArrowCursor)
        QApplication.processEvents()

    def _setup_ui(self):
        self.setWindowTitle("Protocolo EVO REP-C (Pressione F7 para exibir Log)")

        # Utilizamos QStackedWidget no lugar de QTabWidget para ocultar as abas
        self.stacked_widget = QStackedWidget(self)

        # Aba principal (controle / envio de comandos)
        main_tab = QWidget()
        main_layout = QVBoxLayout() # Trocado para QVBox para organizar top e bottom

        # --- ÁREA SUPERIOR: DIVISÃO 1/4 (Login) vs 3/4 (Comandos) ---
        top_layout = QHBoxLayout()

        # Widget de login
        conn_widget = QWidget()
        conn_layout = QGridLayout()
        conn_layout.setContentsMargins(0, 0, 0, 0) # Remove margens extras

        conn_layout.addWidget(QLabel("IP:"), 0, 0)
        self.ip_input = QLineEdit("127.0.0.1")
        self.ip_input.returnPressed.connect(lambda: self.port_input.setFocus())
        conn_layout.addWidget(self.ip_input, 0, 1)

        conn_layout.addWidget(QLabel("Porta:"), 1, 0)
        self.port_input = QLineEdit("5010")
        self.port_input.returnPressed.connect(lambda: self.user_input.setFocus())
        conn_layout.addWidget(self.port_input, 1, 1)

        conn_layout.addWidget(QLabel("Usuário:"), 2, 0)
        self.user_input = QLineEdit("teste fabrica")
        self.user_input.returnPressed.connect(lambda: self.password_input.setFocus())
        conn_layout.addWidget(self.user_input, 2, 1)

        conn_layout.addWidget(QLabel("Senha:"), 3, 0)
        self.password_input = QLineEdit("111111")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setMaxLength(6)
        self.password_input.textChanged.connect(self.validate_password_input)
        self.password_input.returnPressed.connect(self.on_password_enter_pressed)
        conn_layout.addWidget(self.password_input, 3, 1)

        self.password_error_label = QLabel("")
        self.password_error_label.setStyleSheet("color: red; font-size: 10px;")
        conn_layout.addWidget(self.password_error_label, 4, 1, 1, 1, Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)

        self.connect_button = QPushButton("Conectar")
        self.connect_button.clicked.connect(self.on_connect_clicked)
        conn_layout.addWidget(self.connect_button, 5, 0, 1, 2)

        # Empurra os inputs para o topo caso a caixa de comandos ao lado cresça
        conn_layout.setRowStretch(6, 1) 
        conn_widget.setLayout(conn_layout)

        # Box de Comandos vazia (por enquanto)
        cmds_group = QGroupBox("Comandos")

        # Adiciona no topo com stretch 1 (1/4) e 3 (3/4)
        top_layout.addWidget(conn_widget, 1)
        top_layout.addWidget(cmds_group, 3)

        main_layout.addLayout(top_layout)

        # --- ÁREA INFERIOR: CONTROLE ANTIGO DE COMANDO ---
        mid_layout = QGridLayout()
        mid_layout.addWidget(QLabel("Enviar string (comando):"), 0, 0, 1, 2)
        self.command_input = QLineEdit("01+RH+00")
        mid_layout.addWidget(self.command_input, 1, 0, 1, 2)

        self.send_button = QPushButton("Enviar comando")
        self.send_button.clicked.connect(self.on_send_command_clicked)
        self.send_button.setEnabled(False)
        mid_layout.addWidget(self.send_button, 2, 0, 1, 2)

        sent_layout = QVBoxLayout()
        sent_layout.addWidget(QLabel("String enviada:"))
        self.sent_output = QTextEdit()
        self.sent_output.setReadOnly(True)
        sent_layout.addWidget(self.sent_output)

        received_layout = QVBoxLayout()
        received_layout.addWidget(QLabel("String recebida:"))
        self.received_output = QTextEdit()
        self.received_output.setReadOnly(True)
        received_layout.addWidget(self.received_output)

        boxes_layout = QHBoxLayout()
        boxes_layout.addLayout(sent_layout)
        boxes_layout.addLayout(received_layout)

        mid_layout.addLayout(boxes_layout, 3, 0, 1, 2)

        control_layout = QHBoxLayout()
        self.clear_button = QPushButton("Limpar")
        self.clear_button.clicked.connect(self.on_clear_clicked)
        control_layout.addWidget(self.clear_button)

        self.toggle_mode_button = QPushButton("Exibir em bytes")
        self.toggle_mode_button.clicked.connect(self.on_toggle_display_mode)
        control_layout.addWidget(self.toggle_mode_button)

        mid_layout.addLayout(control_layout, 4, 0, 1, 2)
        main_layout.addLayout(mid_layout)

        main_tab.setLayout(main_layout)

        # Aba de log (agora oculta no QStackedWidget)
        log_tab = QWidget()
        log_layout = QVBoxLayout()
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        log_layout.addWidget(self.log_output)
        log_tab.setLayout(log_layout)

        self.stacked_widget.addWidget(main_tab)
        self.stacked_widget.addWidget(log_tab)

        root_layout = QVBoxLayout()
        root_layout.addWidget(self.stacked_widget)
        self.setLayout(root_layout)

        self.resize(720, 540)

    # Novo evento para captar a tecla F7 e alternar as telas
    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_F7:
            current_idx = self.stacked_widget.currentIndex()
            next_idx = (current_idx + 1) % self.stacked_widget.count()
            self.stacked_widget.setCurrentIndex(next_idx)
        else:
            super().keyPressEvent(event)

    def on_password_enter_pressed(self):
        if self.connect_button.isEnabled():
            self.on_connect_clicked()

    def validate_password_input(self):
        password = self.password_input.text()
        
        if not self.connected:
            if not password:
                self.password_error_label.setText("")
                self.connect_button.setEnabled(False)
                return

            if not password.isdigit():
                self.password_error_label.setText("A senha deve ter apenas números")
            elif len(password) < 6:
                self.password_error_label.setText("A senha deve possuir 6 números")
            else:
                self.password_error_label.setText("")

            is_valid = len(password) == 6 and password.isdigit()
            self.connect_button.setEnabled(is_valid)
        else:
            self.password_error_label.setText("")

    def set_inputs_enabled(self, enabled: bool):
        self.ip_input.setEnabled(enabled)
        self.port_input.setEnabled(enabled)
        self.user_input.setEnabled(enabled)
        self.password_input.setEnabled(enabled)

    def load_config(self):
        self.ip_input.setText(self.settings.value('ip', '192.168.60.83'))
        self.port_input.setText(str(self.settings.value('port', 3000)))
        self.user_input.setText(self.settings.value('user', 'teste fabrica'))
        self.password_input.setText(self.settings.value('password', '111111'))
        self.validate_password_input()

    def save_config(self):
        self.settings.setValue('ip', self.ip_input.text())
        self.settings.setValue('port', self.port_input.text())
        self.settings.setValue('user', self.user_input.text())
        self.settings.setValue('password', self.password_input.text())
        self.settings.sync() 

    def append_log(self, message: str):
        self.log_output.append(message)

    def update_sent_received_output(self):
        if self.show_bytes:
            self.sent_output.setPlainText(self.last_sent_bytes)
            self.received_output.setPlainText(self.last_received_bytes)
        else:
            self.sent_output.setPlainText(self.last_sent_text)
            self.received_output.setPlainText(self.last_received_text)

    def append_sent(self, text: str):
        self.last_sent_text = text
        self.update_sent_received_output()

    def append_sent_bytes(self, hex_text: str):
        self.last_sent_bytes = hex_text
        self.update_sent_received_output()
    
    def append_received(self, text: str):
        self.last_received_text = text
        self.update_sent_received_output()

    def append_received_bytes(self, hex_text: str):
        self.last_received_bytes = hex_text
        self.update_sent_received_output()

    def on_toggle_display_mode(self):
        self.show_bytes = not self.show_bytes
        self.toggle_mode_button.setText("Exibir em string" if self.show_bytes else "Exibir em bytes")
        self.update_sent_received_output()

    def animate_connecting_button(self):
        self.dot_count = (self.dot_count + 1) % 4
        dots = "." * self.dot_count
        self.connect_button.setText(f"Conectando{dots}")

    def on_send_command_clicked(self):
        ip = self.ip_input.text().strip()
        port_text = self.port_input.text().strip()
        command = self.command_input.text().strip()

        if not ip or not port_text or not command:
            self.append_log("Preencha IP, Porta e o comando antes de enviar.")
            return

        try:
            port = int(port_text)
        except ValueError:
            self.append_log("Porta inválida; insira um número inteiro.")
            return

        self.send_button.setEnabled(False)
        
        session_key = b"1111111111111111" 
        
        self.command_worker = CommandWorker(ip, port, command, session_key)
        self.command_worker.sent_signal.connect(self.append_sent)
        self.command_worker.sent_bytes_signal.connect(self.append_sent_bytes)
        self.command_worker.received_signal.connect(self.append_received)
        self.command_worker.received_bytes_signal.connect(self.append_received_bytes)
        self.command_worker.finished_signal.connect(self.on_send_command_finished)
        self.command_worker.start()

    def on_send_command_finished(self, success: bool, message: str):
        self.append_log(message)
        self.send_button.setEnabled(True)

    def on_clear_clicked(self):
        self.last_sent_text = ""
        self.last_sent_bytes = ""
        self.last_received_text = ""
        self.last_received_bytes = ""
        self.update_sent_received_output()
        self.append_log("Campos limpos.")

    def on_connect_clicked(self):
        self.append_log(f"Botão Conectar clicado (connected={self.connected})")
        if self.connected:
            self.disconnect()
            return

        ip = self.ip_input.text().strip()
        port_text = self.port_input.text().strip()
        user = self.user_input.text().strip()
        password = self.password_input.text().strip()

        if not ip or not port_text or not user or not password:
            self.append_log("Preencha todos os campos antes de conectar.")
            return

        try:
            port = int(port_text)
        except ValueError:
            self.append_log("Porta inválida; insira um número inteiro.")
            return

        self.save_config()

        self.connect_button.setEnabled(False)
        self.connect_button.setText("Conectando")
        self.dot_count = 0
        self.connect_timer.start(350) 

        self.log_output.clear()

        self.worker = NetworkWorker(ip, port, user, password)
        self.worker.log_signal.connect(self.append_log)
        self.worker.finished_signal.connect(self.on_finished)
        self.worker.start()

    def disconnect(self):
        self.connected = False
        self.connect_button.setText("Conectar")
        self.connect_button.setEnabled(True)
        self.send_button.setEnabled(False)
        self.set_inputs_enabled(True)
        self.append_log("Desconectado.")

    def on_finished(self, success: bool, message: str):
        self.connect_timer.stop()
        self.dot_count = 0
        self.append_log(message)
        if success:
            self.connected = True
            self.connect_button.setText("Desconectar")
            self.send_button.setEnabled(True)
            self.set_inputs_enabled(False)
            self.append_log("Fluxo de autenticação concluído com êxito.")
            QMessageBox.information(self, "Conexão", "Conexão bem sucedida")
        else:
            self.connected = False
            self.connect_button.setText("Conectar")
            self.send_button.setEnabled(False)
            self.set_inputs_enabled(True)
            self.append_log("Fluxo de autenticação finalizado com erro.")
            QMessageBox.critical(self, "Erro de Conexão", message)
        self.connect_button.setEnabled(True)


def main():
    app = QApplication(sys.argv)
    window = EvoRepAuthApp()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
    