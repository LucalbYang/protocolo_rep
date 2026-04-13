import sys
import os
import socket
import base64
import traceback
import time
from comandos import COMMANDS_REGISTRY

from PyQt6.QtCore import QThread, pyqtSignal, QSettings, QTimer, Qt
from PyQt6.QtWidgets import (QApplication, QGridLayout, QLabel, QLineEdit,
                             QPushButton, QTextEdit, QWidget, QStackedWidget,
                             QGroupBox, QVBoxLayout, QHBoxLayout, QMessageBox,
                             QComboBox, QFormLayout)

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
                self.log_signal.emit(f"Falha na tentativa: {e}. Retentando em 350ms...")
                if sock:
                    sock.close()
                time.sleep(0.35)

        self.finished_signal.emit(False, f"Incapaz de conectar: {last_error}", None, b"")


class CommandWorker(QThread):
    sent_signal = pyqtSignal(str)
    sent_bytes_signal = pyqtSignal(str)
    received_signal = pyqtSignal(str)
    received_bytes_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(bool, str)

    def __init__(self, sock: socket.socket, command: str, session_key: bytes, parent=None):
        super().__init__(parent)
        self.sock = sock
        self.command = command
        self.session_key = session_key

    def run(self):
        try:
            # Usar o socket persistente já conectado
            self.sock.settimeout(5)

            encrypted_command = EvoRepCrypto.encrypt_aes(self.session_key, self.command)
            packet = EvoRepProtocol.pack(encrypted_command)
            
            self.sent_signal.emit(self.command)
            self.sent_bytes_signal.emit(packet.hex(' '))
            
            self.sock.sendall(packet)

            resp_data = EvoRepProtocol.receive_full(self.sock)
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
        self.persistent_sock = None
        self.session_key = None
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
        
        # Aciona manualmente o evento pela primeira vez para exibir o painel custom/manual
        self.on_command_selected(0)

    def _setup_ui(self):
        self.setWindowTitle("Protocolo EVO REP-A/C")
        self.stacked_widget = QStackedWidget(self)

        main_tab = QWidget()
        main_layout = QVBoxLayout()

        # --- ÁREA SUPERIOR: DIVISÃO (Login) vs (Vazio/Expansão) ---
        top_layout = QHBoxLayout()
        conn_widget = QWidget()
        conn_layout = QGridLayout()
        conn_layout.setContentsMargins(0, 0, 0, 0)

        conn_layout.addWidget(QLabel(""), 0, 0, 1, 2) # Spacer topo
        conn_layout.addWidget(QLabel("IP:"), 1, 0)
        self.ip_input = QLineEdit("192.168.60.71")
        conn_layout.addWidget(self.ip_input, 1, 1)

        conn_layout.addWidget(QLabel("Porta:"), 2, 0)
        self.port_input = QLineEdit("3000")
        conn_layout.addWidget(self.port_input, 2, 1)

        conn_layout.addWidget(QLabel("Usuário:"), 3, 0)
        self.user_input = QLineEdit("teste fabrica")
        conn_layout.addWidget(self.user_input, 3, 1)

        conn_layout.addWidget(QLabel("Senha:"), 4, 0)
        self.password_input = QLineEdit("111111")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setMaxLength(6)
        self.password_input.textChanged.connect(self.validate_password_input)
        self.password_input.returnPressed.connect(self.on_password_enter_pressed)
        conn_layout.addWidget(self.password_input, 4, 1)

        self.connect_button = QPushButton("Conectar")
        self.connect_button.clicked.connect(self.on_connect_clicked)
        conn_layout.addWidget(self.connect_button, 5, 0, 1, 2)
        conn_layout.setRowStretch(6, 1) 
        conn_widget.setLayout(conn_layout)

        # Em vez de um grupo vazio para comandos ao lado da conexão, 
        # movemos o construtor dinâmico para ficar centralizado e limpo.
        cmds_group = QGroupBox("Construção de Comandos")
        cmds_group_layout = QVBoxLayout(cmds_group)

        # ComboBox para seleção de comandos
        combo_layout = QHBoxLayout()
        combo_layout.addWidget(QLabel("Selecionar:"))
        self.command_combo = QComboBox()
        self.command_combo.addItem("✏️ Modo Manual / Custom", None) # Data = None indica manual
        
        # Popula a ComboBox baseada no catálogo
        for code, cmd_def in COMMANDS_REGISTRY.items():
            resumo = cmd_def.description.split(':')[0] if ':' in cmd_def.description else cmd_def.description.split('.')[0]
            self.command_combo.addItem(f"{code} - {resumo}", code)
            
        self.command_combo.currentIndexChanged.connect(self.on_command_selected)
        combo_layout.addWidget(self.command_combo)
        cmds_group_layout.addLayout(combo_layout)

        # Descrição do comando
        self.cmd_description_label = QLabel("")
        self.cmd_description_label.setWordWrap(True)
        self.cmd_description_label.setStyleSheet("color: #666; font-style: italic;")
        cmds_group_layout.addWidget(self.cmd_description_label)

        # Painel onde os inputs serão gerados dinamicamente
        self.dynamic_params_widget = QWidget()
        self.dynamic_layout = QFormLayout(self.dynamic_params_widget)
        cmds_group_layout.addWidget(self.dynamic_params_widget)
        
        self.param_inputs = {}  # Guarda referências dos QLineEdit gerados

        self.send_button = QPushButton("Enviar comando")
        self.send_button.clicked.connect(self.on_send_command_clicked)
        self.send_button.setEnabled(False)
        cmds_group_layout.addWidget(self.send_button)

        top_layout.addWidget(conn_widget, 1)
        top_layout.addWidget(cmds_group, 3)
        main_layout.addLayout(top_layout)

        # --- ÁREA INFERIOR: LOG DE COMUNICAÇÃO ---
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
        main_layout.addLayout(boxes_layout)

        control_layout = QHBoxLayout()
        self.clear_button = QPushButton("Limpar")
        self.clear_button.clicked.connect(self.on_clear_clicked)
        control_layout.addWidget(self.clear_button)

        self.toggle_mode_button = QPushButton("Exibir em bytes")
        self.toggle_mode_button.clicked.connect(self.on_toggle_display_mode)
        control_layout.addWidget(self.toggle_mode_button)

        main_layout.addLayout(control_layout)
        main_tab.setLayout(main_layout)

        # Aba de log (oculta no QStackedWidget)
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
        
        self.setMinimumSize(850, 600)
        self.resize(850, 600)

    # -------------------------------------------------------------
    # NOVOS MÉTODOS DINÂMICOS
    # -------------------------------------------------------------
    def on_command_selected(self, index):
        """Limpa o layout atual e gera os campos de input baseados no comando selecionado."""
        # Limpar layout anterior
        while self.dynamic_layout.rowCount() > 0:
            self.dynamic_layout.removeRow(0)
        self.param_inputs.clear()

        # Recuperar o código do comando selecionado
        cmd_code = self.command_combo.currentData()

        if cmd_code is None:
            # Modo manual ativo
            self.cmd_description_label.setText("Modo Manual: Digite a string bruta do comando para enviá-la sem validação.")
            self.manual_input = QLineEdit("01+RH+00")
            self.dynamic_layout.addRow("Comando Bruto:", self.manual_input)
            self.param_inputs["_manual"] = self.manual_input
        else:
            # Comando cadastrado ativo
            cmd_def = COMMANDS_REGISTRY[cmd_code]
            self.cmd_description_label.setText(cmd_def.description)
            
            # Variáveis para agrupar Data e Hora na mesma linha
            pending_data_field = None
            pending_data_label = None
            
            # Gerar formulário dinâmico baseado nos params
            for param in cmd_def.params:
                label_text = f"{param.name} {'' if param.required else '(opcional)'}:"

                if param.choices:
                    # Gerar ComboBox para parâmetros com opções fixas
                    input_field = QComboBox()
                    for choice in param.choices:
                        input_field.addItem(choice['label'], choice['value'])
                else:
                    # Gerar LineEdit normal
                    input_field = QLineEdit(str(param.default))
                    input_field.setPlaceholderText(param.description)

                    # Aplicar máscaras para data e hora se identificadas pelo nome/descrição
                    if param.name.lower() == "data" or "dd/mm/aa" in param.description.lower():
                        input_field.setInputMask("99/99/99;_")
                        input_field.setText(time.strftime("%d/%m/%y"))
                    elif param.name.lower() == "hora" or "hh:mm:ss" in param.description.lower():
                        input_field.setInputMask("99:99:99;_")
                        input_field.setText(time.strftime("%H:%M:%S"))

                # LÓGICA DE AGRUPAMENTO DE DATA E HORA
                if param.name.lower() == "data" or "dd/mm/aa" in param.description.lower():
                    # Guarda a data em vez de adicionar na tela imediatamente
                    pending_data_field = input_field
                    pending_data_label = label_text
                    self.param_inputs[param.name] = input_field
                    continue # Pula para o próximo parâmetro
                
                elif (param.name.lower() == "hora" or "hh:mm:ss" in param.description.lower()) and pending_data_field is not None:
                    # Cria um container horizontal para colocar Data e Hora juntos
                    hbox = QHBoxLayout()
                    hbox.setContentsMargins(0, 0, 0, 0)
                    
                    # Adiciona o campo de Data que estava aguardando
                    hbox.addWidget(pending_data_field)
                    
                    # Adiciona o Label e o campo da Hora ao lado
                    label_hora = QLabel(label_text)
                    hbox.addWidget(label_hora)
                    hbox.addWidget(input_field)
                    
                    # Adiciona tudo no formulário em uma única linha
                    self.dynamic_layout.addRow(pending_data_label, hbox)
                    
                    self.param_inputs[param.name] = input_field
                    pending_data_field = None # Limpa a variável
                    continue

                # Adiciona os outros campos normalmente
                self.dynamic_layout.addRow(label_text, input_field)
                self.param_inputs[param.name] = input_field

            # Caso haja um campo de Data sozinho (sem Hora depois), adiciona ele normalmente
            if pending_data_field is not None:
                self.dynamic_layout.addRow(pending_data_label, pending_data_field)
                
    def on_send_command_clicked(self):
        if not self.persistent_sock:
            self.append_log("Erro: Socket não disponível. Conecte primeiro.")
            return

        cmd_code = self.command_combo.currentData()
        
        # 1. Recuperar string final baseado no modo (Manual vs Catalogado)
        if cmd_code is None:
            command_str = self.param_inputs["_manual"].text().strip()
            if not command_str:
                self.append_log("Preencha o comando manual antes de enviar.")
                return
        else:
            cmd_def = COMMANDS_REGISTRY[cmd_code]
            kwargs = {}
            # Extrair os valores digitados ou selecionados
            for param_name, input_field in self.param_inputs.items():
                if isinstance(input_field, QComboBox):
                    val = input_field.currentData()
                else:
                    val = input_field.text().strip()
                
                # Customização solicitada pelo usuário para o comando EU
                if cmd_code == "EU":
                    if param_name == "Matrícula2":
                        val = "}" + val
                    elif param_name == "Senha":
                        val = "[" + val
                
                kwargs[param_name] = val
                
            try:
                # O comando delega a construção de si mesmo (Padrão Builder)
                command_str = cmd_def.build(**kwargs)
            except ValueError as e:
                # Bloqueia o envio e avisa o usuário se a validação falhar
                QMessageBox.warning(self, "Erro de Validação", str(e))
                self.append_log(f"Comando abortado: {e}")
                return

        # 2. Desabilitar botão e instanciar rotina (Comportamento original preservado)
        self.send_button.setEnabled(False)
        self.command_worker = CommandWorker(self.persistent_sock, command_str, self.session_key)
        self.command_worker.sent_signal.connect(self.append_sent)
        self.command_worker.sent_bytes_signal.connect(self.append_sent_bytes)
        self.command_worker.received_signal.connect(self.append_received)
        self.command_worker.received_bytes_signal.connect(self.append_received_bytes)
        self.command_worker.finished_signal.connect(self.on_send_command_finished)
        self.command_worker.start()

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
                self.connect_button.setEnabled(False)
                return

            is_valid = len(password) == 6 and password.isdigit()
            self.connect_button.setEnabled(is_valid)


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
            
        # Rola a barra vertical automaticamente para o final em ambas as caixas
        self.sent_output.verticalScrollBar().setValue(self.sent_output.verticalScrollBar().maximum())
        self.received_output.verticalScrollBar().setValue(self.received_output.verticalScrollBar().maximum())

    def append_sent(self, text: str):
        if self.last_sent_text:
            self.last_sent_text += "\n" + text
        else:
            self.last_sent_text = text
        self.update_sent_received_output()

    def append_sent_bytes(self, hex_text: str):
        if self.last_sent_bytes:
            self.last_sent_bytes += "\n" + hex_text
        else:
            self.last_sent_bytes = hex_text
        self.update_sent_received_output()
    
    def append_received(self, text: str):
        if self.last_received_text:
            self.last_received_text += "\n" + text
        else:
            self.last_received_text = text
        self.update_sent_received_output()

    def append_received_bytes(self, hex_text: str):
        if self.last_received_bytes:
            self.last_received_bytes += "\n" + hex_text
        else:
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

    def on_send_command_finished(self, success: bool, message: str):
        self.append_log(message)
        self.send_button.setEnabled(True)
        if not success:
            # Se falhou o envio do comando, pode ser que a conexão tenha caído.
            self.append_log("Possível perda de conexão. Desconectando...")
            self.disconnect()

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
        if self.persistent_sock:
            try:
                self.persistent_sock.close()
            except:
                pass
            self.persistent_sock = None
        
        self.session_key = None
        self.connected = False
        self.connect_button.setText("Conectar")
        self.connect_button.setEnabled(True)
        self.send_button.setEnabled(False)
        self.set_inputs_enabled(True)
        self.append_log("Desconectado.")

    def on_finished(self, success: bool, message: str, sock=None, session_key=None):
        self.connect_timer.stop()
        self.dot_count = 0
        self.append_log(message)
        if success:
            self.persistent_sock = sock
            self.session_key = session_key
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
