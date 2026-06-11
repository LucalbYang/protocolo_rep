import sys
import os
import socket
import base64
import traceback
import time
import random
import re
import ctypes
from datetime import datetime

from PyQt6.QtCore import QThread, pyqtSignal, QSettings, QTimer, Qt, QEvent
from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import (QApplication, QGridLayout, QLabel, QLineEdit,
                             QPushButton, QTextEdit, QWidget, QStackedWidget,
                             QGroupBox, QVBoxLayout, QHBoxLayout, QMessageBox,
                             QComboBox, QFormLayout, QScrollArea, QCheckBox, QFrame,
                             QRadioButton, QButtonGroup, QProgressBar)

from comandos import COMMANDS_REGISTRY
from constants import APP_VERSION, EC_VAL_CHOICES
from ui_styles import build_qss
from utils import resource_path, generate_cpf, generate_random_name, get_local_ip, list_all_local_ips
from evo_protocol import EvoRepProtocol
from evo_crypto import EvoRepCrypto
from workers import (NetworkWorker, ClientNetworkWorker, F3NetworkWorker, 
                     CommandWorker, ListenerWorker, DeauthWorker, IPDiscoveryWorker)
from widgets import NoScrollComboBox, NotificationCard, HeaderBar, DynamicIPComboBox
from macro import MacroWindow

# ══════════════════════════════════════════════════════════════════════
#  APLICAÇÃO PRINCIPAL
# ══════════════════════════════════════════════════════════════════════

class EvoRepAuthApp(QWidget):
    def __init__(self):
        super().__init__()
        # Estado independente por aba
        self.tab_data = {
            "main_": {
                "persistent_sock": None,
                "session_key": None,
                "rsa_key": None,
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
                "rsa_key": None,
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
                "session_key": None,
                "rsa_key": None,
                "connected": False,
                "worker": None,
                "listener_worker": None,
                "last_sent_text": "",
                "last_sent_bytes": "",
                "last_received_text": "",
                "last_received_bytes": "",
                "reconnect_count": 0,
            },
            "test_": {
                "persistent_sock": None,
                "session_key": None,
                "rsa_key": None,
                "connected": False,
                "worker": None,
                "listener_worker": None,
                "last_sent_text": "",
                "last_sent_bytes": "",
                "last_received_text": "",
                "last_received_bytes": "",
            }
        }

        self.show_bytes    = False
        self.dark_mode     = False
        self.settings      = QSettings("EvoRep", "EvoRepAuthApp")

        # Variáveis para histórico do modo manual
        self.manual_history      = []
        self.history_index       = -1
        self.last_manual_command = "01+RH+00"

        # 🔹 REQUISITO: Lista para manter referências de workers externos
        self.external_workers = []

        self.connect_timer = QTimer()
        self.connect_timer.timeout.connect(self.animate_connecting_button)
        self.dot_count = 0

        self.param_inputs = {}

        self.test_mode = None
        self.old_credentials = {}
        self.test_queue = []
        self.is_test_running = False
        
        # AFD State
        self.afd_save_path = ""
        self.afd_current_file = None
        self.afd_total = 0
        self.afd_collected = 0
        self.afd_nsr = 1
        self.afd_rep_num = "00000000000000001"
        self.afd_rep_model = ""
        self.afd_state = None # "HEADER", "MODEL", "EMPLOYER", "COUNT", "COLLECTING"
        self.afd_emp_id = ""
        self.afd_emp_type = "1"
        self.afd_emp_name = ""

        # Report State
        self.report_save_path   = ""
        self.is_report_running  = False
        self.report_worker      = None
        self.afd_first_date = ""
        self.afd_last_date = ""
        self.afd_count_2 = 0
        self.afd_count_3 = 0
        self.afd_count_4 = 0
        self.afd_count_5 = 0
        self.afd_count_6 = 0
        self.test_timeout_timer = QTimer()
        self.test_timeout_timer.setSingleShot(True)
        self.test_timeout_timer.timeout.connect(self.on_test_timeout)

        self.loading_timer = QTimer()
        self.loading_timer.timeout.connect(self.update_loading_animations)
        self.loading_symbols = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        self.symbol_idx = 0

        self._setup_ui()
        self.load_config()
        self.update_client_ip_list() # Primeira carga ao abrir

        self.setCursor(Qt.CursorShape.ArrowCursor)
        QApplication.processEvents()
        self.on_command_selected(0)

    def closeEvent(self, event):
        """Salva todas as configurações e desconecta sockets ao fechar."""
        self.save_config()
        self.disconnect("main_")
        self.disconnect("client_")
        self.disconnect("f3_")
        self.settings.setValue("geometry", self.saveGeometry())
        self.settings.setValue("active_tab", self.stacked_widget.currentIndex())
        super().closeEvent(event)

    # ──────────────────────────────────────────────────────────────────
    #  TEMA
    # ──────────────────────────────────────────────────────────────────

    def toggle_theme(self):
        """Alterna entre Light Mode e Dark Mode."""
        self.dark_mode = not self.dark_mode
        QApplication.instance().setStyleSheet(build_qss(dark=self.dark_mode))

    # ──────────────────────────────────────────────────────────────────
    #  SETUP UI
    # ──────────────────────────────────────────────────────────────────

    def _normalize_ip_field(self, line_edit: QLineEdit):
        """Remove zeros à esquerda de cada octeto do IP (ex: 192.168.001.010 -> 192.168.1.10)."""
        text = line_edit.text().strip()
        if not text: return
        # Tenta normalizar apenas se parecer um IP (4 blocos numéricos)
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', text):
            try:
                parts = text.split('.')
                normalized = ".".join(str(int(p)) for p in parts)
                line_edit.setText(normalized)
            except:
                pass

    def _setup_ui(self):
        self.setWindowTitle("REPLink — Protocolo EVO REP-A/C")
        self.stacked_widget = QStackedWidget(self)

        # Criação das abas
        self.main_tab   = self._create_rep_tab(prefix="main_")
        self.log_tab    = self._create_log_tab()
        self.client_tab = self._create_rep_tab(prefix="client_")
        self.f3_tab     = self._create_rep_tab(prefix="f3_")
        self.test_tab   = self._create_test_tab()

        self.stacked_widget.addWidget(self.main_tab)    # Index 0
        self.stacked_widget.addWidget(self.log_tab)     # Index 1
        self.stacked_widget.addWidget(self.client_tab)  # Index 2
        self.stacked_widget.addWidget(self.f3_tab)      # Index 3
        self.stacked_widget.addWidget(self.test_tab)    # Index 4

        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # ── Header bar ────────────────────────────────────────────
        self.header_bar = HeaderBar()
        self.header_bar.theme_toggled.connect(self.toggle_theme)
        self.header_bar.tab_changed.connect(self._on_tab_button_clicked)
        root_layout.addWidget(self.header_bar)

        # ── Área de conteúdo ─────────────────────────────────────
        content = QWidget()
        content.setObjectName("content_area")
        content_v = QVBoxLayout(content)
        content_v.setContentsMargins(14, 12, 14, 12)
        content_v.setSpacing(0)
        content_v.addWidget(self.stacked_widget)
        root_layout.addWidget(content)

        self.setLayout(root_layout)
        self.setMinimumSize(900, 640)
        self.resize(940, 680)

        # Sincroniza o indicador de aba ativa com o stacked widget
        self.stacked_widget.currentChanged.connect(self._on_stacked_changed)
        self.header_bar.set_active_tab(0)

    def _on_tab_button_clicked(self, index: int):
        self.stacked_widget.setCurrentIndex(index)
        if index != 1:  # Não é a aba de log
            self.on_command_selected(0)

    def _on_stacked_changed(self, index: int):
        self.header_bar.set_active_tab(index)

    # ──────────────────────────────────────────────────────────────────
    #  CRIAÇÃO DAS ABAS
    # ──────────────────────────────────────────────────────────────────

    def _create_rep_tab(self, prefix="main_"):
        is_client_mode = (prefix == "client_")
        is_f3          = (prefix == "f3_")

        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        # ── ÁREA SUPERIOR: Conexão | Comandos ─────────────────────
        top_layout = QHBoxLayout()
        top_layout.setSpacing(10)

        # ── Painel de Conexão ──────────────────────────────────────
        conn_group = QGroupBox("Conexão")
        conn_layout = QGridLayout(conn_group)
        conn_layout.setContentsMargins(10, 10, 10, 10)
        conn_layout.setSpacing(7)
        conn_layout.setColumnStretch(1, 1)

        conn_layout.addWidget(QLabel("IP:"), 0, 0)
        if is_client_mode:
            ip_input = DynamicIPComboBox()
            ip_input.aboutToShowPopup.connect(self.update_client_ip_list)
        else:
            ip_val  = "192.168.60.71"
            ip_input = QLineEdit(ip_val)
        conn_layout.addWidget(ip_input, 0, 1)

        conn_layout.addWidget(QLabel("Porta:"), 1, 0)
        port_input = QLineEdit("3000")
        conn_layout.addWidget(port_input, 1, 1)

        if not is_f3:
            conn_layout.addWidget(QLabel("Usuário:"), 2, 0)
            user_input = QLineEdit("teste fabrica")
            conn_layout.addWidget(user_input, 2, 1)

            conn_layout.addWidget(QLabel("Senha:"), 3, 0)
            password_input = QLineEdit("111111")
            password_input.setEchoMode(QLineEdit.EchoMode.Password)
            password_input.setMaxLength(6)
            conn_layout.addWidget(password_input, 3, 1)

        # 🔹 REQUISITO 2: Refatoração dos Botões da Aba F2 (Modo Cliente)
        if is_client_mode:
            self.client_btn_server_control = QPushButton("Iniciar Servidor")
            self.client_btn_server_control.setObjectName("primary_btn")
            self.client_btn_client_state = QPushButton("Aguardando Conexão")
            self.client_btn_client_state.setEnabled(False)

            client_btns_layout = QHBoxLayout()
            client_btns_layout.setSpacing(6)
            client_btns_layout.addWidget(self.client_btn_server_control)
            client_btns_layout.addWidget(self.client_btn_client_state)
            conn_layout.addLayout(client_btns_layout, 4, 0, 1, 2)

            self.client_btn_server_control.clicked.connect(self.on_connect_clicked)
            self.client_btn_client_state.clicked.connect(self.on_connect_clicked)

            # 🔹 REQUISITO: Botão Macro para F2 (Client Mode)
            macro_btn = QPushButton("Macro")
            macro_btn.setVisible(False)
            macro_btn.clicked.connect(lambda: self.on_macro_clicked(prefix))
            conn_layout.addWidget(macro_btn, 5, 0, 1, 2)
            setattr(self, f"{prefix}macro_button", macro_btn)

        elif is_f3:
            self.f3_connect_button = QPushButton("Conectar")
            self.f3_connect_button.setObjectName("primary_btn")
            self.f3_connect_button.clicked.connect(self.on_connect_clicked)
            conn_layout.addWidget(self.f3_connect_button, 2, 0, 1, 2)
            
            # 🔹 REQUISITO: Aviso em vermelho abaixo do botão Conectar na F3
            self.f3_connection_warning = QLabel("")
            self.f3_connection_warning.setStyleSheet("color: #E74C3C; font-weight: bold; font-size: 11px;")
            self.f3_connection_warning.setWordWrap(True)
            conn_layout.addWidget(self.f3_connection_warning, 3, 0, 1, 2)

        else:
            self.main_connect_layout = QHBoxLayout()
            self.main_connect_layout.setContentsMargins(0, 0, 0, 0)
            self.main_connect_layout.setSpacing(5)

            self.main_connect_button = QPushButton("Conectar")
            self.main_connect_button.setObjectName("primary_btn")
            self.main_connect_button.clicked.connect(self.on_connect_clicked)

            self.main_cancel_button = QPushButton("🗙")
            self.main_cancel_button.setObjectName("cancel_btn")
            self.main_cancel_button.setVisible(False)
            self.main_cancel_button.setToolTip("Cancelar conexão")
            self.main_cancel_button.clicked.connect(self.on_cancel_connect_clicked)

            self.main_connect_layout.addWidget(self.main_connect_button, 8)
            self.main_connect_layout.addWidget(self.main_cancel_button, 2)
            conn_layout.addLayout(self.main_connect_layout, 4, 0, 1, 2)

            # 🔹 REQUISITO: Botão Macro (F1)
            macro_btn = QPushButton("Macro")
            macro_btn.setVisible(False)
            macro_btn.clicked.connect(lambda: self.on_macro_clicked(prefix))
            conn_layout.addWidget(macro_btn, 5, 0, 1, 2)
            setattr(self, f"{prefix}macro_button", macro_btn)

        conn_layout.setRowStretch(6, 1)

        # ── Painel de Comandos ─────────────────────────────────────
        if is_f3:
            cmds_group = QGroupBox("Identificação do Equipamento")
            cmds_group_layout = QFormLayout(cmds_group)
            cmds_group_layout.setSpacing(7)
            cmds_group_layout.setContentsMargins(10, 10, 10, 10)

            self.f3_rep_num_field = QLineEdit()
            self.f3_rep_num_field.setReadOnly(True)
            self.f3_rep_num_field.setPlaceholderText("Aguardando conexão...")

            self.f3_unlock_code_field = QLineEdit()
            self.f3_unlock_code_field.setReadOnly(True)
            self.f3_unlock_code_field.setPlaceholderText("Aguardando conexão...")

            cmds_group_layout.addRow("Número do REP:", self.f3_rep_num_field)
            cmds_group_layout.addRow("Código de Bloqueio:", self.f3_unlock_code_field)
            cmds_group_layout.addRow(QLabel(""))

            cmds_group_layout.addRow(QLabel("Código de Desbloqueio:"))
            self.f3_unlock_input_field = QLineEdit()
            self.f3_unlock_input_field.setPlaceholderText("Cole ou digite o código de desbloqueio aqui")
            cmds_group_layout.addRow(self.f3_unlock_input_field)

            self.f3_unlock_button = QPushButton("Desbloquear")
            self.f3_unlock_button.setObjectName("primary_btn")
            self.f3_unlock_button.setEnabled(False)
            cmds_group_layout.addRow(self.f3_unlock_button)

            # Funcionalidade de clique para copiar e tooltips
            def copy_to_clipboard(text):
                if text:
                    QApplication.clipboard().setText(text)

            self.f3_unlock_code_field.setToolTip("Clique para copiar")
            self.f3_unlock_code_field.mousePressEvent = lambda e: copy_to_clipboard(self.f3_unlock_code_field.text())
            self.f3_rep_num_field.setToolTip("Número do REP")

            # Widgets invisíveis para compatibilidade com referências compartilhadas
            command_combo    = NoScrollComboBox()
            command_combo.setVisible(False)
            dynamic_layout   = QFormLayout()
            send_button      = QPushButton()
            send_button.setVisible(False)
            cmd_description_label = QLabel()
            cmd_description_label.setVisible(False)

        else:
            cmds_group = QGroupBox("Construção de Comandos")
            cmds_group_layout = QVBoxLayout(cmds_group)
            cmds_group_layout.setContentsMargins(10, 10, 10, 10)
            cmds_group_layout.setSpacing(7)

            combo_layout = QHBoxLayout()
            combo_layout.setSpacing(8)
            combo_layout.addWidget(QLabel("Selecionar:"))

            command_combo = NoScrollComboBox()
            command_combo.addItem("Modo Manual / Custom", None)
            for code, cmd_def in COMMANDS_REGISTRY.items():
                if code in ["RR_MEMORIA", "RR_NSR", "RR_DATA", "RU_QUANTIDADE", "RU_MATRICULA",
                             "RU_CPF", "ED_CADASTRAR", "ED_DELETAR", "ED_SUPREMA", "ED_BIO_AZUL",
                             "ED_FACE", "ED_FACE_CORP", "RD_LISTA", "RD_QTD", "RD_TEMPLATE"]:
                    continue
                resumo = cmd_def.description.split(':')[0] if ':' in cmd_def.description else cmd_def.description.split('.')[0]
                command_combo.addItem(f"{code} — {resumo}", code)
            combo_layout.addWidget(command_combo)
            cmds_group_layout.addLayout(combo_layout)

            cmd_description_label = QLabel("")
            cmd_description_label.setWordWrap(True)
            cmd_description_label.setStyleSheet("color: #888; font-style: italic; font-size: 11px;")
            cmds_group_layout.addWidget(cmd_description_label)

            # Separador
            sep = QFrame()
            sep.setFrameShape(QFrame.Shape.HLine)
            cmds_group_layout.addWidget(sep)

            params_scroll = QScrollArea()
            params_scroll.setWidgetResizable(True)
            params_scroll.setFrameShape(QFrame.Shape.NoFrame)
            dynamic_params_widget = QWidget()
            dynamic_layout = QFormLayout(dynamic_params_widget)
            dynamic_layout.setSpacing(8)
            dynamic_layout.setContentsMargins(4, 4, 4, 4)
            params_scroll.setWidget(dynamic_params_widget)
            cmds_group_layout.addWidget(params_scroll)

            send_button = QPushButton("▶  Enviar Comando")
            send_button.setObjectName("primary_btn")
            send_button.setEnabled(False)
            cmds_group_layout.addWidget(send_button)

        top_layout.addWidget(conn_group, 1)
        top_layout.addWidget(cmds_group, 3)
        layout.addLayout(top_layout)

        # ── ÁREA INFERIOR: Log de comunicação ─────────────────────
        log_row = QHBoxLayout()
        log_row.setSpacing(10)

        sent_group = QGroupBox("String Enviada")
        sent_v = QVBoxLayout(sent_group)
        sent_v.setContentsMargins(8, 10, 8, 8)
        sent_output = QTextEdit()
        sent_output.setReadOnly(True)
        sent_v.addWidget(sent_output)

        received_group = QGroupBox("String Recebida")
        recv_v = QVBoxLayout(received_group)
        recv_v.setContentsMargins(8, 10, 8, 8)
        received_output = QTextEdit()
        received_output.setReadOnly(True)
        recv_v.addWidget(received_output)

        log_row.addWidget(sent_group)
        log_row.addWidget(received_group)
        layout.addLayout(log_row)

        # ── Controles inferiores ──────────────────────────────────
        control_layout = QHBoxLayout()
        control_layout.setSpacing(8)

        clear_button = QPushButton("Limpar")
        control_layout.addWidget(clear_button) 
        control_layout.addStretch()

        toggle_mode_button = QPushButton("Exibir em bytes")
        control_layout.addWidget(toggle_mode_button)
        layout.addLayout(control_layout)

        # ── Armazenar referências ─────────────────────────────────
        setattr(self, f"{prefix}ip_input",            ip_input)
        setattr(self, f"{prefix}port_input",          port_input)
        if not is_f3:
            setattr(self, f"{prefix}user_input",      user_input)
            setattr(self, f"{prefix}password_input",  password_input)
            password_input.textChanged.connect(self.validate_password_input)
            password_input.returnPressed.connect(self.on_enter_pressed)
            user_input.returnPressed.connect(self.on_enter_pressed)

        setattr(self, f"{prefix}sent_group",            sent_group)
        setattr(self, f"{prefix}received_group",        received_group)
        setattr(self, f"{prefix}command_combo",         command_combo)
        setattr(self, f"{prefix}dynamic_layout",        dynamic_layout)
        setattr(self, f"{prefix}send_button",           send_button)
        setattr(self, f"{prefix}sent_output",           sent_output)
        setattr(self, f"{prefix}received_output",       received_output)
        setattr(self, f"{prefix}clear_button",          clear_button)
        setattr(self, f"{prefix}toggle_mode_button",    toggle_mode_button)
        setattr(self, f"{prefix}cmd_description_label", cmd_description_label)

        # ── Sinais ────────────────────────────────────────────────
        if isinstance(ip_input, QLineEdit):
            ip_input.returnPressed.connect(self.on_enter_pressed)
            ip_input.editingFinished.connect(lambda: self._normalize_ip_field(ip_input))
        
        port_input.returnPressed.connect(self.on_enter_pressed)
        command_combo.currentIndexChanged.connect(self.on_command_selected)
        send_button.clicked.connect(self.on_send_command_clicked)
        clear_button.clicked.connect(self.on_clear_clicked)
        toggle_mode_button.clicked.connect(self.on_toggle_display_mode)

        if is_f3:
            self.f3_unlock_button.clicked.connect(self.on_f3_unlock_clicked)
            self.f3_unlock_input_field.returnPressed.connect(self.on_f3_unlock_clicked)
            self.f3_connect_button.clicked.connect(lambda: self.f3_unlock_button.setEnabled(self.tab_data["f3_"]["connected"]))

        return tab

    def _create_log_tab(self):
        log_tab = QWidget()
        log_v   = QVBoxLayout(log_tab)
        log_v.setContentsMargins(0, 0, 0, 0)

        log_group = QGroupBox("Log de Eventos")
        log_grp_v = QVBoxLayout(log_group)
        log_grp_v.setContentsMargins(8, 10, 8, 8)

        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        log_grp_v.addWidget(self.log_output)

        log_v.addWidget(log_group)
        return log_tab

    def _create_test_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        top_boxes_layout = QHBoxLayout()
        top_boxes_layout.setSpacing(10)
        top_boxes_layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        # 1. Box de Conexão
        conn_group = QGroupBox("Conexão")
        conn_form = QFormLayout()
        conn_form.setContentsMargins(10, 20, 10, 10)
        conn_form.setSpacing(5)
        
        self.test_ip_input = QLineEdit()
        self.test_port_input = QLineEdit()
        
        self.test_ip_input.setText(self.main_ip_input.text())
        self.test_port_input.setText(self.main_port_input.text())
        self.main_ip_input.textChanged.connect(self.test_ip_input.setText)
        self.test_ip_input.textChanged.connect(self.main_ip_input.setText)
        self.main_port_input.textChanged.connect(self.test_port_input.setText)
        self.test_port_input.textChanged.connect(self.main_port_input.setText)

        conn_form.addRow("IP:", self.test_ip_input)
        conn_form.addRow("Porta:", self.test_port_input)
        conn_group.setLayout(conn_form)

        # 2. Box de Cadastrar
        cad_group = QGroupBox("Cadastrar")
        cad_box_layout = QVBoxLayout()
        cad_box_layout.setContentsMargins(10, 20, 10, 10)
        cad_box_layout.setSpacing(5)

        self.btn_user_padrao = QPushButton("Usuário Padrão")
        self.btn_user_padrao.setObjectName("primary_btn")
        self.btn_user_padrao.setMinimumHeight(25)
        self.btn_user_padrao.clicked.connect(lambda: self.on_test_button_clicked("usuario_padrao"))

        self.btn_empregador = QPushButton("Empregador EVO")
        self.btn_empregador.setObjectName("primary_btn")
        self.btn_empregador.setMinimumHeight(25)
        self.btn_empregador.clicked.connect(lambda: self.on_test_button_clicked("empregador"))

        self.btn_colab_teste = QPushButton("Colaborador Teste")
        self.btn_colab_teste.setObjectName("primary_btn")
        self.btn_colab_teste.setMinimumHeight(25)
        self.btn_colab_teste.clicked.connect(lambda: self.on_test_button_clicked("colaborador"))

        cad_box_layout.addWidget(self.btn_user_padrao)
        cad_box_layout.addWidget(self.btn_empregador)
        cad_box_layout.addWidget(self.btn_colab_teste)
        cad_group.setLayout(cad_box_layout)

        # 3. Box de Extrair AFD
        afd_group = QGroupBox("Extrair AFD")
        afd_box_layout = QVBoxLayout()
        afd_box_layout.setContentsMargins(10, 20, 10, 10)
        afd_box_layout.setSpacing(5)

        self.btn_choose_afd_path = QPushButton("Escolher pasta")
        self.btn_choose_afd_path.setMinimumHeight(25)
        self.btn_choose_afd_path.clicked.connect(self.on_choose_afd_path)

        # 🔹 REQUISITO: Texto inicial indicativo
        self.btn_gerar_afd = QPushButton("Gerar AFD - Escolha pasta para liberar")
        self.btn_gerar_afd.setObjectName("primary_btn")
        self.btn_gerar_afd.setEnabled(False)
        self.btn_gerar_afd.setMinimumHeight(25)
        self.btn_gerar_afd.clicked.connect(lambda: self.on_test_button_clicked("gerar_afd"))

        self.afd_progress_bar = QProgressBar()
        self.afd_progress_bar.setVisible(False)
        self.afd_progress_bar.setMinimumHeight(15)

        afd_box_layout.addWidget(self.btn_choose_afd_path)
        afd_box_layout.addWidget(self.btn_gerar_afd)
        afd_box_layout.addWidget(self.afd_progress_bar)
        afd_group.setLayout(afd_box_layout)

        # 4. Box de Gerar Relatório de Testes
        report_group = QGroupBox("Gerar Relatório de Testes")
        report_box_layout = QVBoxLayout()
        report_box_layout.setContentsMargins(10, 20, 10, 10)
        report_box_layout.setSpacing(5)

        self.btn_choose_report_path = QPushButton("Escolher pasta")
        self.btn_choose_report_path.setMinimumHeight(25)
        self.btn_choose_report_path.clicked.connect(self.on_choose_report_path)

        self.btn_gerar_relatorio = QPushButton("Gerar Relatório - Escolha pasta para liberar")
        self.btn_gerar_relatorio.setObjectName("primary_btn")
        self.btn_gerar_relatorio.setEnabled(False)
        self.btn_gerar_relatorio.setMinimumHeight(25)
        self.btn_gerar_relatorio.clicked.connect(lambda: self.on_test_button_clicked("gerar_relatorio"))

        self.report_progress_bar = QProgressBar()
        self.report_progress_bar.setVisible(False)
        self.report_progress_bar.setMinimumHeight(15)

        report_box_layout.addWidget(self.btn_choose_report_path)
        report_box_layout.addWidget(self.btn_gerar_relatorio)
        report_box_layout.addWidget(self.report_progress_bar)
        report_group.setLayout(report_box_layout)

        # 5. Box Procurar REPs
        search_group = QGroupBox("Procurar REPs")
        search_box_layout = QVBoxLayout()
        search_box_layout.setContentsMargins(10, 20, 10, 10)
        search_box_layout.setSpacing(5)

        from PyQt6.QtWidgets import QListWidget
        self.rep_list_widget = QListWidget()
        self.rep_list_widget.setMinimumHeight(60)

        search_btns_layout = QHBoxLayout()
        self.btn_search_reps = QPushButton("Buscar")
        self.btn_search_reps.setObjectName("primary_btn")
        self.btn_search_reps.clicked.connect(self.on_search_reps_clicked)

        self.btn_connect_rep = QPushButton("Conectar")
        self.btn_connect_rep.setObjectName("primary_btn")
        self.btn_connect_rep.clicked.connect(self.on_connect_searched_rep)

        search_btns_layout.addWidget(self.btn_search_reps)
        search_btns_layout.addWidget(self.btn_connect_rep)

        search_box_layout.addWidget(self.rep_list_widget)
        search_box_layout.addLayout(search_btns_layout)
        search_group.setLayout(search_box_layout)

        # Organiza as boxes no layout horizontal com peso 1 (distribuição igualitária)
        top_boxes_layout.addWidget(conn_group, 1)
        top_boxes_layout.addWidget(cad_group, 1)
        top_boxes_layout.addWidget(afd_group, 1)

        # 🔹 REQUISITO: Relatório na linha de baixo ocupando 1/3 e Procurar REPs ocupando 1/3
        bottom_boxes_layout = QHBoxLayout()
        bottom_boxes_layout.setSpacing(10)
        bottom_boxes_layout.addWidget(report_group, 1)
        bottom_boxes_layout.addWidget(search_group, 1)
        bottom_boxes_layout.addStretch(1) # Faz os dois ocuparem 2/3 e o resto ser espaço vazio

        # Layout Principal da aba
        layout.addLayout(top_boxes_layout)
        layout.addLayout(bottom_boxes_layout)
        
        # 🔹 REQUISITO: Label de aviso em vermelho no canto inferior esquerdo
        bottom_layout = QHBoxLayout()
        self.test_connection_warning = QLabel("")
        self.test_connection_warning.setStyleSheet("color: #E74C3C; font-weight: bold; font-size: 11px;")
        bottom_layout.addWidget(self.test_connection_warning)
        bottom_layout.addStretch()
        
        layout.addStretch()
        layout.addLayout(bottom_layout)

        return tab

    def update_dependent_tabs_state(self):
        """Atualiza o estado das abas F3 e F5 baseado na conexão da F1."""
        is_f1_connected = self.tab_data["main_"]["connected"]
        is_test_active = getattr(self, "is_test_running", False)
        is_report_active = getattr(self, "is_report_running", False)

        # ── LÓGICA PARA ABA F5 (TESTES) ──────────────────────────
        if hasattr(self, "test_connection_warning"):
            # Só mostra o aviso se a F1 estiver conectada MANUALMENTE (não via teste)
            if is_f1_connected and not is_test_active:
                self.test_connection_warning.setText("⚠️ Desconecte na aba F1 para liberar os testes.")
            elif is_report_active:
                self.test_connection_warning.setText("⚠️ Relatório em execução...")
            else:
                self.test_connection_warning.setText("")

            # 🔹 REQUISITO: Botões liberados se F1 desconectada OU se for conexão de teste ativo
            # Bloqueia tudo se o relatório estiver rodando.
            base_interact = (not is_f1_connected or is_test_active) and not is_report_active

            # Helper para saber se o botão específico já está na fila
            def is_in_queue(btn):
                return any(item[1] == btn for item in getattr(self, "test_queue", []))

            self.btn_user_padrao.setEnabled(base_interact and not is_in_queue(self.btn_user_padrao))
            self.btn_empregador.setEnabled(base_interact and not is_in_queue(self.btn_empregador))
            self.btn_colab_teste.setEnabled(base_interact and not is_in_queue(self.btn_colab_teste))
            self.btn_choose_afd_path.setEnabled(base_interact) # Escolher pasta sempre livre se base_interact

            if hasattr(self, "btn_choose_report_path"):
                self.btn_choose_report_path.setEnabled(base_interact)
                if not base_interact or is_in_queue(self.btn_gerar_relatorio):
                    self.btn_gerar_relatorio.setEnabled(False)
                else:
                    self.btn_gerar_relatorio.setEnabled(bool(self.report_save_path))

            # Gerar AFD também entra na fila
            if not base_interact or is_in_queue(self.btn_gerar_afd):
                self.btn_gerar_afd.setEnabled(False)
            else:
                self.btn_gerar_afd.setEnabled(bool(self.afd_save_path))
        # ── LÓGICA PARA ABA F3 (DESBLOQUEIO) ──────────────────────
        if hasattr(self, "f3_connection_warning"):
            if is_f1_connected:
                self.f3_connection_warning.setText("⚠️ Desconecte na aba F1 para realizar o desbloqueio F3.")
                self.f3_connect_button.setEnabled(False)
            else:
                self.f3_connection_warning.setText("")
                # Se não está conectada, habilita apenas se não houver um worker de conexão rodando
                state_f3 = self.tab_data["f3_"]
                if not state_f3["connected"]:
                    self.f3_connect_button.setEnabled(True)
                    
    def update_client_ip_list(self):
        """Dispara a busca de IPs em segundo plano para não travar a UI."""
        if not hasattr(self, "client_ip_input") or not isinstance(self.client_ip_input, QComboBox):
            return

        # Evita disparar múltiplos workers simultâneos
        if hasattr(self, "ip_discovery_worker") and self.ip_discovery_worker.isRunning():
            return

        self.ip_discovery_worker = IPDiscoveryWorker()
        self.ip_discovery_worker.finished_signal.connect(self.apply_discovered_ips)
        self.ip_discovery_worker.start()

    def apply_discovered_ips(self, all_ips):
        """Aplica os IPs encontrados ao ComboBox da aba F2."""
        if not hasattr(self, "client_ip_input"): return
        
        current_ip = self.client_ip_input.currentText()
        
        # Só atualiza se a lista mudou para evitar flicker
        existing_items = [self.client_ip_input.itemText(i) for i in range(self.client_ip_input.count())]
        if all_ips == existing_items:
            return

        self.client_ip_input.blockSignals(True)
        self.client_ip_input.clear()
        self.client_ip_input.addItems(all_ips)
        
        # Tenta restaurar a seleção anterior
        index = self.client_ip_input.findText(current_ip)
        if index >= 0:
            self.client_ip_input.setCurrentIndex(index)
        elif self.client_ip_input.count() > 0:
            self.client_ip_input.setCurrentIndex(0)
            
        self.client_ip_input.blockSignals(False)
    def on_choose_afd_path(self):
        from PyQt6.QtWidgets import QFileDialog
        last_dir = self.settings.value("afd_last_dir", os.path.expanduser("~"))
        folder = QFileDialog.getExistingDirectory(self, "Escolher Pasta para salvar AFD", last_dir)
        
        if folder:
            self.afd_save_path = folder
            self.settings.setValue("afd_last_dir", folder)
            self.btn_gerar_afd.setEnabled(True)
            self.btn_gerar_afd.setText("Gerar AFD") # 🔹 Restaura o texto original ao liberar
            self.append_log(f"ABA TESTES (F5): Pasta para AFD definida: {folder}")

    def on_choose_report_path(self):
        from PyQt6.QtWidgets import QFileDialog
        last_dir = self.settings.value("report_last_dir", os.path.expanduser("~"))
        folder = QFileDialog.getExistingDirectory(self, "Escolher Pasta para salvar Relatório", last_dir)
        
        if folder:
            self.report_save_path = folder
            self.settings.setValue("report_last_dir", folder)
            self.btn_gerar_relatorio.setEnabled(True)
            self.btn_gerar_relatorio.setText("Gerar Relatório")
            self.append_log(f"ABA TESTES (F5): Pasta para Relatório definida: {folder}")

    def on_search_reps_clicked(self):
        self.btn_search_reps.setEnabled(False)
        self.btn_search_reps.setText("Buscando...")
        self.rep_list_widget.clear()
        
        from workers import REPScannerWorker
        self.rep_scanner = REPScannerWorker(port=int(self.main_port_input.text() or 3000))
        self.rep_scanner.progress_signal.connect(self.on_rep_search_progress)
        self.rep_scanner.found_signal.connect(self.on_rep_found)
        self.rep_scanner.finished_signal.connect(self.on_rep_search_finished)
        self.rep_scanner.start()

    def on_rep_search_progress(self, percent):
        self.btn_search_reps.setText(f"Buscando... {percent}%")

    def on_rep_found(self, ip):
        self.rep_list_widget.addItem(ip)

    def on_rep_search_finished(self, found_reps):
        self.btn_search_reps.setText("Buscar")
        self.btn_search_reps.setEnabled(True)
        if not found_reps:
            self.append_log("ABA TESTES (F5): Nenhum REP encontrado na rede local.")

    def on_connect_searched_rep(self):
        selected_items = self.rep_list_widget.selectedItems()
        if not selected_items:
            return
            
        ip = selected_items[0].text()
        
        # Redireciona para aba F1 e preenche o IP
        self.stacked_widget.setCurrentIndex(0)
        self.main_ip_input.setText(ip)
        self.on_command_selected(0)
        
        # Opcionalmente já clicar em conectar
        # self.on_connect_clicked("main_")

    def update_loading_animations(self):
        self.symbol_idx = (self.symbol_idx + 1) % len(self.loading_symbols)
        symbol = self.loading_symbols[self.symbol_idx]
        
        # Atualiza todos os botões que estão na fila (test_queue contém tuplas (tipo, btn))
        for _, btn in self.test_queue:
            orig = btn.property("original_text")
            if orig:
                btn.setText(f"{symbol} {orig}")

    def on_test_button_clicked(self, test_type):
        btn = self.sender()
        if not btn: return
        
        # Salva o texto original para restauração posterior
        if not btn.property("original_text"):
            btn.setProperty("original_text", btn.text())

        # Log da ação iniciada
        self.append_log(f"ABA TESTES (F5): Iniciando ação '{btn.property('original_text')}'...")

        # Bloqueia o botão IMEDIATAMENTE
        btn.setEnabled(False)

        # Inicia a animação se não estiver rodando
        if not self.loading_timer.isActive():
            self.loading_timer.start(100)

        self.test_queue.append((test_type, btn))
        
        if not self.is_test_running:
            self.run_next_test()

    def run_next_test(self):
        if not self.test_queue:
            self.is_test_running = False
            return

        self.is_test_running = True
        test_type, btn = self.test_queue[0]

        # Inicia o timer de timeout de 5 segundos para a execução atual (Exceto para AFD e relatório que são longos)
        if test_type not in ["gerar_afd", "gerar_relatorio"]:
            self.test_timeout_timer.start(5000)

        if test_type == "gerar_relatorio":
            self.test_mode = test_type
            self.old_credentials = {
                "user": self.main_user_input.text(),
                "pass": self.main_password_input.text()
            }
            self.start_report_flow()
            return

        if self.tab_data["main_"]["connected"]:
            # Se já estiver conectado, pula o handshake e envia direto se for o mesmo usuário
            current_user = self.main_user_input.text()
            target_user = "rep" if test_type == "usuario_padrao" else "teste fabrica"

            if current_user != target_user:
                self.append_log(f"ABA TESTES (F5): Trocando usuário para {target_user}...")
                self.disconnect("main_")
                QTimer.singleShot(500, lambda: self._start_test_connection(test_type))
            else:
                self.test_mode = test_type # Garante que test_mode esteja setado antes de enviar
                if test_type == "gerar_afd":
                    self.start_afd_flow()
                else:
                    self._send_test_command(test_type)
        else:
            self._start_test_connection(test_type)

    def _start_test_connection(self, test_type):
        self.test_mode = test_type
        self.old_credentials = {
            "user": self.main_user_input.text(),
            "pass": self.main_password_input.text()
        }

        if test_type == "usuario_padrao":
            self.main_user_input.setText("rep")
            self.main_password_input.setText("123456")
        else:
            self.main_user_input.setText("teste fabrica")
            self.main_password_input.setText("111111")

        # Aciona conexão na aba F1
        self.on_connect_clicked()

    def _send_test_command(self, test_type):
        cmd = ""
        if test_type == "usuario_padrao":
            cmd = "01+ES+00+1+I[26571383063[teste fabrica[111111[525521[111111"
        elif test_type == "empregador":
            cmd = "01+EE+00+1]44880091000172]]EVO Sistemas Inteligentes LTDA]Rio Piquiri, 400"
        elif test_type == "colaborador":
            cmd = "01+EU+00+1+I[26571383063[Teste[0[2[1}4132669"
        
        if cmd:
            self.append_log(f"ABA TESTES (F5): Enviando comando para {test_type}...")
            QTimer.singleShot(500, lambda: self._send_raw_command("main_", cmd))

    def _calculate_afd_crc16(self, data):
        """Calcula o CRC-16 (Polynomial 0x8005/0xA001) para o cabeçalho do AFD."""
        crc = 0xFFFF
        if isinstance(data, str):
            data_bytes = data.encode('ascii', errors='ignore')
        else:
            data_bytes = data

        for byte in data_bytes:
            crc ^= byte
            for _ in range(8):
                if crc & 0x0001:
                    crc = (crc >> 1) ^ 0xA001
                else:
                    crc >>= 1
        return f"{crc:04X}"

    def _generate_afd_header(self):
        # 001-009: 000000000
        header = "000000000"
        # 010-010: 1 (Tipo do registro)
        header += "1"
        # 011-011: emp_type ("1": CNPJ; "2": CPF)
        header += str(self.afd_emp_type)
        # 012-025: CNPJ ou CPF do empregador (14 chars)
        header += self.afd_emp_id.ljust(14)[:14]
        # 026-039: Em branco (14 chars)
        header += " " * 14
        # 040-189: Razão social ou nome do empregador (150 chars)
        header += self.afd_emp_name.ljust(150)[:150]
        # 190-206: Número do rep (17 chars)
        header += self.afd_rep_num.ljust(17)[:17]
        # 207-216: Data inicial (AAAA-MM-DD)
        header += self.afd_first_date.ljust(10)[:10]
        # 217-226: Data final (AAAA-MM-DD)
        header += self.afd_last_date.ljust(10)[:10]
        # 227-250: Data e hora da geração (AAAA-MM-DDThh:mm:ss-0300)
        gen_dt = datetime.now().strftime("%Y-%m-%dT%H:%M:%S-0300")
        header += gen_dt.ljust(24)[:24]
        # 251-253: Versão 003
        header += "003"
        # 254-254: Fabricante tipo 1 (CNPJ)
        header += "1"
        # 255-268: CNPJ Fabricante
        header += "44880091000172".ljust(14)[:14]
        # 269-298: Modelo (30 chars)
        header += self.afd_rep_model.ljust(30)[:30]
        
        # CRC16 do registro (primeiros 298 caracteres)
        crc = self._calculate_afd_crc16(header)
        header += crc
        
        return header

    def start_afd_flow(self):
        self.afd_state = "HEADER"
        self.afd_collected = 0
        self.afd_nsr = 1
        self.afd_first_date = ""
        self.afd_last_date = ""
        self.afd_emp_id = ""
        self.afd_emp_type = "1"
        self.afd_emp_name = ""
        self.afd_rep_model = ""
        self.afd_count_2 = 0
        self.afd_count_3 = 0
        self.afd_count_4 = 0
        self.afd_count_5 = 0
        self.afd_count_6 = 0
        
        # Inicia a barra de progresso
        self.afd_progress_bar.setValue(0)
        self.afd_progress_bar.setVisible(True)
        self.afd_progress_bar.setFormat("Iniciando... %p%")

        self.append_log("ABA TESTES (F5): Iniciando extração de AFD...")
        self._send_raw_command("main_", "01+RC+00+NR_REP")

    def handle_afd_flow(self, text):
        if self.afd_state == "HEADER":
            if text.startswith("01+RC+000+NR_REP["):
                try:
                    # Extrai o número de 17 dígitos dentro dos colchetes
                    match = re.search(r"NR_REP\[(\d{17})\]", text)
                    if match:
                        self.afd_rep_num = match.group(1)
                    else:
                        self.afd_rep_num = "00000000000000001"
                    
                    self.append_log(f"ABA TESTES (F5): REP Num: {self.afd_rep_num}. Coletando modelo...")
                    self.afd_progress_bar.setFormat("Obtendo Modelo... %p%")
                    
                    self.afd_state = "MODEL"
                    self._send_raw_command("main_", "01+RC+00+MODELO")
                except Exception as e:
                    self._finish_current_test(f"Erro AFD: {e}", "#C0392B")
            else:
                self._finish_current_test("Erro AFD: Falha ao obter cabeçalho", "#C0392B")

        elif self.afd_state == "MODEL":
            if text.startswith("01+RC+000+MODELO["):
                try:
                    match = re.search(r"MODELO\[(.*?)\]", text)
                    if match:
                        self.afd_rep_model = match.group(1)
                    else:
                        self.afd_rep_model = "EVO REP-C"
                    
                    self.append_log(f"ABA TESTES (F5): Modelo: {self.afd_rep_model}. Coletando dados do empregador...")
                    self.afd_progress_bar.setFormat("Obtendo Empregador... %p%")
                    
                    # Prepara arquivo reservando espaço para o cabeçalho (302 bytes + \n)
                    filename = f"AFD{self.afd_rep_num}L.txt"
                    filepath = os.path.join(self.afd_save_path, filename)
                    self.afd_last_filepath = filepath
                    self.afd_current_file = open(filepath, "w", encoding="iso-8859-1", newline='\n')
                    self.afd_current_file.write(" " * 302 + "\n")
                    
                    self.afd_state = "EMPLOYER"
                    self._send_raw_command("main_", "01+RE+00")
                except Exception as e:
                    self._finish_current_test(f"Erro AFD: {e}", "#C0392B")
            else:
                self._finish_current_test("Erro AFD: Falha ao obter modelo", "#C0392B")

        elif self.afd_state == "EMPLOYER":
            if text.startswith("01+RE+000+"):
                try:
                    parts = text.split("]")
                    if len(parts) >= 4:
                        # 01+RE+000+1](CNPJouCPF)]              ]Razão social...]Local
                        self.afd_emp_id = parts[1].strip()
                        self.afd_emp_name = parts[3].strip()
                        # Detecta se é CPF (11) ou CNPJ (14)
                        self.afd_emp_type = "1" if len(self.afd_emp_id) == 14 else "2"
                    
                    self.append_log(f"ABA TESTES (F5): Empregador: {self.afd_emp_name}. Buscando quantidade de registros...")
                    self.afd_progress_bar.setFormat("Contando registros... %p%")

                    self.afd_state = "COUNT"
                    self._send_raw_command("main_", "01+RQ+00+R")
                except Exception as e:
                    self._finish_current_test(f"Erro AFD: {e}", "#C0392B")
            else:
                self._finish_current_test("Erro AFD: Falha ao obter dados do empregador", "#C0392B")

        elif self.afd_state == "COUNT":
            if text.startswith("01+RQ+000+R]"):
                try:
                    self.afd_total = int(text.split("]")[1])
                    self.append_log(f"ABA TESTES (F5): AFD Total: {self.afd_total} registros. Iniciando coleta...")
                    
                    if self.afd_total == 0:
                        self.afd_progress_bar.setMaximum(100)
                        self.afd_progress_bar.setValue(100)
                        self.afd_progress_bar.setFormat("Concluído (Vazio)")
                        self._finish_current_test("AFD Gerado (Equipamento vazio)", "#27AE60")
                        return

                    self.afd_progress_bar.setMaximum(self.afd_total)
                    self.afd_progress_bar.setValue(0)
                    self.afd_progress_bar.setFormat("Coletando: %v/%m (%p%)")

                    self.afd_state = "COLLECTING"
                    self._send_raw_command("main_", f"01+RR+00+N]80]{self.afd_nsr}")
                except Exception as e:
                    self._finish_current_test(f"Erro AFD: {e}", "#C0392B")
            else:
                self._finish_current_test("Erro AFD: Falha ao obter contagem", "#C0392B")

        elif self.afd_state == "COLLECTING":
            if text.startswith("01+RR+000+"):
                try:
                    header_part, data_part = text.split("]", 1)
                    passo = int(header_part.split("+")[-1])
                    
                    events = data_part.split("\n")
                    # Remove linhas vazias se houver
                    events = [e.strip() for e in events if e.strip()]
                    
                    for event in events:
                        # Captura data inicial e final (posições 11-20 -> index 10-20)
                        if len(event) >= 20:
                            dt = event[10:20]
                            if not self.afd_first_date:
                                self.afd_first_date = dt
                            self.afd_last_date = dt
                        
                        # Contagem de tipos para o trailer (Tipo 2 ao 6)
                        if len(event) >= 10:
                            tipo = event[9] # 10º caractere
                            if tipo == '2': self.afd_count_2 += 1
                            elif tipo == '3': self.afd_count_3 += 1
                            elif tipo == '4': self.afd_count_4 += 1
                            elif tipo == '5': self.afd_count_5 += 1
                            elif tipo == '6': self.afd_count_6 += 1

                        self.afd_current_file.write(event + "\n")
                        self.afd_collected += 1
                    
                    self.afd_nsr += passo
                    self.afd_progress_bar.setValue(self.afd_collected)
                    self.append_log(f"ABA TESTES (F5): Coletados {self.afd_collected}/{self.afd_total}...")

                    if self.afd_collected < self.afd_total and passo > 0:
                        self._send_raw_command("main_", f"01+RR+00+N]80]{self.afd_nsr}")
                    else:
                        self.afd_progress_bar.setValue(self.afd_total)
                        self._finish_current_test("AFD Gerado com Sucesso", "#27AE60")
                except Exception as e:
                    self._finish_current_test(f"Erro AFD: {e}", "#C0392B")
            else:
                self._finish_current_test("Erro AFD: Falha na coleta de eventos", "#C0392B")

    def _finish_current_test(self, msg, color):
        # Para o timer de timeout
        self.test_timeout_timer.stop()
        
        # Esconde a barra de progresso após um curto delay se for AFD
        if self.test_mode == "gerar_afd":
            QTimer.singleShot(2000, lambda: self.afd_progress_bar.setVisible(False))

        # Fecha arquivo se estiver aberto
        if self.afd_current_file:
            # Grava o trailer se o AFD foi gerado com sucesso
            if msg == "AFD Gerado com Sucesso":
                trailer = f"999999999{self.afd_count_2:09d}{self.afd_count_3:09d}{self.afd_count_4:09d}{self.afd_count_5:09d}{self.afd_count_6:09d}0000000009"
                trailer = trailer.ljust(64, ' ')
                self.afd_current_file.write(trailer + "\n")

            self.afd_current_file.close()
            self.afd_current_file = None

        # Se AFD gerado com sucesso, grava o cabeçalho final no topo reservado
        if msg == "AFD Gerado com Sucesso" and hasattr(self, 'afd_last_filepath'):
            try:
                header = self._generate_afd_header()
                # Reabre o arquivo em modo leitura/escrita para gravar o cabeçalho no seek(0)
                with open(self.afd_last_filepath, "r+", encoding="utf-8", newline='\n') as f:
                    f.seek(0)
                    f.write(header)
            except Exception as e:
                self.append_log(f"ABA TESTES (F5): Erro ao gravar cabeçalho final: {e}")

        # Log do resultado
        self.append_log(f"ABA TESTES (F5): {msg}")

        # Mostra o card de notificação com a cor específica
        if msg:
            NotificationCard(self, msg, color)
            
            # REQUISITO: Se AFD gerado com sucesso, abre o arquivo
            if msg == "AFD Gerado com Sucesso" and hasattr(self, 'afd_last_filepath'):
                try:
                    os.startfile(self.afd_last_filepath)
                except:
                    pass
        
        # Restaura o botão correspondente
        if self.test_queue:
            test_type, btn = self.test_queue.pop(0)
            orig = btn.property("original_text")
            btn.setText(orig)
            btn.setEnabled(True)
            
            # Se a fila esvaziou totalmente, para a animação
            if not self.test_queue:
                self.loading_timer.stop()

        self.test_mode = None
        self.disconnect("main_")
        self.main_user_input.setText(self.old_credentials.get("user", ""))
        self.main_password_input.setText(self.old_credentials.get("pass", ""))
        
        # Próximo teste na fila
        QTimer.singleShot(500, self.run_next_test)

    def on_test_timeout(self):
        if self.is_test_running:
            self.append_log("ABA TESTES (F5): Tempo esgotado (5s).")
            self._finish_current_test("Erro ao Cadastrar", "#C0392B")

    def handle_test_response(self, text):
        if self.test_mode == "gerar_afd":
            self.handle_afd_flow(text)
            return

        msg = ""
        color = "#C0392B" # Vermelho padrão (Erro)
        
        if self.test_mode == "usuario_padrao":
            if text.startswith("01+ES+000+1+0"):
                msg = "Usuário Padrão Cadastrado com Sucesso"
                color = "#27AE60" # Verde Sucesso
            elif text.startswith("01+ES+000+1+23"):
                msg = "Usuário Padrão já Cadastrado Anteriormente"
                color = "#E67E22" # Laranja (Já cadastrado)
            else:
                msg = "Erro ao Cadastrar Usuário Padrão"
        elif self.test_mode == "empregador":
            if text.startswith("01+EE+000"):
                msg = "Empregador Cadastrado com Sucesso"
                color = "#27AE60"
            else:
                msg = "Erro ao Cadastrar Empregador"
        elif self.test_mode == "colaborador":
            if text.startswith("01+EU+000+1+0"):
                msg = "Colaborador Cadastrado com Sucesso"
                color = "#27AE60"
            else:
                msg = "Erro ao Cadastrar Colaborador"

        if msg:
            self._finish_current_test(msg, color)
        else:
            # Fallback para resposta desconhecida para não travar a UI
            self._finish_current_test(f"Resposta Inesperada: {text[:20]}...", "#C0392B")

    def start_report_flow(self):
        from workers import ReportWorker
        self.is_report_running = True
        self.update_dependent_tabs_state()

        self.report_progress_bar.setVisible(True)
        self.report_progress_bar.setValue(0)
        self.report_progress_bar.setFormat("Iniciando Relatório... %p%")

        ip = self.test_ip_input.text().strip()
        port = int(self.test_port_input.text().strip())
        # Usa usuário fixo conforme requisito ou pega do input de teste
        user = "teste fabrica"
        password = "111111"

        self.append_log(f"ABA TESTES (F5): Iniciando Geração de Relatório em {ip}:{port}...")

        self.report_worker = ReportWorker(ip, port, user, password, self.report_save_path)
        self.report_worker.log_signal.connect(lambda msg: self.append_log(f"RELATÓRIO: {msg}"))
        self.report_worker.progress_signal.connect(self._on_report_progress)
        self.report_worker.entry_signal.connect(self._on_report_entry)
        self.report_worker.finished_signal.connect(self._on_report_finished)
        self.report_worker.start()

    def _on_report_progress(self, current, total):
        self.report_progress_bar.setMaximum(total)
        self.report_progress_bar.setValue(current)
        self.report_progress_bar.setFormat(f"Executando: {current}/{total} (%p%)")

    def _on_report_entry(self, label, sent, received):
        self.append_log(f"RELATÓRIO {label} -> {sent}")

    def _on_report_finished(self, success, result_or_error):
        self.is_report_running = False
        self.update_dependent_tabs_state()

        QTimer.singleShot(2000, lambda: self.report_progress_bar.setVisible(False))

        if success:
            self.append_log(f"ABA TESTES (F5): Relatório gerado com sucesso em {result_or_error}")
            NotificationCard(self, "Relatório Gerado com Sucesso", "#27AE60")
            try:
                import os
                os.startfile(result_or_error)
            except:
                pass
            self._finish_current_test("Relatório Gerado com Sucesso", "#27AE60")
        else:
            self.append_log(f"ABA TESTES (F5): Falha ao gerar relatório: {result_or_error}")
            NotificationCard(self, "Falha ao Gerar Relatório", "#C0392B")
            self._finish_current_test("Erro ao Gerar Relatório", "#C0392B")

    def _send_raw_command(self, prefix, command_str):
        state = self.tab_data[prefix]
        if not state["persistent_sock"]: return

        getattr(self, f"{prefix}send_button").setEnabled(False)
        self.command_worker = CommandWorker(state["persistent_sock"], command_str, state["session_key"])
        self.command_worker.sent_signal.connect(lambda txt: self.append_sent(txt, prefix))
        self.command_worker.sent_bytes_signal.connect(lambda hex_txt: self.append_sent_bytes(hex_txt, prefix))
        self.command_worker.finished_signal.connect(self.on_send_command_finished)
        self.command_worker.start()

    # ──────────────────────────────────────────────────────────────────
    #  HELPERS DE ABA ATIVA  (inalterados)
    # ──────────────────────────────────────────────────────────────────

    def _get_active_prefix(self):
        idx = self.stacked_widget.currentIndex()
        if idx == 0: return "main_"
        if idx == 2: return "client_"
        if idx == 3: return "f3_"
        if idx == 4: return "test_"
        return "main_"

    def _get_widget(self, name):
        prefix = self._get_active_prefix()
        return getattr(self, f"{prefix}{name}")

    # ──────────────────────────────────────────────────────────────────
    #  SELEÇÃO E CONSTRUÇÃO DINÂMICA DE PARÂMETROS  (inalterada)
    # ──────────────────────────────────────────────────────────────────

    def on_command_selected(self, index):
        prefix = self._get_active_prefix()
        if prefix == "test_":
            return

        dynamic_layout    = getattr(self, f"{prefix}dynamic_layout")
        command_combo     = getattr(self, f"{prefix}command_combo")
        cmd_description_label = getattr(self, f"{prefix}cmd_description_label")

        while dynamic_layout.rowCount() > 0:
            dynamic_layout.removeRow(0)
        self.param_inputs.clear()

        cmd_code = command_combo.currentData()

    def setup_ec_categories(self, dynamic_layout):
        from constants import EC_CATEGORIES
        
        # 1. ComboBox de Categorias
        cat_combo = NoScrollComboBox()
        cat_combo.addItem("Selecione uma categoria...", None)
        for cat in EC_CATEGORIES.keys():
            cat_combo.addItem(cat)
        
        dynamic_layout.addRow("Categoria:", cat_combo)
        
        # 2. ComboBox de Comandos (Oculto inicialmente)
        self.ec_cmd_label = QLabel("Comando:")
        self.ec_cmd_combo = NoScrollComboBox()
        self.ec_cmd_label.setVisible(False)
        self.ec_cmd_combo.setVisible(False)
        dynamic_layout.addRow(self.ec_cmd_label, self.ec_cmd_combo)
        
        def update_cmd_list(cat_name):
            self.ec_cmd_combo.clear()
            if cat_name in EC_CATEGORIES:
                self.ec_cmd_label.setVisible(True)
                self.ec_cmd_combo.setVisible(True)
                # Adiciona cada comando com seu valor como DATA também
                for cmd in EC_CATEGORIES[cat_name]:
                    self.ec_cmd_combo.addItem(cmd, cmd) 
                
                # Força a atualização do campo de valor para o primeiro item da lista
                self.update_ec_valor_field()
            else:
                self.ec_cmd_label.setVisible(False)
                self.ec_cmd_combo.setVisible(False)
                self.update_ec_valor_field() 
                    
        cat_combo.currentTextChanged.connect(update_cmd_list)
        # Conecta a mudança de texto para atualizar o campo de valor
        self.ec_cmd_combo.currentTextChanged.connect(self.update_ec_valor_field)
        
        self.param_inputs["EC_Categoria"] = cat_combo
        self.param_inputs["Configuração"] = self.ec_cmd_combo 

    def setup_rc_categories(self, dynamic_layout):
        from constants import RC_CATEGORIES
        
        # 1. ComboBox de Categorias
        cat_combo = NoScrollComboBox()
        cat_combo.addItem("Selecione uma categoria...", None)
        for cat in RC_CATEGORIES.keys():
            cat_combo.addItem(cat)
            
        dynamic_layout.addRow("Categoria:", cat_combo)
        
        # 2. Criar todos os checkboxes (ocultos inicialmente)
        cmd_def = COMMANDS_REGISTRY["RC"]
        config_param = next(p for p in cmd_def.params if p.name == "Configuração")
        
        checkboxes = []
        cb_map = {}
        
        for choice in config_param.choices:
            cb = QCheckBox(choice['label'])
            cb.setProperty("value", choice['value'])
            cb.setVisible(False)
            dynamic_layout.addRow("", cb)
            
            # Como passamos "" como string, o QFormLayout cria automaticamente um QLabel
            label_widget = dynamic_layout.labelForField(cb)
            if label_widget:
                label_widget.setVisible(False)
                
            checkboxes.append(cb)
            cb_map[choice['value']] = cb
            
        def update_rc_checkboxes(cat_name):
            # Esconde e desmarca todos os checkboxes
            for cb in checkboxes:
                cb.setVisible(False)
                cb.setChecked(False)
                label_widget = dynamic_layout.labelForField(cb)
                if label_widget:
                    label_widget.setVisible(False)
            
            # Mostra apenas os checkboxes da categoria selecionada
            if cat_name in RC_CATEGORIES:
                allowed_values = RC_CATEGORIES[cat_name]
                for val in allowed_values:
                    if val in cb_map:
                        cb = cb_map[val]
                        cb.setVisible(True)
                        label_widget = dynamic_layout.labelForField(cb)
                        if label_widget:
                            label_widget.setVisible(True)
                            
        cat_combo.currentTextChanged.connect(update_rc_checkboxes)
        
        self.param_inputs["RC_Categoria"] = cat_combo
        self.param_inputs["Configuração"] = checkboxes


    # Removed clear_ec_valor_field as its logic is now integrated into update_ec_valor_field
    # def clear_ec_valor_field(self, dynamic_layout):
    #     old_valor_widget = self.param_inputs.get("Valor")
    #     if old_valor_widget:
    #         dynamic_layout.removeRow(old_valor_widget)
    #         if "Valor" in self.param_inputs:
    #             del self.param_inputs["Valor"]


    def on_command_selected(self, index):
        prefix = self._get_active_prefix()
        if prefix == "test_":
            return

        dynamic_layout    = getattr(self, f"{prefix}dynamic_layout")
        command_combo     = getattr(self, f"{prefix}command_combo")
        cmd_description_label = getattr(self, f"{prefix}cmd_description_label")

        while dynamic_layout.rowCount() > 0:
            dynamic_layout.removeRow(0)
        self.param_inputs.clear()

        cmd_code = command_combo.currentData()

        # 🔹 LÓGICA DE CATEGORIAS PARA EC
        if cmd_code == "EC":
            cmd_def = COMMANDS_REGISTRY["EC"]
            cmd_description_label.setText(cmd_def.description)
            self.setup_ec_categories(dynamic_layout)
            return

        # 🔹 LÓGICA DE CATEGORIAS PARA RC
        if cmd_code == "RC":
            cmd_def = COMMANDS_REGISTRY["RC"]
            cmd_description_label.setText(cmd_def.description)
            self.setup_rc_categories(dynamic_layout)
            return


        if cmd_code is None:
            cmd_description_label.setText("Modo Manual: Digite a string bruta do comando para enviá-la diretamente.")
            self.manual_input = QLineEdit(self.last_manual_command)
            self.manual_input.installEventFilter(self)
            self.manual_input.returnPressed.connect(self.on_enter_pressed)
            dynamic_layout.addRow("Comando:", self.manual_input)
            self.param_inputs["_manual"] = self.manual_input
        else:
            cmd_def = COMMANDS_REGISTRY[cmd_code]
            cmd_description_label.setText(cmd_def.description)
            # ... rest of the original logic
            pending_data_field = None
            pending_data_label = None

            for param in cmd_def.params:
                label_text = f"{param.name} {'' if param.required else '(opcional)'}:"

                if param.choices:
                    input_field = NoScrollComboBox()
                    for choice in param.choices:
                        input_field.addItem(choice['label'], choice['value'])
                    dynamic_layout.addRow(label_text, input_field)
                    self.param_inputs[param.name] = input_field

                    if cmd_code == "EC" and param.name == "Configuração":
                        input_field.currentIndexChanged.connect(self.update_ec_valor_field)
                    elif cmd_code == "RR" and param.name == "Tipo":
                        input_field.currentIndexChanged.connect(self.update_rr_fields)
                    elif cmd_code == "RU" and param.name == "Tipo":
                        input_field.currentIndexChanged.connect(self.update_ru_fields)
                    elif cmd_code == "ED" and param.name == "Operação":
                        input_field.currentIndexChanged.connect(self.update_ed_fields)
                    elif cmd_code == "RD" and param.name == "Operação":
                        input_field.currentIndexChanged.connect(self.update_rd_fields)
                    continue
                else:
                    input_field = QLineEdit(str(param.default))
                    input_field.setPlaceholderText(param.description)
                    input_field.returnPressed.connect(self.on_enter_pressed)

                    if param.name.lower() == "data" or "dd/mm/aa" in param.description.lower():
                        if "aaaa" in param.description.lower():
                            input_field.setInputMask("99/99/9999;_")
                            input_field.setText(time.strftime("%d/%m/%Y"))
                        else:
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
                    hbox.setSpacing(6)
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
            elif cmd_code == "RU":
                self.update_ru_fields()
            elif cmd_code == "ED":
                self.update_ed_fields()
            elif cmd_code == "RD":
                self.update_rd_fields()

    def update_ec_valor_field(self):
        """Atualiza o campo 'Valor' do comando EC com base na 'Configuração' selecionada."""
        prefix = self._get_active_prefix()
        dynamic_layout = getattr(self, f"{prefix}dynamic_layout")
        config_combo   = self.param_inputs.get("Configuração") # This is self.ec_cmd_combo
        if not config_combo: return

        config_key = config_combo.currentData()

        # Sempre remove a linha 'Valor' existente antes de adicionar uma nova
        # Percorre as linhas de trás para frente para remover com segurança
        for i in range(dynamic_layout.rowCount() - 1, -1, -1):
            # No PyQt6, o acesso ao enum é via QFormLayout.ItemRole
            label_item = dynamic_layout.itemAt(i, QFormLayout.ItemRole.LabelRole)
            if label_item and label_item.widget():
                label_widget = label_item.widget()
                if isinstance(label_widget, QLabel) and label_widget.text() in ["Valor:", "Valor (opcional):"]:
                    dynamic_layout.removeRow(i)
                    if "Valor" in self.param_inputs:
                        del self.param_inputs["Valor"]
                    break

        if config_key is None:
            return

        choices = EC_VAL_CHOICES.get(config_key)

        new_input = None
        if choices:
            new_input = NoScrollComboBox()
            for c in choices:
                new_input.addItem(c['label'], c['value'])
        else:
            new_input = QLineEdit()
            # ... (placeholders logic remains same)
            if config_key == "LOGIN":         new_input.setPlaceholderText("Máx 16 caracteres")
            elif config_key == "SENHA_MENU":  new_input.setPlaceholderText("6 dígitos")
            elif config_key == "MENSAGEM":    new_input.setPlaceholderText("Máx 20 caracteres")
            elif config_key == "ACORDO_SIND": new_input.setPlaceholderText("17 dígitos")
            elif config_key == "TAM_BOB":     new_input.setPlaceholderText("0 ~ 400")
            elif config_key == "TEMPO_LIB":   new_input.setPlaceholderText("0 ~ 60")
            elif config_key == "NTP_TIMEOUT": new_input.setPlaceholderText("1 ~ 99")
            elif any(x in str(config_key) for x in ["IP", "DNS", "GATEWAY", "SERVER_IP"]):
                new_input.setPlaceholderText("Ex: 192.168.1.100")
            elif "PORTA" in str(config_key) or "SERVER_PORT" in str(config_key):
                new_input.setPlaceholderText("1000 ~ 65535")
            else:
                new_input.setPlaceholderText(f"Valor para {config_key}")

        if new_input:
            if hasattr(new_input, "returnPressed"):
                new_input.returnPressed.connect(self.on_enter_pressed)
            
            if isinstance(new_input, QLineEdit) and any(x in str(config_key) for x in ["IP", "DNS", "GATEWAY", "SERVER_IP"]):
                new_input.editingFinished.connect(lambda: self._normalize_ip_field(new_input))

            label_text = "Valor (opcional):" if config_key == "MENSAGEM" else "Valor:"
            dynamic_layout.addRow(label_text, new_input)
            self.param_inputs["Valor"] = new_input


    def update_rd_fields(self):
        """Atualiza os campos do comando RD com base na 'Operação' selecionada."""
        prefix = self._get_active_prefix()
        dynamic_layout  = getattr(self, f"{prefix}dynamic_layout")
        operacao_combo  = self.param_inputs.get("Operação")
        if not operacao_combo: return

        sub_cmd_code = operacao_combo.currentData()
        sub_cmd_def  = COMMANDS_REGISTRY.get(sub_cmd_code)

        while dynamic_layout.rowCount() > 1:
            dynamic_layout.removeRow(1)

        keys_to_remove = [k for k in self.param_inputs.keys() if k not in ["Operação", "_manual"]]
        for k in keys_to_remove:
            del self.param_inputs[k]

        if not sub_cmd_def: return

        if sub_cmd_code == "RD_LISTA":
            radio_widget = QWidget()
            radio_layout = QHBoxLayout(radio_widget)
            radio_layout.setContentsMargins(0, 0, 0, 0)
            unica_radio = QRadioButton("ÚNICA")
            unica_radio.setChecked(True)
            dual_radio  = QRadioButton("DUAL")
            radio_group = QButtonGroup(self)
            radio_group.addButton(unica_radio)
            radio_group.addButton(dual_radio)
            self.param_inputs["ListaTipo"] = radio_group
            radio_layout.addWidget(unica_radio)
            radio_layout.addWidget(dual_radio)
            dynamic_layout.addRow("Tipo:", radio_widget)

            for param in sub_cmd_def.params:
                input_field = QLineEdit(str(param.default))
                input_field.setPlaceholderText(param.description)
                input_field.returnPressed.connect(self.on_enter_pressed)
                dynamic_layout.addRow(f"{param.name}:", input_field)
                self.param_inputs[param.name] = input_field

        elif sub_cmd_code == "RD_TEMPLATE":
            radio_widget = QWidget()
            radio_layout = QVBoxLayout(radio_widget)
            radio_layout.setContentsMargins(0, 0, 0, 0)
            suprema_radio  = QRadioButton("Suprema")
            suprema_radio.setChecked(True)
            evobio_radio   = QRadioButton("EVO BIO")
            evoface_radio  = QRadioButton("EVO FACE")
            facecorp_radio = QRadioButton("FACE CORP")

            radio_group = QButtonGroup(self)
            radio_group.addButton(suprema_radio)
            radio_group.addButton(evobio_radio)
            radio_group.addButton(evoface_radio)
            radio_group.addButton(facecorp_radio)
            self.param_inputs["TemplateModelo"] = radio_group

            radio_layout.addWidget(suprema_radio)
            radio_layout.addWidget(evobio_radio)
            radio_layout.addWidget(evoface_radio)
            radio_layout.addWidget(facecorp_radio)
            dynamic_layout.addRow("Modelo:", radio_widget)

            for param in sub_cmd_def.params:
                input_field = QLineEdit(str(param.default))
                input_field.setPlaceholderText(param.description)
                input_field.returnPressed.connect(self.on_enter_pressed)
                dynamic_layout.addRow(f"{param.name}:", input_field)
                self.param_inputs[param.name] = input_field

            def on_template_radio_changed():
                selected    = radio_group.checkedButton().text()
                index_field = self.param_inputs.get("Index")
                if index_field:
                    index_field.setEnabled(selected in ["EVO BIO", "EVO FACE"])

            suprema_radio.toggled.connect(on_template_radio_changed)
            evobio_radio.toggled.connect(on_template_radio_changed)
            evoface_radio.toggled.connect(on_template_radio_changed)
            facecorp_radio.toggled.connect(on_template_radio_changed)
            on_template_radio_changed()

        else:
            for param in sub_cmd_def.params:
                input_field = QLineEdit(str(param.default))
                input_field.setPlaceholderText(param.description)
                input_field.returnPressed.connect(self.on_enter_pressed)
                dynamic_layout.addRow(f"{param.name}:", input_field)
                self.param_inputs[param.name] = input_field

    def update_rr_fields(self):
        """Atualiza os campos secundários do comando RR com base no 'Tipo' selecionado."""
        prefix = self._get_active_prefix()
        dynamic_layout = getattr(self, f"{prefix}dynamic_layout")
        tipo_combo     = self.param_inputs.get("Tipo")
        if not tipo_combo: return

        sub_cmd_code = tipo_combo.currentData()
        sub_cmd_def  = COMMANDS_REGISTRY.get(sub_cmd_code)

        while dynamic_layout.rowCount() > 1:
            dynamic_layout.removeRow(1)

        keys_to_remove = [k for k in self.param_inputs.keys() if k not in ["Tipo", "_manual"]]
        for k in keys_to_remove:
            del self.param_inputs[k]

        if not sub_cmd_def: return

        pending_data_field = None
        pending_data_label = None

        for param in sub_cmd_def.params:
            label_text  = f"{param.name} {'' if param.required else '(opcional)'}:"
            input_field = QLineEdit(str(param.default))
            input_field.setPlaceholderText(param.description)
            input_field.returnPressed.connect(self.on_enter_pressed)

            if param.name.lower() == "data" or "dd/mm/aa" in param.description.lower():
                if "aaaa" in param.description.lower():
                    input_field.setInputMask("99/99/9999;_")
                    input_field.setText(time.strftime("%d/%m/%Y"))
                else:
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
                hbox.setSpacing(6)
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

    def update_ru_fields(self):
        """Atualiza os campos secundários do comando RU com base no 'Tipo' selecionado."""
        prefix = self._get_active_prefix()
        dynamic_layout = getattr(self, f"{prefix}dynamic_layout")
        tipo_combo     = self.param_inputs.get("Tipo")
        if not tipo_combo: return

        sub_cmd_code = tipo_combo.currentData()
        sub_cmd_def  = COMMANDS_REGISTRY.get(sub_cmd_code)

        while dynamic_layout.rowCount() > 1:
            dynamic_layout.removeRow(1)

        keys_to_remove = [k for k in self.param_inputs.keys() if k not in ["Tipo", "_manual"]]
        for k in keys_to_remove:
            del self.param_inputs[k]

        if not sub_cmd_def: return

        for param in sub_cmd_def.params:
            label_text  = f"{param.name} {'' if param.required else '(opcional)'}:"
            input_field = QLineEdit(str(param.default))
            input_field.setPlaceholderText(param.description)
            input_field.returnPressed.connect(self.on_enter_pressed)
            dynamic_layout.addRow(label_text, input_field)
            self.param_inputs[param.name] = input_field

    def update_ed_fields(self):
        """Atualiza os campos secundários do comando ED com base na 'Operação' selecionada."""
        prefix = self._get_active_prefix()
        dynamic_layout = getattr(self, f"{prefix}dynamic_layout")
        operacao_combo = self.param_inputs.get("Operação")
        if not operacao_combo: return

        sub_cmd_code = operacao_combo.currentData()
        sub_cmd_def  = COMMANDS_REGISTRY.get(sub_cmd_code)

        while dynamic_layout.rowCount() > 1:
            dynamic_layout.removeRow(1)

        keys_to_remove = [k for k in self.param_inputs.keys() if k not in ["Operação", "_manual"]]
        for k in keys_to_remove:
            del self.param_inputs[k]

        if not sub_cmd_def: return

        if sub_cmd_code == "ED_CADASTRAR":
            bio_widget = QWidget()
            bio_layout = QHBoxLayout(bio_widget)
            bio_layout.setContentsMargins(0, 0, 0, 0)
            bio_layout.setSpacing(10)

            digital_radio = QRadioButton("Digital")
            digital_radio.setChecked(True)
            facial_radio  = QRadioButton("Facial")

            bio_group = QButtonGroup(self)
            bio_group.addButton(digital_radio)
            bio_group.addButton(facial_radio)
            self.param_inputs["BiometriaTipo"] = bio_group

            bio_layout.addWidget(digital_radio)
            bio_layout.addWidget(facial_radio)
            dynamic_layout.addRow("Biometria:", bio_widget)

            input_field = QLineEdit("")
            input_field.setPlaceholderText("Matrícula do colaborador")
            input_field.returnPressed.connect(self.on_enter_pressed)
            dynamic_layout.addRow("Matrícula:", input_field)
            self.param_inputs["Matricula"] = input_field

        elif sub_cmd_code == "ED_SUPREMA":
            input_field = QLineEdit("")
            input_field.setPlaceholderText("Matrícula do colaborador")
            input_field.returnPressed.connect(self.on_enter_pressed)
            dynamic_layout.addRow("Matrícula:", input_field)
            self.param_inputs["Matricula"] = input_field

            tp_grid_container = QWidget()
            tp_grid_layout = QGridLayout(tp_grid_container)
            tp_grid_layout.setContentsMargins(0, 0, 0, 0)
            tp_grid_layout.setSpacing(5)

            self.suprema_tp_inputs = []
            for i in range(1, 11):
                tp_field = QLineEdit()
                tp_field.setPlaceholderText(f"TP{i}")
                tp_field.returnPressed.connect(self.on_enter_pressed)
                tp_field.setMaxLength(10000)
                tp_field.setMinimumWidth(80)

                row = (i - 1) // 5
                col = (i - 1) % 5

                tp_grid_layout.addWidget(tp_field, row, col)
                self.suprema_tp_inputs.append(tp_field)
                self.param_inputs[f"TP{i}"] = tp_field

            dynamic_layout.addRow("Templates:", tp_grid_container)

        elif sub_cmd_code in ["ED_BIO_AZUL", "ED_FACE", "ED_FACE_CORP"]:
            input_field = QLineEdit("")
            input_field.setPlaceholderText("Matrícula do colaborador")
            input_field.returnPressed.connect(self.on_enter_pressed)
            dynamic_layout.addRow("Matrícula:", input_field)
            self.param_inputs["Matricula"] = input_field

            if sub_cmd_code == "ED_FACE":
                index_field = QLineEdit("0")
                index_field.setPlaceholderText("Index (0~7)")
                index_field.returnPressed.connect(self.on_enter_pressed)
                dynamic_layout.addRow("Index (0~7):", index_field)
                self.param_inputs["Index"] = index_field

            tp_field = QLineEdit("")
            tp_field.setPlaceholderText("Cole o template aqui")
            tp_field.returnPressed.connect(self.on_enter_pressed)
            tp_field.setMaxLength(20000)
            dynamic_layout.addRow("Template (TP1):", tp_field)
            self.param_inputs["TP1"] = tp_field

        else:
            for param in sub_cmd_def.params:
                label_text  = f"{param.name} {'' if param.required else '(opcional)'}:"
                input_field = QLineEdit(str(param.default))
                input_field.setPlaceholderText(param.description)
                input_field.returnPressed.connect(self.on_enter_pressed)
                dynamic_layout.addRow(label_text, input_field)
                self.param_inputs[param.name] = input_field

    # ──────────────────────────────────────────────────────────────────
    #  EVENT FILTER (histórico de comandos manuais)  — inalterado
    # ──────────────────────────────────────────────────────────────────

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

    # ──────────────────────────────────────────────────────────────────
    #  ENVIO DE COMANDO  (inalterado)
    # ──────────────────────────────────────────────────────────────────

    def on_send_command_clicked(self):
        prefix = self._get_active_prefix()
        if prefix == "test_":
            prefix = "main_"
        state  = self.tab_data[prefix]

        if not state["persistent_sock"]:
            self.append_log(f"Erro: Socket não disponível na aba {prefix}. Conecte primeiro.")
            return

        command_combo = self._get_widget("command_combo")
        cmd_code      = command_combo.currentData()

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
            elif cmd_code == "RU":
                cmd_code = self.param_inputs["Tipo"].currentData()
            elif cmd_code == "ED":
                cmd_code = self.param_inputs["Operação"].currentData()
            elif cmd_code == "RD":
                cmd_code = self.param_inputs["Operação"].currentData()

            cmd_def     = COMMANDS_REGISTRY[cmd_code]
            kwargs      = {}
            command_str = None

            if cmd_code.startswith("ED_"):
                matricula = self.param_inputs.get("Matricula")
                if matricula:
                    mat_val = matricula.text().strip()
                    if not mat_val:
                        QMessageBox.warning(self, "Aviso", "Preencha a matrícula antes de enviar.")
                        return
                    kwargs["Matricula"] = mat_val
                else:
                    QMessageBox.warning(self, "Aviso", "Campo de matrícula não encontrado.")
                    return

                if cmd_code == "ED_CADASTRAR":
                    bio_group = self.param_inputs.get("BiometriaTipo")
                    if bio_group and isinstance(bio_group, QButtonGroup):
                        selected_button = bio_group.checkedButton()
                        bio_mode = "F" if selected_button and selected_button.text() == "Facial" else "D"
                    else:
                        bio_mode = "D"
                    command_str = f"01+ED+00+R]{bio_mode}}}{mat_val}"

                elif cmd_code == "ED_SUPREMA":
                    tp_parts = []
                    count = 0
                    for i in range(1, 11):
                        tp_field = self.param_inputs.get(f"TP{i}")
                        if tp_field and tp_field.text().strip():
                            count += 1
                            tp_val = tp_field.text().strip()
                            tp_parts.append(f"{i}{{{tp_val}")

                    if tp_parts:
                        command_str = f"01+ED+00+D]{mat_val}}}{count}}}" + "".join(tp_parts)
                    else:
                        QMessageBox.warning(self, "Aviso", "Nenhum template preenchido.")
                        return

                elif cmd_code == "ED_BIO_AZUL":
                    tp_val = self.param_inputs.get("TP1").text().strip()
                    if not tp_val:
                        QMessageBox.warning(self, "Aviso", "Preencha o template.")
                        return
                    command_str = f"01+ED+00+T]{mat_val}}}K}}B}}0}}00810{{{tp_val}"

                elif cmd_code == "ED_FACE":
                    tp_val = self.param_inputs.get("TP1").text().strip()
                    idx_val = self.param_inputs.get("Index").text().strip() if self.param_inputs.get("Index") else "0"
                    if not tp_val:
                        QMessageBox.warning(self, "Aviso", "Preencha o template.")
                        return
                    command_str = f"01+ED+00+T]{mat_val}}}R}}B}}{idx_val}}}02048{{{tp_val}"

                elif cmd_code == "ED_FACE_CORP":
                    tp_val = self.param_inputs.get("TP1").text().strip()
                    if not tp_val:
                        QMessageBox.warning(self, "Aviso", "Preencha o template.")
                        return
                    command_str = f"01+ED+00+T]{mat_val}}}X}}B}}0}}01072{{{tp_val}"

                else:
                    command_str = cmd_def.build(**kwargs)

            elif cmd_code.startswith("RD_"):
                if cmd_code == "RD_LISTA":
                    radio_group = self.param_inputs.get("ListaTipo")
                    is_dual     = radio_group and radio_group.checkedButton().text() == "DUAL"
                    qty         = self.param_inputs.get("Quantidade").text().strip()
                    idx         = self.param_inputs.get("Indice").text().strip()
                    
                    if is_dual:
                        command_str = [
                            f"01+RD+00+L]D]{qty}}}{idx}",
                            f"01+RD+00+L]F]{qty}}}{idx}"
                        ]
                    else:
                        command_str = f"01+RD+00+L]{qty}}}{idx}"
                elif cmd_code == "RD_QTD":
                    mat         = self.param_inputs.get("Matricula").text().strip()
                    command_str = f"01+RD+00+Q]{mat}"
                elif cmd_code == "RD_TEMPLATE":
                    radio_group = self.param_inputs.get("TemplateModelo")
                    modelo      = radio_group.checkedButton().text()
                    mat         = self.param_inputs.get("Matricula").text().strip()
                    idx         = self.param_inputs.get("Index").text().strip()

                    if modelo == "Suprema":
                        command_str = f"01+RD+00+D]{mat}"
                    elif modelo == "EVO BIO":
                        command_str = f"01+RD+00+T]{mat}}}K}}B}}{idx}"
                    elif modelo == "EVO FACE":
                        command_str = f"01+RD+00+T]{mat}}}R}}B}}{idx}"
                    elif modelo == "FACE CORP":
                        command_str = f"01+RD+00+T]{mat}}}X}}B}}0"
            else:
                for param_name, input_field in self.param_inputs.items():
                    if isinstance(input_field, list):
                        selected_values = [cb.property("value") for cb in input_field if cb.isChecked()]
                        val = "]".join(selected_values)
                    elif isinstance(input_field, QButtonGroup):
                        selected_button = input_field.checkedButton()
                        val = selected_button.text() if selected_button else ""
                    elif isinstance(input_field, QComboBox):
                        val = input_field.currentData()
                    else:
                        val = input_field.text().strip()
                    if cmd_code == "EU":
                        if param_name == "Matrícula2" and val: val = "}" + val
                        elif param_name == "Senha" and val:    val = "[" + val
                    kwargs[param_name] = val

                # 🔹 REQUISITO: Detecção automática de Tipo para o comando EE
                if cmd_code == "EE":
                    id_val = str(kwargs.get("ID", "")).replace(".", "").replace("-", "").replace("/", "").strip()
                    if len(id_val) == 14:
                        kwargs["Tipo"] = "1"
                    elif len(id_val) == 11:
                        kwargs["Tipo"] = "2"
                    kwargs["ID"] = id_val

                # 🔹 REQUISITO: Valor opcional apenas para MENSAGEM no comando EC
                if cmd_code == "EC":
                    if kwargs.get("Configuração") != "MENSAGEM" and not kwargs.get("Valor"):
                        QMessageBox.warning(self, "Erro de Validação", "O campo 'Valor' é obrigatório para esta configuração.")
                        return

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

    # ──────────────────────────────────────────────────────────────────
    #  ATALHOS DE TECLADO  (inalterados)
    # ──────────────────────────────────────────────────────────────────

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
        elif event.key() == Qt.Key.Key_F5:
            self.stacked_widget.setCurrentIndex(4)
        elif event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            self.on_enter_pressed()
        else:
            super().keyPressEvent(event)

    def on_enter_pressed(self):
        prefix = self._get_active_prefix()
        # REQUISITO: Ignora Enter na aba F5 (test_)
        if prefix == "test_":
            return

        if prefix == "main_":
            if self.main_connect_button.text() in ("Conectar", ) and self.main_connect_button.isEnabled():
                self.on_connect_clicked()
            elif "Desconectar" in self.main_connect_button.text():
                if self.main_send_button.isEnabled():
                    self.on_send_command_clicked()
        elif prefix == "client_":
            if self.client_btn_server_control.text() == "Iniciar Servidor" and self.client_btn_server_control.isEnabled():
                self.on_connect_clicked()
            elif self.client_btn_client_state.text() == "Desconectar":
                if self.client_send_button.isEnabled():
                    self.on_send_command_clicked()
        elif prefix == "f3_":
            if self.f3_connect_button.text() == "Conectar" and self.f3_connect_button.isEnabled():
                self.on_connect_clicked()
            elif self.f3_connect_button.text() == "Desconectar":
                if self.f3_send_button.isEnabled():
                    self.on_send_command_clicked()

    # ──────────────────────────────────────────────────────────────────
    #  VALIDAÇÃO DE SENHA  (inalterada)
    # ──────────────────────────────────────────────────────────────────

    def validate_password_input(self):
        prefix = self._get_active_prefix()
        # REQUISITO: Ignora validação na aba F5 e F3 (F3 não tem senha, F5 usa a da F1)
        if prefix in ("f3_", "test_"): return
        
        state          = self.tab_data[prefix]
        password_input = self._get_widget("password_input")
        password       = password_input.text()

        if not state["connected"]:
            is_valid = len(password) == 6 and password.isdigit()
            if prefix == "main_":
                self.main_connect_button.setEnabled(is_valid if password else False)
            elif prefix == "client_":
                self.client_btn_server_control.setEnabled(is_valid if password else False)

    def set_inputs_enabled(self, enabled: bool, prefix=None):
        if prefix is None: prefix = self._get_active_prefix()
        if prefix == "test_": return

        getattr(self, f"{prefix}ip_input").setEnabled(enabled)
        getattr(self, f"{prefix}port_input").setEnabled(enabled)
        if prefix != "f3_":
            getattr(self, f"{prefix}user_input").setEnabled(enabled)
            getattr(self, f"{prefix}password_input").setEnabled(enabled)

    # ──────────────────────────────────────────────────────────────────
    #  CONFIGURAÇÕES  (inalteradas)
    # ──────────────────────────────────────────────────────────────────

    def load_config(self):
        geom = self.settings.value("geometry")
        if geom: self.restoreGeometry(geom)

        # Carregar Tema
        dark = self.settings.value("dark_mode", False, type=bool)
        self.dark_mode = dark
        self.header_bar.set_dark(dark)
        QApplication.instance().setStyleSheet(build_qss(dark=dark))

        self.main_ip_input.setText(self.settings.value('ip', '192.168.60.83'))
        self.main_port_input.setText(str(self.settings.value('port', 3000)))
        self.main_user_input.setText(self.settings.value('user', 'teste fabrica'))
        self.main_password_input.setText(self.settings.value('password', '111111'))

        self.client_ip_input.setCurrentText(self.settings.value('client_ip', get_local_ip()))
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

    def save_config(self, prefix=None):
        self.settings.setValue("active_tab", self.stacked_widget.currentIndex())

        if prefix is None:
            prefix = self._get_active_prefix()

        # REQUISITO: Se estiver na aba F5, não tenta salvar campos locais (IP/Porta já linkados com F1)
        if prefix == "test_":
            self.settings.sync()
            return

        ip_input   = getattr(self, f"{prefix}ip_input")
        port_input = getattr(self, f"{prefix}port_input")

        if prefix == "main_":
            self.settings.setValue('ip',   ip_input.text())
            self.settings.setValue('port', port_input.text())
        elif prefix == "client_":
            self.settings.setValue('client_port', port_input.text())
        elif prefix == "f3_":
            self.settings.setValue('f3_ip',   ip_input.text())
            self.settings.setValue('f3_port', port_input.text())

        if prefix != "f3_":
            self.settings.setValue('user',     getattr(self, f"{prefix}user_input").text())
            self.settings.setValue('password', getattr(self, f"{prefix}password_input").text())

        self.settings.setValue('dark_mode',           self.dark_mode)
        self.settings.setValue('manual_history',      self.manual_history)
        self.settings.setValue('last_manual_command', self.last_manual_command)
        self.settings.sync()

    # ──────────────────────────────────────────────────────────────────
    #  LOG / OUTPUT  (inalterado)
    # ──────────────────────────────────────────────────────────────────

    def append_log(self, message: str):
        self.log_output.append(message)

    def update_sent_received_output(self, prefix=None):
        if prefix is None: prefix = self._get_active_prefix()
        state          = self.tab_data[prefix]
        sent_output    = getattr(self, f"{prefix}sent_output")
        received_output = getattr(self, f"{prefix}received_output")

        if self.show_bytes:
            sent_output.setPlainText(state["last_sent_bytes"])
            received_output.setPlainText(state["last_received_bytes"])
        else:
            sent_output.setPlainText(state["last_sent_text"])
            received_output.setPlainText(state["last_received_text"])

        QTimer.singleShot(0, lambda: self._scroll_to_bottom(sent_output))
        QTimer.singleShot(0, lambda: self._scroll_to_bottom(received_output))

    def _scroll_to_bottom(self, text_edit):
        from PyQt6.QtGui import QTextCursor
        text_edit.moveCursor(QTextCursor.MoveOperation.End)
        scrollbar = text_edit.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def append_sent(self, text: str, prefix=None):
        if prefix is None: prefix = self._get_active_prefix()
        state = self.tab_data[prefix]
        if state["last_sent_text"]: state["last_sent_text"] += "\n" + text
        else: state["last_sent_text"] = text

        # Limita o buffer visual para evitar crash de RAM
        if len(state["last_sent_text"]) > 20000:
            state["last_sent_text"] = "..." + state["last_sent_text"][-20000:]

        self.update_sent_received_output(prefix)

    def append_sent_bytes(self, hex_text: str, prefix=None):
        if prefix is None: prefix = self._get_active_prefix()
        state = self.tab_data[prefix]
        if state["last_sent_bytes"]: state["last_sent_bytes"] += "\n" + hex_text
        else: state["last_sent_bytes"] = hex_text

        # Limita o buffer visual para evitar crash de RAM
        if len(state["last_sent_bytes"]) > 20000:
            state["last_sent_bytes"] = "..." + state["last_sent_bytes"][-20000:]

        self.update_sent_received_output(prefix)

    # ──────────────────────────────────────────────────────────────────
    #  MACRO  (inalterada)
    # ──────────────────────────────────────────────────────────────────

    def on_macro_clicked(self, prefix):
        if not hasattr(self, f"{prefix}macro_window"):
            setattr(self, f"{prefix}macro_window", MacroWindow(self, prefix))

        window = getattr(self, f"{prefix}macro_window")
        window.show()
        window.raise_()

    def send_external_command(self, command_str, prefix):
        state = self.tab_data[prefix]
        if not state["persistent_sock"]: return

        worker = CommandWorker(state["persistent_sock"], command_str, state["session_key"])
        self.external_workers.append(worker)

        worker.sent_signal.connect(lambda txt: self.append_sent(txt, prefix))
        worker.sent_bytes_signal.connect(lambda hex_txt: self.append_sent_bytes(hex_txt, prefix))
        worker.finished_signal.connect(lambda: self.external_workers.remove(worker) if worker in self.external_workers else None)

        worker.start()

    # ──────────────────────────────────────────────────────────────────
    #  RECEBIMENTO  (inalterado)
    # ──────────────────────────────────────────────────────────────────

    def append_received(self, text: str, prefix=None):
        if prefix is None: prefix = self._get_active_prefix()
        state = self.tab_data[prefix]

        # 🔹 Atualiza a string recebida IMEDIATAMENTE na interface
        if state["last_received_text"]: state["last_received_text"] += "\n" + text
        else: state["last_received_text"] = text

        # Limita o buffer visual para evitar crash de RAM
        if len(state["last_received_text"]) > 20000:
            state["last_received_text"] = "..." + state["last_received_text"][-20000:]

        self.update_sent_received_output(prefix)

        # 🔹 DETECÇÃO GLOBAL DE BLOQUEIO (Erro 047)
        # Se aparecer 047 em qualquer resposta (ex: 01+RA+047, 01+EU+047), bloqueia e desconecta.
        if "00+00+047" in text or re.search(r"01\+[A-Z]{2}\+047", text):
            self.append_log(f"BLOQUEIO DETECTADO ({prefix}): {text}")
            QMessageBox.warning(self, "Equipamento Bloqueado", "Equipamento bloqueado")
            self.disconnect(prefix)
            return

        # 🔹 REQUISITO: Se houver macro rodando, notificar a janela
        if hasattr(self, f"{prefix}macro_window"):
            window = getattr(self, f"{prefix}macro_window")
            if window.is_running or getattr(window, 'is_deleting', False) or getattr(window, 'is_deleting_bio', False):
                window.handle_response(text)

        # 🔹 Lógica especial para processar resposta RB na aba F3
        if prefix == "f3_":
            # Detecta se a resposta parece criptografada (não começa com o protocolo 01+ ou 00+)
            is_encrypted = not (text.startswith("01+") or text.startswith("00+"))
            if is_encrypted:
                self.append_log(f"F3: Criptografia detectada: {text}")
                QMessageBox.warning(self, "Criptografia Detectada", 
                                    "Equipamento com criptografia ativa.\n\n"
                                    "Por favor, reinicie o REP para prosseguir com o desbloqueio na aba F3.")
                self.disconnect(prefix)
                return

            if text.startswith("01+RB+000+"):
                state["reconnect_count"] = 0
                try:
                    data_part = text[10:]
                    if "]" in data_part:
                        unlock_code, rep_num = data_part.split("]", 1)
                        unlock_code = unlock_code.strip()
                        rep_num     = rep_num.strip()

                        self.f3_unlock_code_field.setText(unlock_code)
                        self.f3_rep_num_field.setText(rep_num)

                        state["unlock_code"] = unlock_code
                        state["rep_num"]     = rep_num

                        if not unlock_code:
                            QMessageBox.information(self, "Conexão F3", "Equipamento já desbloqueado")
                            QTimer.singleShot(100, lambda: self.disconnect(prefix))
                except Exception as e:
                    self.append_log(f"F3: Erro ao processar dados de identificação: {e}")

            elif text.startswith("01+EB+000"):
                QMessageBox.information(self, "Desbloqueio F3", "Equipamento desbloqueado com sucesso!")
                QTimer.singleShot(100, lambda: self.disconnect(prefix))

            elif text.startswith("01+EB+012"):
                QMessageBox.warning(self, "Desbloqueio F3", "Código de Desbloqueio Inválido")

            elif text.startswith("01+EB+121"):
                QMessageBox.warning(self, "Desbloqueio F3", 
                                    "Não foi possível realizar o desbloqueio pois o tamper está aberto.")
                self.disconnect(prefix)
                return

            elif "00+00+015" in text:
                self.append_log(f"F3: Erro 015 detectado na resposta: {text}")
                if state["reconnect_count"] < 3:
                    state["reconnect_count"] += 1
                    self.append_log(f"F3: Iniciando ciclo de reconexão automática {state['reconnect_count']}/3...")
                    self.disconnect(prefix)
                    QTimer.singleShot(500, lambda: self.on_connect_clicked(prefix))
                else:
                    self.append_log("F3: Erro 015 persistente após 3 tentativas. Reconexão automática interrompida.")
                    state["reconnect_count"] = 0

        if self.test_mode and prefix == "main_" and state["connected"]:
            # Filtro para ignorar mensagens de handshake que podem vir de workers persistentes
            if not (text.startswith("01+RA") or text.startswith("01+EA")):
                self.handle_test_response(text)

    def append_received_bytes(self, hex_text: str, prefix=None):
        if prefix is None: prefix = self._get_active_prefix()
        state = self.tab_data[prefix]
        if state["last_received_bytes"]: state["last_received_bytes"] += "\n" + hex_text
        else: state["last_received_bytes"] = hex_text

        # Limita o buffer visual para evitar crash de RAM
        if len(state["last_received_bytes"]) > 20000:
            state["last_received_bytes"] = "..." + state["last_received_bytes"][-20000:]

        self.update_sent_received_output(prefix)

    # ──────────────────────────────────────────────────────────────────
    #  CONTROLES DA UI  (inalterados)
    # ──────────────────────────────────────────────────────────────────

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

    def on_cancel_connect_clicked(self):
        prefix = "main_"
        state = self.tab_data[prefix]
        if state["worker"] and state["worker"].isRunning():
            state["worker"].stop()
            self.append_log("Cancelando conexão...")

    def on_send_command_finished(self, success: bool, message: str):
        self.append_log(message)
        prefix = self._get_active_prefix()
        if prefix == "test_":
            prefix = "main_"
        getattr(self, f"{prefix}send_button").setEnabled(True)

    def on_clear_clicked(self):
        prefix = self._get_active_prefix()
        if prefix == "test_":
            prefix = "main_"
        state  = self.tab_data[prefix]
        state["last_sent_text"]     = ""
        state["last_sent_bytes"]    = ""
        state["last_received_text"] = ""
        state["last_received_bytes"] = ""
        self.update_sent_received_output(prefix)
        self.append_log(f"Campos da aba {prefix} limpos.")

    # ──────────────────────────────────────────────────────────────────
    #  CONEXÃO / DESCONEXÃO  (inalteradas)
    # ──────────────────────────────────────────────────────────────────

    def on_connect_clicked(self, prefix=None):
        # Se prefix for o booleano do sinal clicked ou None, pega o ativo
        if prefix is None or isinstance(prefix, bool):
            prefix = self._get_active_prefix()

        if prefix == "test_":
            prefix = "main_"
        state  = self.tab_data[prefix]

        if state["connected"]:
            if prefix == "client_":
                # Se clicar em "Desconectar" (botão da direita), fecha apenas a conexão com o equipamento
                if self.sender() == self.client_btn_client_state:
                    self.disconnect_equipment_only(prefix)
                    return
            self.disconnect(prefix)
            return

        if prefix == "client_" and state["worker"] and state["worker"].isRunning():
            self.disconnect(prefix)
            return

        ip_widget = getattr(self, f"{prefix}ip_input")
        ip = ip_widget.currentText().strip() if isinstance(ip_widget, QComboBox) else ip_widget.text().strip()
        port_text = getattr(self, f"{prefix}port_input").text().strip()

        if prefix != "f3_":
            user     = getattr(self, f"{prefix}user_input").text().strip()
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

        self.save_config(prefix)

        if prefix == "main_":
            self.main_connect_button.setEnabled(False)
            self.main_cancel_button.setVisible(True)
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
            # 🔹 REQUISITO: Conectar sinais de recebimento para o handshake F3
            state["worker"].received_signal.connect(lambda txt: self.append_received(txt, prefix))
            state["worker"].received_bytes_signal.connect(lambda hex_txt: self.append_received_bytes(hex_txt, prefix))

        state["worker"].log_signal.connect(self.append_log)
        if hasattr(state["worker"], "sent_signal"):
            state["worker"].sent_signal.connect(lambda txt, p=prefix: self.append_sent(txt, p))
            state["worker"].sent_bytes_signal.connect(lambda hex_txt, p=prefix: self.append_sent_bytes(hex_txt, p))
            state["worker"].received_signal.connect(lambda txt, p=prefix: self.append_received(txt, p))
            state["worker"].received_bytes_signal.connect(lambda hex_txt, p=prefix: self.append_received_bytes(hex_txt, p))
        state["worker"].finished_signal.connect(lambda s, m, sk, key, rsa, p=prefix: self.on_finished(s, m, sk, key, rsa, p))
        state["worker"].start()

    def disconnect_equipment_only(self, prefix):
        """Fecha apenas a conexão com o equipamento, mantendo o servidor/worker ativo se necessário."""
        state = self.tab_data[prefix]

        if state["listener_worker"]:
            state["listener_worker"].stop()
            state["listener_worker"].wait(500)
            state["listener_worker"] = None

        if state["persistent_sock"]:
            try:
                state["persistent_sock"].shutdown(socket.SHUT_RDWR)
                state["persistent_sock"].close()
            except: pass
            state["persistent_sock"] = None

        state["session_key"] = None
        state["connected"]   = False

        if prefix == "client_":
            self.client_btn_client_state.setText("Aguardando Conexão")
            self.client_btn_client_state.setEnabled(False)
            self.client_macro_button.setVisible(False)
            # Re-habilita o worker de escuta do servidor se ele foi fechado após o accept
            if not state["worker"] or not state["worker"].isRunning():
                ip_widget = getattr(self, f"{prefix}ip_input")
                ip = ip_widget.currentText().strip() if isinstance(ip_widget, QComboBox) else ip_widget.text().strip()
                port_text = getattr(self, f"{prefix}port_input").text().strip()
                user      = getattr(self, f"{prefix}user_input").text().strip()
                password  = getattr(self, f"{prefix}password_input").text().strip()
                try:
                    port = int(port_text)
                    state["worker"] = ClientNetworkWorker(ip, port, user, password)
                    state["worker"].log_signal.connect(self.append_log)
                    if hasattr(state["worker"], "sent_signal"):
                        state["worker"].sent_signal.connect(lambda txt, p=prefix: self.append_sent(txt, p))
                        state["worker"].sent_bytes_signal.connect(lambda hex_txt, p=prefix: self.append_sent_bytes(hex_txt, p))
                        state["worker"].received_signal.connect(lambda txt, p=prefix: self.append_received(txt, p))
                        state["worker"].received_bytes_signal.connect(lambda hex_txt, p=prefix: self.append_received_bytes(hex_txt, p))
                    state["worker"].finished_signal.connect(lambda s, m, sk, key, rsa, p=prefix: self.on_finished(s, m, sk, key, rsa, p))
                    state["worker"].start()
                    self.append_log("Servidor reiniciado para aguardar nova conexão.")
                except:
                    pass

        self.set_inputs_enabled(True, prefix)
        self.append_log(f"Equipamento desconectado. Servidor permanece ativo ({prefix}).")
        self.update_dependent_tabs_state()

    def on_f3_auto_sent(self, text, packet_bytes):
        self.append_sent(text, "f3_")
        self.append_sent_bytes(packet_bytes.hex(' '), "f3_")

    def on_f3_unlock_clicked(self):
        prefix = "f3_"
        state  = self.tab_data[prefix]

        if not state["connected"]:
            self.append_log("F3: Erro: Não conectado para enviar comando de desbloqueio.")
            return

        unlock_code = self.f3_unlock_input_field.text().strip()
        if not unlock_code:
            QMessageBox.warning(self, "Desbloqueio F3", "Por favor, insira o Código de Bloqueio.")
            return

        command_str = f"01+EB+00+{unlock_code}"
        self.append_log(f"F3: Enviando comando de desbloqueio: {command_str}")

        self.f3_unlock_button.setEnabled(False)
        self.command_worker = CommandWorker(state["persistent_sock"], command_str, None)
        self.command_worker.sent_signal.connect(lambda txt: self.append_sent(txt, prefix))
        self.command_worker.sent_bytes_signal.connect(lambda hex_txt: self.append_sent_bytes(hex_txt, prefix))
        self.command_worker.finished_signal.connect(self.on_f3_unlock_command_finished)
        self.command_worker.start()

    def on_f3_unlock_command_finished(self, success: bool, message: str):
        self.append_log(f"F3 Desbloqueio: {message}")
        self.f3_unlock_button.setEnabled(True)
        if not success:
            QMessageBox.critical(self, "Erro Desbloqueio F3", "Falha ao enviar comando de desbloqueio.")

    def disconnect(self, prefix=None):
        if prefix is None: prefix = self._get_active_prefix()
        state = self.tab_data[prefix]

        # FECHAR AUTOMATICAMENTE JANELA DE MACRO SE A CONEXÃO FOR ENCERRADA
        if hasattr(self, f"{prefix}macro_window"):
            macro_window = getattr(self, f"{prefix}macro_window")
            if macro_window:
                macro_window.close()

        # 🔹 REQUISITO: Realizar Deauth antes de fechar a conexão se for uma aba criptografada
        if state["connected"] and prefix in ("main_", "client_", "test_") and state["persistent_sock"] and state["rsa_key"]:
            self.append_log(f"Encerrando criptografia ({prefix})...")
            
            # Nas abas criptografadas, precisamos do usuário/senha para o blob RSA do deauth
            target_prefix = "main_" if prefix == "test_" else prefix
            user = getattr(self, f"{target_prefix}user_input").text().strip()
            password = getattr(self, f"{target_prefix}password_input").text().strip()

            deauth = DeauthWorker(state["persistent_sock"], state["rsa_key"], user, password, state["session_key"])
            self.external_workers.append(deauth)
            deauth.sent_signal.connect(lambda txt: self.append_sent(txt, prefix))
            deauth.sent_bytes_signal.connect(lambda hex_txt: self.append_sent_bytes(hex_txt, prefix))
            
            deauth.finished_signal.connect(lambda: self._final_disconnect(prefix))
            deauth.finished_signal.connect(lambda: self.external_workers.remove(deauth) if deauth in self.external_workers else None)
            deauth.start()
            state["connected"] = False
            return

        self._final_disconnect(prefix)

    def _final_disconnect(self, prefix):
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
        state["rsa_key"]     = None
        state["connected"]   = False

        if prefix == "main_":
            self.connect_timer.stop()
            self.main_cancel_button.setVisible(False)
            self.main_connect_button.setText("Conectar")
            self.main_connect_button.setObjectName("primary_btn")
            self.main_connect_button.setEnabled(True)
            self.main_macro_button.setVisible(False)

        elif prefix == "client_":
            self.client_btn_server_control.setText("Iniciar Servidor")
            self.client_btn_server_control.setObjectName("primary_btn")
            self.client_btn_server_control.setEnabled(True)
            self.client_btn_client_state.setText("Aguardando Conexão")
            self.client_btn_client_state.setEnabled(False)
            self.client_macro_button.setVisible(False)

        elif prefix == "f3_":
            self.f3_connect_button.setText("Conectar")
            self.f3_connect_button.setObjectName("primary_btn")
            self.f3_connect_button.setEnabled(True)
            self.f3_unlock_button.setEnabled(False)
            # Limpa campos de identificação
            self.f3_rep_num_field.clear()
            self.f3_unlock_code_field.clear()

        self.set_inputs_enabled(True, prefix)
        self.append_log(f"Estado resetado ({prefix}).")
        self.update_dependent_tabs_state()

    def on_listener_error(self, error_msg, prefix):
        self.append_log(f"Erro na escuta ({prefix}): {error_msg}")
        self.disconnect(prefix)

    def on_finished(self, success: bool, message: str, sock, session_key, rsa_key, prefix):
        if prefix == "main_":
            self.connect_timer.stop()
            self.main_cancel_button.setVisible(False)
            self.dot_count = 0

        self.append_log(message)
        state = self.tab_data[prefix]

        if success:
            state["persistent_sock"] = sock
            state["session_key"]     = session_key
            state["rsa_key"]         = rsa_key
            state["connected"]       = True

            if prefix == "main_":
                self.main_connect_button.setText("Desconectar")
                self.main_connect_button.setObjectName("disconnect_btn")
                self.main_connect_button.setEnabled(True)

            elif prefix == "client_":
                self.client_btn_client_state.setText("Desconectar")
                self.client_btn_client_state.setEnabled(True)
                self.client_btn_server_control.setText("Desligar Servidor")

            elif prefix == "f3_":
                self.f3_connect_button.setText("Desconectar")
                self.f3_connect_button.setObjectName("disconnect_btn")
                self.f3_connect_button.setEnabled(True)
                self.f3_unlock_button.setEnabled(True)

            getattr(self, f"{prefix}send_button").setEnabled(True)
            self.set_inputs_enabled(False, prefix)

            # 🔹 REQUISITO: Exibir botão Macro se for F1 ou F2
            if prefix in ["main_", "client_"]:
                getattr(self, f"{prefix}macro_button").setVisible(True)

            state["listener_worker"] = ListenerWorker(state["persistent_sock"], state["session_key"])
            state["listener_worker"].received_signal.connect(lambda txt: self.append_received(txt, prefix))
            state["listener_worker"].received_bytes_signal.connect(lambda hex_txt: self.append_received_bytes(hex_txt, prefix))
            state["listener_worker"].error_signal.connect(lambda err: self.on_listener_error(err, prefix))
            state["listener_worker"].start()

            if self.test_mode and prefix == "main_":
                if self.test_mode == "gerar_afd":
                    QTimer.singleShot(500, self.start_afd_flow)
                else:
                    # Envia o comando correspondente ao teste
                    cmd = ""
                    if self.test_mode == "usuario_padrao":
                        cmd = "01+ES+00+1+I[26571383063[teste fabrica[111111[525521[111111"
                    elif self.test_mode == "empregador":
                        cmd = "01+EE+00+1]44880091000172]]EVO Sistemas Inteligentes LTDA]Rio Piquiri, 400"
                    elif self.test_mode == "colaborador":
                        cmd = "01+EU+00+1+I[26571383063[Teste[0[2[1}4132669"
                    
                    if cmd:
                        QTimer.singleShot(500, lambda: self._send_raw_command("main_", cmd))
            
            elif prefix != "f3_" and not self.test_mode:
                QMessageBox.information(self, "Conexão", f"Conexão bem sucedida ({prefix})")

        else:
            if self.test_mode and prefix == "main_":
                self._finish_current_test("Erro ao Cadastrar", "#C0392B")
                return

            state["connected"] = False

            if prefix == "main_":
                self.main_connect_button.setText("Conectar")
                self.main_connect_button.setObjectName("primary_btn")
                self.main_connect_button.setEnabled(True)

            elif prefix == "client_":
                self.client_btn_server_control.setText("Iniciar Servidor")
                self.client_btn_client_state.setText("Aguardando Conexão")
                self.client_btn_client_state.setEnabled(False)

            elif prefix == "f3_":
                self.f3_connect_button.setText("Conectar")
                self.f3_connect_button.setObjectName("primary_btn")
                self.f3_connect_button.setEnabled(True)
                # Limpa campos de identificação em caso de falha
                self.f3_rep_num_field.clear()
                self.f3_unlock_code_field.clear()

            getattr(self, f"{prefix}send_button").setEnabled(False)
            self.set_inputs_enabled(True, prefix)

            if "Erro 047" in message:
                QMessageBox.warning(self, "Equipamento Bloqueado", "Equipamento bloqueado")
                self.disconnect(prefix)
                return

            if "Operação cancelada pelo usuário" in message or "Servidor parado pelo usuário" in message:
                return

            if "10013" in message or "10048" in message:
                message = "Soquete em uso por outra aplicação"
            
            # 🔹 REQUISITO: Não mostrar mensagem de erro se for o Erro 015 (reconexão automática silenciosa)
            if not self.test_mode and "Erro 015" not in message:
                QMessageBox.critical(self, "Erro de Conexão", message)

        self.update_dependent_tabs_state()


# ══════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════════

def main():
    # Fix taskbar icon on Windows
    if sys.platform == 'win32':
        myappid = 'evosistemas.replink.protocolo.05'
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)

    app = QApplication(sys.argv)
    app.setStyle("Fusion")      # base neutra para o QSS funcionar uniformemente
    
    # Define o ícone da janela e da barra de tarefas
    icon_path = resource_path("logo.png")
    if os.path.exists(icon_path):
        app.setWindowIcon(QIcon(icon_path))
    
    window = EvoRepAuthApp()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()

