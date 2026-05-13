# main.py  —  Visual refactor (UI/UX only)
#              All network / crypto / protocol logic is UNCHANGED.

import sys
import os
import socket
import base64
import traceback
import time
import random
import re
from comandos import COMMANDS_REGISTRY

from PyQt6.QtCore import QThread, pyqtSignal, QSettings, QTimer, Qt, QEvent
from PyQt6.QtWidgets import (QApplication, QGridLayout, QLabel, QLineEdit,
                             QPushButton, QTextEdit, QWidget, QStackedWidget,
                             QGroupBox, QVBoxLayout, QHBoxLayout, QMessageBox,
                             QComboBox, QFormLayout, QScrollArea, QCheckBox, QFrame,
                             QRadioButton, QButtonGroup)

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


# ══════════════════════════════════════════════════════════════════════
#  THEME ENGINE
# ══════════════════════════════════════════════════════════════════════

def build_qss(dark: bool = False) -> str:
    """Retorna a folha de estilo QSS completa para o tema claro ou escuro."""
    if dark:
        bg         = "#16161A"
        surface    = "#1F1F27"
        surface2   = "#28282F"
        border     = "#38383F"
        text       = "#E8E8F2"
        text_muted = "#7878A0"
        primary    = "#2ECC71"
        primary_h  = "#27AE60"
        primary_p  = "#1E8449"
        danger     = "#E74C3C"
        danger_h   = "#C0392B"
        input_bg   = "#1B1B22"
        dis_bg     = "#2A2A35"
        dis_fg     = "#505068"
        scr_bg     = "#1F1F27"
        scr_h      = "#3C3C48"
    else:
        bg         = "#ECEEF3"
        surface    = "#FFFFFF"
        surface2   = "#F3F5F8"
        border     = "#CBD0DC"
        text       = "#1A1C2C"
        text_muted = "#6B7280"
        primary    = "#16A34A"
        primary_h  = "#15803D"
        primary_p  = "#14532D"
        danger     = "#DC2626"
        danger_h   = "#B91C1C"
        input_bg   = "#FFFFFF"
        dis_bg     = "#E5E7EB"
        dis_fg     = "#9CA3AF"
        scr_bg     = "#E4E7EE"
        scr_h      = "#BBC0CC"

    return f"""
/* ── BASE ────────────────────────────────────────────── */
QWidget {{
    background-color: {bg};
    color: {text};
    font-family: 'Segoe UI', 'SF Pro Text', -apple-system, sans-serif;
    font-size: 13px;
    selection-background-color: {primary};
    selection-color: #FFFFFF;
}}

/* ── HEADER BAR ──────────────────────────────────────── */
#header_bar {{
    background-color: {surface};
    border-bottom: 2px solid {primary};
    min-height: 54px;
    max-height: 54px;
}}
#header_title {{
    color: {primary};
    font-size: 20px;
    font-weight: 800;
    background: transparent;
    border: none;
    padding: 0;
}}
#header_version {{
    color: {text_muted};
    font-size: 10px;
    font-weight: 500;
    background: transparent;
    border: none;
    padding: 0 0 2px 2px;
}}

/* ── TAB BUTTONS ─────────────────────────────────────── */
QPushButton#tab_btn {{
    background-color: transparent;
    color: {text_muted};
    border: none;
    border-radius: 6px;
    padding: 6px 14px;
    font-size: 12px;
    font-weight: 600;
    min-width: 100px;
}}
QPushButton#tab_btn:hover {{
    background-color: {surface2};
    color: {text};
}}
QPushButton#tab_btn:checked {{
    color: {primary};
    background-color: {surface2};
}}

/* ── THEME BUTTON ────────────────────────────────────── */
QPushButton#theme_btn {{
    background-color: {surface2};
    color: {text_muted};
    border: 1.5px solid {border};
    border-radius: 14px;
    padding: 5px 14px;
    font-size: 11px;
    font-weight: 600;
    min-width: 86px;
    max-height: 28px;
}}
QPushButton#theme_btn:hover {{
    border-color: {primary};
    color: {primary};
    background-color: {surface};
}}
QPushButton#theme_btn:pressed {{
    background-color: {surface2};
}}

/* ── GROUPBOX ─────────────────────────────────────────── */
QGroupBox {{
    background-color: {surface};
    border: 1.5px solid {border};
    border-radius: 10px;
    margin-top: 14px;
    padding: 14px 12px 12px 12px;
    font-weight: 600;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 14px;
    padding: 0 6px;
    color: {primary};
    font-size: 10px;
    font-weight: 700;
    background-color: {surface};
}}

/* ── STANDARD BUTTON ─────────────────────────────────── */
QPushButton {{
    background-color: {surface2};
    color: {text};
    border: 1.5px solid {border};
    border-radius: 7px;
    padding: 6px 14px;
    font-weight: 600;
    font-size: 12px;
}}
QPushButton:hover {{
    background-color: {border};
    border-color: {text_muted};
}}
QPushButton:pressed {{
    background-color: {primary};
    color: #FFFFFF;
    border-color: {primary_p};
}}
QPushButton:disabled {{
    background-color: {dis_bg};
    color: {dis_fg};
    border-color: {dis_bg};
}}

/* ── PRIMARY BUTTON (Conectar / Enviar) ──────────────── */
QPushButton#primary_btn {{
    background-color: {primary};
    color: #FFFFFF;
    border: none;
    border-radius: 7px;
    padding: 7px 18px;
    font-weight: 700;
    font-size: 13px;
}}
QPushButton#primary_btn:hover {{
    background-color: {primary_h};
}}
QPushButton#primary_btn:pressed {{
    background-color: {primary_p};
}}
QPushButton#primary_btn:disabled {{
    background-color: {dis_bg};
    color: {dis_fg};
}}

/* ── DISCONNECT BUTTON ───────────────────────────────── */
QPushButton#disconnect_btn {{
    background-color: transparent;
    color: {danger};
    border: 1.5px solid {danger};
    border-radius: 7px;
    padding: 7px 18px;
    font-weight: 700;
    font-size: 13px;
}}
QPushButton#disconnect_btn:hover {{
    background-color: {danger};
    color: #FFFFFF;
}}
QPushButton#disconnect_btn:pressed {{
    background-color: {danger_h};
    color: #FFFFFF;
}}

/* ── DANGER BUTTON ────────────────────────────────────── */
QPushButton#danger_btn {{
    background-color: transparent;
    color: {danger};
    border: 1.5px solid {danger};
    border-radius: 7px;
    padding: 6px 14px;
    font-weight: 600;
    font-size: 12px;
}}
QPushButton#danger_btn:hover {{
    background-color: {danger};
    color: #FFFFFF;
    border-color: {danger};
}}
QPushButton#danger_btn:pressed {{
    background-color: {danger_h};
    color: #FFFFFF;
}}
QPushButton#danger_btn:disabled {{
    color: {dis_fg};
    border-color: {dis_bg};
}}

/* ── LINE EDIT ────────────────────────────────────────── */
QLineEdit {{
    background-color: {input_bg};
    color: {text};
    border: 1.5px solid {border};
    border-radius: 6px;
    padding: 5px 9px;
    min-height: 22px;
}}
QLineEdit:focus {{
    border-color: {primary};
    background-color: {surface};
}}
QLineEdit:disabled {{
    background-color: {dis_bg};
    color: {dis_fg};
    border-color: {dis_bg};
}}
QLineEdit:read-only {{
    background-color: {surface2};
    border-style: dashed;
    color: {text_muted};
}}

/* ── TEXT EDIT ────────────────────────────────────────── */
QTextEdit {{
    background-color: {input_bg};
    color: {text};
    border: 1.5px solid {border};
    border-radius: 8px;
    padding: 8px 10px;
    font-family: 'Cascadia Code', 'Consolas', 'Courier New', monospace;
    font-size: 11px;
    line-height: 1.4;
}}
QTextEdit:focus {{
    border-color: {primary};
}}
QTextEdit[readOnly="true"] {{
    background-color: {surface2};
    color: {text};
    border-color: {border};
}}

/* ── COMBOBOX ─────────────────────────────────────────── */
QComboBox {{
    background-color: {input_bg};
    color: {text};
    border: 1.5px solid {border};
    border-radius: 6px;
    padding: 5px 9px;
    min-height: 24px;
}}
QComboBox:focus, QComboBox:on {{
    border-color: {primary};
}}
QComboBox::drop-down {{
    border: none;
    width: 22px;
}}
QComboBox::down-arrow {{
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-top: 5px solid {text_muted};
    width: 0;
    height: 0;
    margin-right: 6px;
}}
QComboBox QAbstractItemView {{
    background-color: {surface};
    color: {text};
    border: 1.5px solid {border};
    border-radius: 6px;
    padding: 4px;
    selection-background-color: {primary};
    selection-color: #FFFFFF;
    outline: none;
}}
QComboBox:disabled {{
    background-color: {dis_bg};
    color: {dis_fg};
    border-color: {dis_bg};
}}

/* ── SCROLL AREA ─────────────────────────────────────── */
QScrollArea {{
    border: none;
    background-color: transparent;
}}
QScrollArea > QWidget > QWidget {{
    background-color: transparent;
}}

/* ── SCROLLBAR ────────────────────────────────────────── */
QScrollBar:vertical {{
    background-color: {scr_bg};
    width: 7px;
    border-radius: 4px;
    margin: 0;
}}
QScrollBar::handle:vertical {{
    background-color: {scr_h};
    border-radius: 4px;
    min-height: 26px;
}}
QScrollBar::handle:vertical:hover {{
    background-color: {primary};
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0; border: none;
}}
QScrollBar:horizontal {{
    background-color: {scr_bg};
    height: 7px;
    border-radius: 4px;
    margin: 0;
}}
QScrollBar::handle:horizontal {{
    background-color: {scr_h};
    border-radius: 4px;
    min-width: 26px;
}}
QScrollBar::handle:horizontal:hover {{
    background-color: {primary};
}}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
    width: 0; border: none;
}}

/* ── CHECKBOX ─────────────────────────────────────────── */
QCheckBox {{
    color: {text};
    spacing: 7px;
    background: transparent;
    font-size: 12px;
}}
QCheckBox::indicator {{
    width: 15px;
    height: 15px;
    border: 1.5px solid {border};
    border-radius: 4px;
    background-color: {input_bg};
}}
QCheckBox::indicator:checked {{
    background-color: {primary};
    border-color: {primary};
}}
QCheckBox::indicator:hover {{
    border-color: {primary};
}}

/* ── RADIO BUTTON ─────────────────────────────────────── */
QRadioButton {{
    color: {text};
    spacing: 7px;
    background: transparent;
    font-size: 12px;
}}
QRadioButton::indicator {{
    width: 15px;
    height: 15px;
    border: 1.5px solid {border};
    border-radius: 8px;
    background-color: {input_bg};
}}
QRadioButton::indicator:checked {{
    background-color: {primary};
    border-color: {primary};
}}
QRadioButton::indicator:hover {{
    border-color: {primary};
}}

/* ── LABELS ───────────────────────────────────────────── */
QLabel {{
    background: transparent;
    color: {text};
}}
QFormLayout QLabel {{
    color: {text_muted};
    font-size: 11px;
    font-weight: 600;
}}

/* ── MESSAGE BOX ─────────────────────────────────────── */
QMessageBox {{
    background-color: {surface};
}}
QMessageBox QPushButton {{
    min-width: 80px;
    min-height: 28px;
}}

/* ── SEPARATOR ───────────────────────────────────────── */
QFrame[frameShape="4"], QFrame[frameShape="5"] {{
    color: {border};
    background-color: {border};
    max-height: 1px;
}}
"""


# ══════════════════════════════════════════════════════════════════════
#  CUSTOM WIDGETS
# ══════════════════════════════════════════════════════════════════════

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


APP_VERSION = "0.4"


class HeaderBar(QWidget):
    """Barra de cabeçalho: REPLink | versão | tabs | toggle de tema."""

    theme_toggled = pyqtSignal()
    tab_changed   = pyqtSignal(int)   # emite o índice do QStackedWidget

    # (rótulo visível, índice no QStackedWidget)
    _TAB_DEFS = [
        ("Servidor",    0),
        ("Cliente",     2),
        ("Desbloqueio", 3),
    ]

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("header_bar")
        self._dark = False

        outer = QHBoxLayout(self)
        outer.setContentsMargins(18, 0, 18, 0)
        outer.setSpacing(0)

        # ─── Brand (título + versão) ───────────────────────────────
        title = QLabel("REPLink")
        title.setObjectName("header_title")

        self._version_label = _VersionBadge()
        self._version_label.setObjectName("header_version")

        brand_row = QHBoxLayout()
        brand_row.setSpacing(5)
        brand_row.setContentsMargins(0, 0, 0, 0)
        brand_row.addWidget(title, 0, Qt.AlignmentFlag.AlignVCenter)
        brand_row.addWidget(self._version_label, 0, Qt.AlignmentFlag.AlignVCenter)

        outer.addLayout(brand_row)
        outer.addSpacing(28)
        outer.addStretch(1)

        # ─── Tab buttons ──────────────────────────────────────────
        self._tab_btns: list[tuple[QPushButton, int]] = []
        for label, idx in self._TAB_DEFS:
            btn = QPushButton(label)
            btn.setObjectName("tab_btn")
            btn.setCheckable(True)
            btn.setFlat(True)
            btn.clicked.connect(lambda _c, i=idx: self.tab_changed.emit(i))
            self._tab_btns.append((btn, idx))
            outer.addWidget(btn)
            outer.addSpacing(2)

        outer.addStretch(1)

        # ─── Theme toggle button ──────────────────────────────────
        self._theme_btn = QPushButton("🌙  Escuro")
        self._theme_btn.setObjectName("theme_btn")
        self._theme_btn.clicked.connect(self._on_toggle)
        outer.addWidget(self._theme_btn)

        self.set_active_tab(0)

    # ------------------------------------------------------------------
    def _on_toggle(self):
        self._dark = not self._dark
        self._theme_btn.setText("☀  Claro" if self._dark else "🌙  Escuro")
        self.theme_toggled.emit()

    def set_dark(self, dark: bool):
        """Atualiza o estado interno e o texto do botão de tema."""
        self._dark = dark
        self._theme_btn.setText("☀  Claro" if self._dark else "🌙  Escuro")

    def set_active_tab(self, stacked_index: int):
        for btn, idx in self._tab_btns:
            btn.setChecked(idx == stacked_index)


class _VersionBadge(QLabel):
    """Versão com Easter Egg de duplo clique."""
    def __init__(self, parent=None):
        super().__init__(f"{APP_VERSION}", parent)

    def mouseDoubleClickEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.setText("Lucas C Albuquerque")
            QTimer.singleShot(1200, self._reset)

    def _reset(self):
        self.setText(f"{APP_VERSION}")


# ══════════════════════════════════════════════════════════════════════
#  HELPER FUNCTIONS  (inalteradas)
# ══════════════════════════════════════════════════════════════════════

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


# ══════════════════════════════════════════════════════════════════════
#  MACRO WINDOW
# ══════════════════════════════════════════════════════════════════════

class MacroWindow(QWidget):
    def __init__(self, parent_app, prefix):
        super().__init__()
        self.parent_app = parent_app
        self.prefix = prefix
        self.setWindowTitle(f"Macro — {prefix.replace('_', '').upper()}")
        self.setMinimumSize(420, 300)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        # ── Gerar colaboradores ──────────────────────────────────
        group_box = QGroupBox("Gerar Colaboradores")
        group_layout = QFormLayout(group_box)
        group_layout.setSpacing(8)
        group_layout.setContentsMargins(12, 18, 12, 12)

        self.count_input = QLineEdit("10")
        group_layout.addRow("Quantidade:", self.count_input)

        self.btn_bulk = QPushButton("Gerar todos de uma vez")
        self.btn_sequential = QPushButton("Gerar um por um")

        self.btn_delete_last = QPushButton("Deletar últimos gerados")
        self.btn_delete_last.setObjectName("danger_btn")
        self.btn_delete_last.setVisible(False)

        group_layout.addRow(self.btn_bulk)
        group_layout.addRow(self.btn_sequential)
        group_layout.addRow(self.btn_delete_last)

        layout.addWidget(group_box)

        # ── Deletar colaboradores do REP ─────────────────────────
        delete_group_box = QGroupBox("Deletar Colaboradores do REP")
        delete_layout = QFormLayout(delete_group_box)
        delete_layout.setSpacing(8)
        delete_layout.setContentsMargins(12, 18, 12, 12)

        self.delete_count_input = QLineEdit("10")
        delete_layout.addRow("Quantidade:", self.delete_count_input)

        self.btn_delete_rep = QPushButton("Deletar")
        self.btn_delete_rep.setObjectName("danger_btn")
        delete_layout.addRow(self.btn_delete_rep)

        layout.addWidget(delete_group_box)

        # ── Log ──────────────────────────────────────────────────
        log_group = QGroupBox("Status")
        log_v = QVBoxLayout(log_group)
        log_v.setContentsMargins(10, 18, 10, 10)
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        log_v.addWidget(self.log_output)
        layout.addWidget(log_group)

        # PERSISTÊNCIA: Carregar posição e tamanho salvos
        self.settings = QSettings("EvoRep", "MacroWindow")
        geom = self.settings.value(f"geometry_{self.prefix}")
        if geom:
            self.restoreGeometry(geom)

        self.btn_bulk.clicked.connect(self.on_bulk_clicked)
        self.btn_sequential.clicked.connect(self.on_sequential_clicked)
        self.btn_delete_last.clicked.connect(self.on_delete_last_clicked)
        self.btn_delete_rep.clicked.connect(self.on_delete_rep_clicked)

        self.is_running = False
        self.is_deleting = False
        self.queue = []
        self.last_generated_ids = []
        self.delete_queue_cpfs = []
        self.target_delete_count = 0
        self.current_ru_index = 0
        self.delete_chunks = []

    def closeEvent(self, event):
        self.settings.setValue(f"geometry_{self.prefix}", self.saveGeometry())
        self.clear_content()
        super().closeEvent(event)

    def clear_content(self):
        self.log_output.clear()
        self.count_input.setText("10")
        self.delete_count_input.setText("10")
        self.btn_delete_last.setVisible(False)
        self.last_generated_ids = []
        self.queue = []
        self.is_running = False
        self.is_deleting = False
        self.btn_bulk.setEnabled(True)
        self.btn_sequential.setEnabled(True)
        self.btn_delete_rep.setEnabled(True)

    def log(self, msg):
        self.log_output.append(msg)

    def generate_employee_data(self):
        return {
            "id": generate_cpf(),
            "nome": generate_random_name(),
            "matricula": "".join(random.choices("0123456789", k=5))
        }

    def on_bulk_clicked(self):
        if self.is_running or self.is_deleting: return
        try:
            count = int(self.count_input.text())
        except:
            QMessageBox.warning(self, "Erro", "Quantidade inválida")
            return

        employees = [self.generate_employee_data() for _ in range(count)]
        self.last_generated_ids = [emp['id'] for emp in employees]

        parts = []
        for emp in employees:
            parts.append(f"I[{emp['id']}[{emp['nome']}[0[1[{emp['matricula']}]")

        command_str = f"01+EU+00+{count}+" + "".join(parts)
        self.parent_app.send_external_command(command_str, self.prefix)
        self.log(f"Enviado comando bulk com {count} colaboradores.")
        self.btn_delete_last.setVisible(True)

    def on_sequential_clicked(self):
        if self.is_running or self.is_deleting: return
        try:
            count = int(self.count_input.text())
        except:
            QMessageBox.warning(self, "Erro", "Quantidade inválida")
            return

        self.queue = [self.generate_employee_data() for _ in range(count)]
        self.last_generated_ids = [emp['id'] for emp in self.queue]

        self.is_running = True
        self.btn_bulk.setEnabled(False)
        self.btn_sequential.setEnabled(False)
        self.btn_delete_last.setVisible(False)
        self.log(f"Iniciando envio sequencial de {count} colaboradores...")
        self.send_next_in_queue()

    def send_next_in_queue(self):
        if not self.queue:
            self.log("Envio sequencial concluído.")
            self.is_running = False
            self.btn_bulk.setEnabled(True)
            self.btn_sequential.setEnabled(True)
            self.btn_delete_last.setVisible(True)
            return

        emp = self.queue.pop(0)
        command_str = f"01+EU+00+1+I[{emp['id']}[{emp['nome']}[0[1[{emp['matricula']}]"
        self.parent_app.send_external_command(command_str, self.prefix)
        self.log(f"Enviando ({len(self.queue)} restantes): {emp['nome']}")

    def on_delete_last_clicked(self):
        if not self.last_generated_ids or self.is_deleting: return

        count = len(self.last_generated_ids)
        parts = [f"E[{id_val}]" for id_val in self.last_generated_ids]
        command_str = f"01+EU+00+{count}+" + "".join(parts)

        self.parent_app.send_external_command(command_str, self.prefix)
        self.log(f"Enviado comando de exclusão para os últimos {count} IDs gerados.")
        self.btn_delete_last.setVisible(False)
        self.last_generated_ids = []

    def on_delete_rep_clicked(self):
        if self.is_running or self.is_deleting: return
        try:
            self.target_delete_count = int(self.delete_count_input.text())
            if self.target_delete_count <= 0: raise ValueError()
        except:
            QMessageBox.warning(self, "Erro", "Quantidade inválida")
            return

        self.is_deleting = True
        self.delete_queue_cpfs = []
        self.current_ru_index = 0
        self.delete_chunks = []

        self.btn_bulk.setEnabled(False)
        self.btn_sequential.setEnabled(False)
        self.btn_delete_rep.setEnabled(False)

        self.log(f"Iniciando coleta de CPFs para deletar {self.target_delete_count} colaboradores...")
        self.request_next_cpfs()

    def request_next_cpfs(self):
        remaining = self.target_delete_count - len(self.delete_queue_cpfs)
        if remaining <= 0:
            self.start_deletion_phase()
            return

        batch_size = min(20, remaining)
        command_str = f"01+RU+00+{batch_size}]{self.current_ru_index}"
        self.parent_app.send_external_command(command_str, self.prefix)
        self.log(f"Coletando CPFs... (Índice: {self.current_ru_index}, Meta: {self.target_delete_count})")

    def start_deletion_phase(self):
        if not self.delete_queue_cpfs:
            self.log("Nenhum CPF coletado para deletar.")
            self.finish_deletion()
            return

        self.log(f"Coletados {len(self.delete_queue_cpfs)} CPFs. Iniciando exclusão...")
        self.delete_chunks = [self.delete_queue_cpfs[i:i + 20] for i in range(0, len(self.delete_queue_cpfs), 20)]
        self.send_next_delete_chunk()

    def send_next_delete_chunk(self):
        if not self.delete_chunks:
            self.log("Exclusão concluída.")
            self.finish_deletion()
            return

        chunk = self.delete_chunks.pop(0)
        count = len(chunk)
        parts = [f"E[{id_val}]" for id_val in chunk]
        command_str = f"01+EU+00+{count}+" + "".join(parts)

        self.parent_app.send_external_command(command_str, self.prefix)
        self.log(f"Enviando exclusão de {count} CPFs ({len(self.delete_chunks)} blocos restantes)...")

    def finish_deletion(self):
        self.is_deleting = False
        self.btn_bulk.setEnabled(True)
        self.btn_sequential.setEnabled(True)
        self.btn_delete_rep.setEnabled(True)

    def handle_response(self, text):
        if self.is_running:
            QTimer.singleShot(100, self.send_next_in_queue)
            return

        if self.is_deleting:
            if "+RU+" in text:
                cpfs = re.findall(r"(\d{11})\[", text)
                if not cpfs:
                    self.log("Nenhum CPF retornado na resposta RU. Iniciando exclusão com o que foi coletado.")
                    self.start_deletion_phase()
                    return

                added_count = 0
                for cpf in cpfs:
                    if cpf not in self.delete_queue_cpfs and len(self.delete_queue_cpfs) < self.target_delete_count:
                        self.delete_queue_cpfs.append(cpf)
                        added_count += 1

                self.log(f"Recebidos {len(cpfs)} CPFs ({added_count} novos). Total: {len(self.delete_queue_cpfs)}")

                if len(self.delete_queue_cpfs) >= self.target_delete_count:
                    self.start_deletion_phase()
                else:
                    self.current_ru_index += 20
                    QTimer.singleShot(100, self.request_next_cpfs)

            elif "+EU+" in text:
                QTimer.singleShot(100, self.send_next_delete_chunk)


# ══════════════════════════════════════════════════════════════════════
#  PROTOCOLO EVO REP  (inalterado)
# ══════════════════════════════════════════════════════════════════════

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


# ══════════════════════════════════════════════════════════════════════
#  CRIPTOGRAFIA  (inalterada)
# ══════════════════════════════════════════════════════════════════════

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
        if not key:
            return ciphertext.decode('utf-8', errors='ignore')

        if len(ciphertext) < 16 or len(ciphertext) % 16 != 0:
            return ciphertext.decode('utf-8', errors='ignore')

        iv = ciphertext[:16]
        actual_ciphertext = ciphertext[16:]

        if CRYPTO_BACKEND == "pycryptodome":
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(actual_ciphertext)
            return decrypted.rstrip(b'\x00').decode('utf-8', errors='replace')
        else:
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(actual_ciphertext) + decryptor.finalize()
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

        encrypted = pubkey.encrypt(data, padding.PKCS1v15())
        return encrypted


# ══════════════════════════════════════════════════════════════════════
#  WORKERS DE REDE  (inalterados)
# ══════════════════════════════════════════════════════════════════════

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


# ══════════════════════════════════════════════════════════════════════
#  UTILIDADES  (inalteradas)
# ══════════════════════════════════════════════════════════════════════

def get_local_ip():
    """Obtém o IP local priorizando interfaces do tipo Ethernet (cabo) via PowerShell."""
    import subprocess
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


# ══════════════════════════════════════════════════════════════════════
#  CHOICES DO COMANDO EC  (inalteradas)
# ══════════════════════════════════════════════════════════════════════

EC_VAL_CHOICES = {
    "LEITOR_VER_DIG":       [{"label": "H - Habilitado", "value": "H"}, {"label": "D - Desabilitado", "value": "D"}],
    "EVENTO_ON":            [{"label": "H - Habilitado", "value": "H"}, {"label": "D - Desabilitado", "value": "D"}],
    "EXP_NR_REP":           [{"label": "H - Habilitado", "value": "H"}, {"label": "D - Desabilitado", "value": "D"}],
    "TECLADO_MANUT":        [{"label": "H - Habilitado", "value": "H"}, {"label": "D - Desabilitado", "value": "D"}],
    "SENSOR_CORTE":         [{"label": "H - Habilitado", "value": "H"}, {"label": "D - Desabilitado", "value": "D"}],
    "FEW_PAPER":            [{"label": "H - Habilitado", "value": "H"}, {"label": "D - Desabilitado", "value": "D"}],
    "DIGITO_OCULTO":        [{"label": "H - Habilitado", "value": "H"}, {"label": "D - Desabilitado", "value": "D"}],
    "ACENTOS":              [{"label": "H - Habilitado", "value": "H"}, {"label": "D - Desabilitado", "value": "D"}],
    "NOBREAK":              [{"label": "H - Habilitado", "value": "H"}, {"label": "D - Desabilitado", "value": "D"}],
    "BEEP_TECLADO":         [{"label": "H - Habilitado", "value": "H"}, {"label": "D - Desabilitado", "value": "D"}],
    "BIO_PREVIEW":          [{"label": "H - Habilitado", "value": "H"}, {"label": "D - Desabilitado", "value": "D"}],
    "CON_SEGURA":           [{"label": "H - Habilitado", "value": "H"}, {"label": "D - Desabilitado", "value": "D"}],
    "RECONEXAO_IMEDIATA":   [{"label": "H - Habilitado", "value": "H"}, {"label": "D - Desabilitado", "value": "D"}],
    "NTP":                  [{"label": "H - Habilitado", "value": "H"}, {"label": "D - Desabilitado", "value": "D"}],
    "CON_SEGURA_W":         [{"label": "H - Habilitado", "value": "H"}, {"label": "D - Desabilitado", "value": "D"}],
    "RECONEXAO_IMEDIATA_W": [{"label": "H - Habilitado", "value": "H"}, {"label": "D - Desabilitado", "value": "D"}],
    "USAR_DNS_W":           [{"label": "H - Habilitado", "value": "H"}, {"label": "D - Desabilitado", "value": "D"}],
    "MODO_CADASTRO[P]":     [{"label": "P - Padrão",  "value": "P"}, {"label": "D - Dinâmico", "value": "D"}],
    "COR_SENSOR[G]":        [{"label": "G - Green",   "value": "G"}, {"label": "R - Red",      "value": "R"}, {"label": "B - Blue", "value": "B"}],
    "TEMPLATE[P]":          [{"label": "P - Padrão",  "value": "P"}, {"label": "I - ISO",       "value": "I"}, {"label": "A - ANSI", "value": "A"}],
    "VEL_SERIAL":           [{"label": "9600",   "value": "9600"},   {"label": "19200",  "value": "19200"},
                             {"label": "57600",  "value": "57600"},  {"label": "115200", "value": "115200"}],
    "TIPO_COM":             [{"label": "S - Serial",  "value": "S"}, {"label": "T - TCP",     "value": "T"}],
    "MODE":                 [{"label": "C - Cliente", "value": "C"}, {"label": "S - Servidor", "value": "S"}],
    "MODE_W":               [{"label": "C - Cliente", "value": "C"}, {"label": "S - Servidor", "value": "S"}],
}


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
                "session_key": None,
                "connected": False,
                "worker": None,
                "listener_worker": None,
                "last_sent_text": "",
                "last_sent_bytes": "",
                "last_received_text": "",
                "last_received_bytes": "",
                "reconnect_count": 0,
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

        self._setup_ui()
        self.load_config()

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

        self.stacked_widget.addWidget(self.main_tab)    # Index 0
        self.stacked_widget.addWidget(self.log_tab)     # Index 1
        self.stacked_widget.addWidget(self.client_tab)  # Index 2
        self.stacked_widget.addWidget(self.f3_tab)      # Index 3

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
        conn_layout.setContentsMargins(12, 20, 12, 12)
        conn_layout.setSpacing(8)

        conn_layout.addWidget(QLabel(""), 0, 0, 1, 2)  # Spacer topo

        conn_layout.addWidget(QLabel("IP:"), 1, 0)
        ip_val  = get_local_ip() if is_client_mode else "192.168.60.71"
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
            self.client_btn_server_control.setObjectName("primary_btn")
            self.client_btn_client_state = QPushButton("Aguardando Conexão")
            self.client_btn_client_state.setEnabled(False)

            client_btns_layout = QHBoxLayout()
            client_btns_layout.setSpacing(6)
            client_btns_layout.addWidget(self.client_btn_server_control)
            client_btns_layout.addWidget(self.client_btn_client_state)
            conn_layout.addLayout(client_btns_layout, 5, 0, 1, 2)

            self.client_btn_server_control.clicked.connect(self.on_connect_clicked)
            self.client_btn_client_state.clicked.connect(self.on_connect_clicked)

            # 🔹 REQUISITO: Botão Macro para F2 (Client Mode)
            macro_btn = QPushButton("Macro")
            macro_btn.setVisible(False)
            macro_btn.clicked.connect(lambda: self.on_macro_clicked(prefix))
            conn_layout.addWidget(macro_btn, 6, 0, 1, 2)
            setattr(self, f"{prefix}macro_button", macro_btn)

        elif is_f3:
            self.f3_connect_button = QPushButton("Conectar")
            self.f3_connect_button.setObjectName("primary_btn")
            self.f3_connect_button.clicked.connect(self.on_connect_clicked)
            conn_layout.addWidget(self.f3_connect_button, 5, 0, 1, 2)

        else:
            self.main_connect_button = QPushButton("Conectar")
            self.main_connect_button.setObjectName("primary_btn")
            self.main_connect_button.clicked.connect(self.on_connect_clicked)
            conn_layout.addWidget(self.main_connect_button, 5, 0, 1, 2)

            # 🔹 REQUISITO: Botão Macro (F1)
            macro_btn = QPushButton("Macro")
            macro_btn.setVisible(False)
            macro_btn.clicked.connect(lambda: self.on_macro_clicked(prefix))
            conn_layout.addWidget(macro_btn, 6, 0, 1, 2)
            setattr(self, f"{prefix}macro_button", macro_btn)

        conn_layout.setRowStretch(7, 1)

        # ── Painel de Comandos ─────────────────────────────────────
        if is_f3:
            cmds_group = QGroupBox("Identificação do Equipamento")
            cmds_group_layout = QFormLayout(cmds_group)
            cmds_group_layout.setSpacing(8)
            cmds_group_layout.setContentsMargins(12, 20, 12, 12)

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
            cmds_group_layout.setContentsMargins(12, 20, 12, 12)
            cmds_group_layout.setSpacing(8)

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
        sent_v.setContentsMargins(10, 18, 10, 10)
        sent_output = QTextEdit()
        sent_output.setReadOnly(True)
        sent_v.addWidget(sent_output)

        received_group = QGroupBox("String Recebida")
        recv_v = QVBoxLayout(received_group)
        recv_v.setContentsMargins(10, 18, 10, 10)
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

        setattr(self, f"{prefix}command_combo",         command_combo)
        setattr(self, f"{prefix}dynamic_layout",        dynamic_layout)
        setattr(self, f"{prefix}send_button",           send_button)
        setattr(self, f"{prefix}sent_output",           sent_output)
        setattr(self, f"{prefix}received_output",       received_output)
        setattr(self, f"{prefix}clear_button",          clear_button)
        setattr(self, f"{prefix}toggle_mode_button",    toggle_mode_button)
        setattr(self, f"{prefix}cmd_description_label", cmd_description_label)

        # ── Sinais ────────────────────────────────────────────────
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
        log_grp_v.setContentsMargins(10, 18, 10, 10)

        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        log_grp_v.addWidget(self.log_output)

        log_v.addWidget(log_group)
        return log_tab

    # ──────────────────────────────────────────────────────────────────
    #  HELPERS DE ABA ATIVA  (inalterados)
    # ──────────────────────────────────────────────────────────────────

    def _get_active_prefix(self):
        idx = self.stacked_widget.currentIndex()
        if idx == 0: return "main_"
        if idx == 2: return "client_"
        if idx == 3: return "f3_"
        return "main_"

    def _get_widget(self, name):
        prefix = self._get_active_prefix()
        return getattr(self, f"{prefix}{name}")

    # ──────────────────────────────────────────────────────────────────
    #  SELEÇÃO E CONSTRUÇÃO DINÂMICA DE PARÂMETROS  (inalterada)
    # ──────────────────────────────────────────────────────────────────

    def on_command_selected(self, index):
        prefix = self._get_active_prefix()
        dynamic_layout    = getattr(self, f"{prefix}dynamic_layout")
        command_combo     = getattr(self, f"{prefix}command_combo")
        cmd_description_label = getattr(self, f"{prefix}cmd_description_label")

        while dynamic_layout.rowCount() > 0:
            dynamic_layout.removeRow(0)
        self.param_inputs.clear()

        cmd_code = command_combo.currentData()

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

            pending_data_field = None
            pending_data_label = None

            for param in cmd_def.params:
                label_text = f"{param.name} {'' if param.required else '(opcional)'}:"

                if param.choices:
                    if cmd_code == "RC" and "config" in cmd_def.description.lower():
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
        config_combo   = self.param_inputs.get("Configuração")
        if not config_combo: return

        config_key = config_combo.currentData()

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
            if config_key == "LOGIN":         new_input.setPlaceholderText("Máx 16 caracteres")
            elif config_key == "SENHA_MENU":  new_input.setPlaceholderText("6 dígitos")
            elif config_key == "MENSAGEM":    new_input.setPlaceholderText("Máx 20 caracteres")
            elif config_key == "ACORDO_SIND": new_input.setPlaceholderText("17 dígitos")
            elif config_key == "TAM_BOB":     new_input.setPlaceholderText("0 ~ 400")
            elif config_key == "TEMPO_LIB":   new_input.setPlaceholderText("0 ~ 60")
            elif config_key == "NTP_TIMEOUT": new_input.setPlaceholderText("1 ~ 99")
            elif any(x in config_key for x in ["IP", "DNS", "GATEWAY", "SERVER_IP"]):
                new_input.setPlaceholderText("Ex: 192.168.1.100")
            elif "PORTA" in config_key or "SERVER_PORT" in config_key:
                new_input.setPlaceholderText("1000 ~ 65535")

        if hasattr(new_input, "returnPressed"):
            new_input.returnPressed.connect(self.on_enter_pressed)
        
        if isinstance(new_input, QLineEdit) and any(x in config_key for x in ["IP", "DNS", "GATEWAY", "SERVER_IP"]):
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
                        command_str = f"01+ED+00+D]{mat_val}}}{count}}}1{{"+"".join(tp_parts) # O formato pede n{template
                        # Ajustando para o formato exato solicitado: 01+ED+00+D]{Matricula}}{QuantTPs}}1{TP1 2{TP2...
                        res_parts = []
                        for idx, part in enumerate(tp_parts):
                            res_parts.append(part)
                        command_str = f"01+ED+00+D]{mat_val}}}{count}}}" + "".join(res_parts)
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
                    tipo        = "L]D" if radio_group and radio_group.checkedButton().text() == "DUAL" else "L"
                    qty         = self.param_inputs.get("Quantidade").text().strip()
                    idx         = self.param_inputs.get("Indice").text().strip()
                    command_str = f"01+RD+00+{tipo}]{qty}}}{idx}"
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
        elif event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            self.on_enter_pressed()
        else:
            super().keyPressEvent(event)

    def on_enter_pressed(self):
        prefix = self._get_active_prefix()
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
        if prefix == "f3_": return
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
        self.settings.setValue("active_tab", self.stacked_widget.currentIndex())

        prefix     = self._get_active_prefix()
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
        self.update_sent_received_output(prefix)

    def append_sent_bytes(self, hex_text: str, prefix=None):
        if prefix is None: prefix = self._get_active_prefix()
        state = self.tab_data[prefix]
        if state["last_sent_bytes"]: state["last_sent_bytes"] += "\n" + hex_text
        else: state["last_sent_bytes"] = hex_text
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

        # 🔹 REQUISITO: Se houver macro rodando, notificar a janela
        if hasattr(self, f"{prefix}macro_window"):
            window = getattr(self, f"{prefix}macro_window")
            if window.is_running or getattr(window, 'is_deleting', False):
                window.handle_response(text)

        # 🔹 Lógica especial para processar resposta RB na aba F3
        if prefix == "f3_":
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

            elif "00+00+015" in text:
                self.append_log(f"F3: Erro 015 detectado na resposta: {text}")
                if state["reconnect_count"] < 3:
                    state["reconnect_count"] += 1
                    self.append_log(f"F3: Iniciando ciclo de reconexão automática {state['reconnect_count']}/3...")
                    self.disconnect(prefix)
                    QTimer.singleShot(500, self.on_connect_clicked)
                else:
                    self.append_log("F3: Erro 015 persistente após 3 tentativas. Reconexão automática interrompida.")
                    state["reconnect_count"] = 0

        if state["last_received_text"]: state["last_received_text"] += "\n" + text
        else: state["last_received_text"] = text
        self.update_sent_received_output(prefix)

    def append_received_bytes(self, hex_text: str, prefix=None):
        if prefix is None: prefix = self._get_active_prefix()
        state = self.tab_data[prefix]
        if state["last_received_bytes"]: state["last_received_bytes"] += "\n" + hex_text
        else: state["last_received_bytes"] = hex_text
        self.update_sent_received_output(prefix)

    # ──────────────────────────────────────────────────────────────────
    #  CONTROLES DA UI  (inalterados)
    # ──────────────────────────────────────────────────────────────────

    def on_toggle_display_mode(self):
        self.show_bytes = not self.show_bytes
        btn_text = "📄  Exibir em string" if self.show_bytes else "🔢  Exibir em bytes"
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

    def on_connect_clicked(self):
        prefix = self._get_active_prefix()
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

        ip        = getattr(self, f"{prefix}ip_input").text().strip()
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
                ip        = getattr(self, f"{prefix}ip_input").text().strip()
                port_text = getattr(self, f"{prefix}port_input").text().strip()
                user      = getattr(self, f"{prefix}user_input").text().strip()
                password  = getattr(self, f"{prefix}password_input").text().strip()
                try:
                    port = int(port_text)
                    state["worker"] = ClientNetworkWorker(ip, port, user, password)
                    state["worker"].log_signal.connect(self.append_log)
                    state["worker"].finished_signal.connect(lambda s, m, sk, key: self.on_finished(s, m, sk, key, prefix))
                    state["worker"].start()
                    self.append_log("Servidor reiniciado para aguardar nova conexão.")
                except:
                    pass

        getattr(self, f"{prefix}send_button").setEnabled(False)
        self.set_inputs_enabled(True, prefix)
        self.append_log(f"Equipamento desconectado. Servidor permanece ativo ({prefix}).")

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
        state["connected"]   = False

        if prefix == "main_":
            self.connect_timer.stop()
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
            state["session_key"]     = session_key
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

            if prefix != "f3_":
                QMessageBox.information(self, "Conexão", f"Conexão bem sucedida ({prefix})")

        else:
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

            getattr(self, f"{prefix}send_button").setEnabled(False)
            self.set_inputs_enabled(True, prefix)

            if "Operação cancelada pelo usuário" in message or "Servidor parado pelo usuário" in message:
                return

            if "10013" in message or "10048" in message:
                message = "Soquete em uso por outra aplicação"
            QMessageBox.critical(self, "Erro de Conexão", message)


# ══════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════════

def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")      # base neutra para o QSS funcionar uniformemente
    window = EvoRepAuthApp()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()