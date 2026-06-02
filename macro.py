# macro.py
import re
import random
from PyQt6.QtCore import Qt, QTimer, QSettings
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QLineEdit, QGroupBox, QFormLayout, 
                             QFrame, QMessageBox, QRadioButton, QButtonGroup)
from utils import generate_cpf, generate_random_name

class MacroWindow(QWidget):
    def __init__(self, parent_app, prefix):
        super().__init__()
        self.parent_app = parent_app
        self.prefix = prefix
        self.setWindowTitle(f"Macro — {prefix.replace('_', '').upper()}")
        self.setMinimumSize(360, 430)
        self.setMaximumWidth(460)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        # ── Gerar colaboradores ──────────────────────────────────
        group_box = QGroupBox("Gerar Colaboradores")
        group_layout = QFormLayout(group_box)
        group_layout.setSpacing(6)
        group_layout.setContentsMargins(10, 14, 10, 10)

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
        delete_layout.setSpacing(6)
        delete_layout.setContentsMargins(10, 14, 10, 10)

        self.delete_count_input = QLineEdit("10")
        delete_layout.addRow("Quantidade:", self.delete_count_input)

        self.btn_delete_rep = QPushButton("Deletar")
        self.btn_delete_rep.setObjectName("danger_btn")
        delete_layout.addRow(self.btn_delete_rep)

        layout.addWidget(delete_group_box)

        # ── Deletar Todas as Biometrias ───────────────────────────
        bio_group_box = QGroupBox("Deletar Todas as biometrias")
        bio_layout = QVBoxLayout(bio_group_box)
        bio_layout.setSpacing(6)
        bio_layout.setContentsMargins(10, 14, 10, 10)

        radio_layout = QHBoxLayout()
        self.radio_unica = QRadioButton("ÚNICA")
        self.radio_dual = QRadioButton("DUAL")
        self.radio_unica.setChecked(True)
        radio_layout.addWidget(self.radio_unica)
        radio_layout.addWidget(self.radio_dual)
        
        self.btn_delete_all_bio = QPushButton("Deletar Todas")
        self.btn_delete_all_bio.setObjectName("danger_btn")

        bio_layout.addLayout(radio_layout)
        bio_layout.addWidget(self.btn_delete_all_bio)

        layout.addWidget(bio_group_box)

        # ── Status (linha única) ──────────────────────────────────
        status_frame = QFrame()
        status_frame.setFrameShape(QFrame.Shape.StyledPanel)
        status_frame.setObjectName("status_frame")
        status_h = QHBoxLayout(status_frame)
        status_h.setContentsMargins(10, 6, 10, 6)
        status_h.setSpacing(6)
        dot = QLabel("●")
        dot.setObjectName("status_dot")
        dot.setFixedWidth(14)
        self.status_label = QLabel("Aguardando ação...")
        self.status_label.setObjectName("status_text")
        self.status_label.setWordWrap(False)
        status_h.addWidget(dot)
        status_h.addWidget(self.status_label, 1)
        layout.addWidget(status_frame)

        # PERSISTÊNCIA: Carregar posição e tamanho salvos
        self.settings = QSettings("EvoRep", "MacroWindow")
        geom = self.settings.value(f"geometry_{self.prefix}")
        if geom:
            self.restoreGeometry(geom)

        self.btn_bulk.clicked.connect(self.on_bulk_clicked)
        self.btn_sequential.clicked.connect(self.on_sequential_clicked)
        self.btn_delete_last.clicked.connect(self.on_delete_last_clicked)
        self.btn_delete_rep.clicked.connect(self.on_delete_rep_clicked)
        self.btn_delete_all_bio.clicked.connect(self.on_delete_all_bio_clicked)

        self.is_running = False
        self.is_deleting = False
        self.queue = []
        self.last_generated_ids = []
        self.delete_queue_cpfs = []
        self.target_delete_count = 0
        self.current_ru_index = 0
        self.delete_chunks = []
        self.is_deleting_bio = False
        self.bio_delete_phase = ""
        self.bio_total_1 = 0
        self.bio_total_2 = 0
        self.bio_current_index = 0
        self.bio_matriculas = []
        self.bio_type = "UNICA"
        self.bio_dual_phase = "D"

    def closeEvent(self, event):
        self.settings.setValue(f"geometry_{self.prefix}", self.saveGeometry())
        self.clear_content()
        super().closeEvent(event)

    def clear_content(self):
        self.status_label.setText("Aguardando ação...")
        self.count_input.setText("10")
        self.delete_count_input.setText("10")
        self.btn_delete_last.setVisible(False)
        self.last_generated_ids = []
        self.queue = []
        self.is_running = False
        self.is_deleting = False
        self.is_deleting_bio = False
        self.btn_bulk.setEnabled(True)
        self.btn_sequential.setEnabled(True)
        self.btn_delete_rep.setEnabled(True)
        self.btn_delete_all_bio.setEnabled(True)
        self.radio_unica.setEnabled(True)
        self.radio_dual.setEnabled(True)

    def log(self, msg):
        self.status_label.setText(msg)

    def generate_employee_data(self):
        return {
            "id": generate_cpf(),
            "nome": generate_random_name(),
            "matricula": "".join(random.choices("0123456789", k=6))
        }

    def on_bulk_clicked(self):
        if self.is_running or self.is_deleting or self.is_deleting_bio: return
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
        if self.is_running or self.is_deleting or self.is_deleting_bio: return
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
        if not self.last_generated_ids or self.is_deleting or self.is_deleting_bio: return

        count = len(self.last_generated_ids)
        parts = [f"E[{id_val}]" for id_val in self.last_generated_ids]
        command_str = f"01+EU+00+{count}+" + "".join(parts)

        self.parent_app.send_external_command(command_str, self.prefix)
        self.log(f"Enviado comando de exclusão para os últimos {count} IDs gerados.")
        self.btn_delete_last.setVisible(False)
        self.last_generated_ids = []

    def on_delete_rep_clicked(self):
        if self.is_running or self.is_deleting or self.is_deleting_bio: return
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

    def on_delete_all_bio_clicked(self):
        if self.is_running or self.is_deleting or self.is_deleting_bio: return
        
        self.is_deleting_bio = True
        self.bio_delete_phase = "quantity"
        self.bio_type = "UNICA" if self.radio_unica.isChecked() else "DUAL"
        self.bio_total_1 = 0
        self.bio_total_2 = 0
        self.bio_dual_phase = "D"
        
        self.btn_bulk.setEnabled(False)
        self.btn_sequential.setEnabled(False)
        self.btn_delete_rep.setEnabled(False)
        self.btn_delete_all_bio.setEnabled(False)
        self.radio_unica.setEnabled(False)
        self.radio_dual.setEnabled(False)

        # 1. Coletar quantidade de biometrias
        command_str = "01+RQ+00+D"
        self.parent_app.send_external_command(command_str, self.prefix)
        self.log("Coletando quantidade de biometrias...")

    def request_next_bio_matriculas(self):
        if self.bio_type == "UNICA":
            cmd = f"01+RD+00+L]100}}{self.bio_current_index}"
        else:
            if self.bio_dual_phase == "D":
                cmd = f"01+RD+00+L]D]100}}{self.bio_current_index}"
            else:
                cmd = f"01+RD+00+L]F]100}}{self.bio_current_index}"
            
        self.parent_app.send_external_command(cmd, self.prefix)
        
    def send_next_bio_delete(self):
        if not self.bio_matriculas:
            self.log("Exclusão de biometrias concluída.")
            self.finish_bio_deletion()
            return
            
        mat = self.bio_matriculas.pop(0)
        cmd = f"01+ED+00+E]{mat}"
        self.parent_app.send_external_command(cmd, self.prefix)
        self.log(f"Deletando biometria matrícula {mat} ({len(self.bio_matriculas)} restantes)...")

    def finish_bio_deletion(self):
        self.is_deleting_bio = False
        self.btn_bulk.setEnabled(True)
        self.btn_sequential.setEnabled(True)
        self.btn_delete_rep.setEnabled(True)
        self.btn_delete_all_bio.setEnabled(True)
        self.radio_unica.setEnabled(True)
        self.radio_dual.setEnabled(True)

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

        if self.is_deleting_bio:
            if self.bio_delete_phase == "quantity":
                # Resposta esperada: 01+RQ+000+D]{biometrias}
                if "+RQ+" in text and ("+D]" in text or "+D}" in text or "+D" in text):
                    try:
                        data_part = text.split("+D", 1)[1]
                        # Remove non-numeric prefixes/suffixes from the data part just to be clean
                        # Extract all numbers and sum them
                        nums = re.findall(r'\d+', data_part)
                        if self.bio_type == "UNICA":
                            self.bio_total_1 = sum(int(n) for n in nums)
                            self.bio_total_2 = 0
                        else:
                            self.bio_total_1 = int(nums[0]) if len(nums) > 0 else 0
                            self.bio_total_2 = int(nums[1]) if len(nums) > 1 else 0
                    except Exception as e:
                        self.log("Erro ao ler quantidade de biometrias.")
                        self.finish_bio_deletion()
                        return
                        
                    if self.bio_total_1 == 0 and (self.bio_type == "UNICA" or self.bio_total_2 == 0):
                        self.log("Nenhuma biometria cadastrada.")
                        self.finish_bio_deletion()
                        return
                    
                    if self.bio_type == "DUAL":
                        self.log(f"Quantidade de biometrias: D={self.bio_total_1}, F={self.bio_total_2}. Coletando matrículas...")
                    else:
                        self.log(f"Quantidade de biometrias: {self.bio_total_1}. Coletando matrículas...")
                        
                    self.bio_current_index = 0
                    self.bio_matriculas = []
                    self.bio_delete_phase = "matriculas"
                    self.bio_dual_phase = "F"
                    if self.bio_type == "DUAL" and self.bio_total_1 == 0:
                        self.bio_dual_phase = "D"
                        
                    QTimer.singleShot(100, self.request_next_bio_matriculas)
                    return
            elif self.bio_delete_phase == "matriculas":
                if "+RD+" in text and "+L]" in text:
                    data_part = text.split("+L]", 1)[1]
                    if data_part.startswith("D}") or data_part.startswith("D]") or data_part.startswith("F}") or data_part.startswith("F]"):
                        data_part = data_part[2:]
                        
                    mats = re.split(r'[\]\}]', data_part)
                    mats = [m.strip() for m in mats if m.strip()]
                    
                    self.bio_matriculas.extend(mats)
                    self.bio_matriculas = list(dict.fromkeys(self.bio_matriculas))
                    
                    self.log(f"Coletadas {len(self.bio_matriculas)} matrículas...")
                    
                    self.bio_current_index += 100
                    
                    if self.bio_type == "UNICA":
                        if self.bio_current_index < self.bio_total_1:
                            QTimer.singleShot(100, self.request_next_bio_matriculas)
                        else:
                            self.log(f"Total de matrículas coletadas: {len(self.bio_matriculas)}. Iniciando exclusão...")
                            self.bio_delete_phase = "delete"
                            QTimer.singleShot(100, self.send_next_bio_delete)
                    else: # DUAL
                        if self.bio_dual_phase == "F":
                            if self.bio_current_index < self.bio_total_1:
                                QTimer.singleShot(100, self.request_next_bio_matriculas)
                            else:
                                self.bio_dual_phase = "D"
                                self.bio_current_index = 0
                                if self.bio_total_2 > 0:
                                    QTimer.singleShot(100, self.request_next_bio_matriculas)
                                else:
                                    self.log(f"Total de matrículas coletadas: {len(self.bio_matriculas)}. Iniciando exclusão...")
                                    self.bio_delete_phase = "delete"
                                    QTimer.singleShot(100, self.send_next_bio_delete)
                        else: # phase D
                            if self.bio_current_index < self.bio_total_2:
                                QTimer.singleShot(100, self.request_next_bio_matriculas)
                            else:
                                self.log(f"Total de matrículas coletadas: {len(self.bio_matriculas)}. Iniciando exclusão...")
                                self.bio_delete_phase = "delete"
                                QTimer.singleShot(100, self.send_next_bio_delete)
                    return

            elif self.bio_delete_phase == "delete":
                QTimer.singleShot(100, self.send_next_bio_delete)
                return
