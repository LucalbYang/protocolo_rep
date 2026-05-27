# widgets.py
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QComboBox)
from constants import APP_VERSION

class NoScrollComboBox(QComboBox):
    """QComboBox que ignora scroll do mouse e teclas de seta para evitar mudanças acidentais."""
    def wheelEvent(self, event):
        event.ignore()

    def keyPressEvent(self, event):
        if event.key() in (Qt.Key.Key_Up, Qt.Key.Key_Down):
            event.ignore()
        else:
            super().keyPressEvent(event)

class DynamicIPComboBox(NoScrollComboBox):
    """ComboBox que emite sinal antes de mostrar o popup, útil para atualizar dados sob demanda."""
    aboutToShowPopup = pyqtSignal()

    def showPopup(self):
        self.aboutToShowPopup.emit()
        super().showPopup()


class NotificationCard(QWidget):
    """Card temporário que aparece no canto inferior direito."""
    def __init__(self, parent, message, color="#2ECC71"):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setFixedWidth(300)
        self.setFixedHeight(80)
        
        layout = QVBoxLayout(self)
        self.label = QLabel(message)
        self.label.setWordWrap(True)
        self.label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.label.setStyleSheet("color: white; font-weight: bold; font-size: 13px; background: transparent;")
        layout.addWidget(self.label)
        
        self.setStyleSheet(f"background-color: {color}; border-radius: 10px;")
        
        # Posicionamento inicial (será ajustado no show)
        self.move_to_corner()
        
        self.timer = QTimer(self)
        self.timer.setSingleShot(True)
        self.timer.timeout.connect(self.close)
        self.timer.start(3000) # 3 segundos
        
        self.show()

    def move_to_corner(self):
        if self.parentWidget():
            p_rect = self.parentWidget().rect()
            self.move(p_rect.width() - self.width() - 20, p_rect.height() - self.height() - 20)

    def resizeEvent(self, event):
        self.move_to_corner()
        super().resizeEvent(event)


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
