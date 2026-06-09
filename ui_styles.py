# ui_styles.py

def build_qss(dark: bool = False) -> str:
    """Retorna a folha de estilo QSS completa para o tema claro ou escuro."""
    if dark:
        bg         = "#16161A"
        surface    = "#1F1F27"
        surface2   = "#28282F"
        border     = "#38383F"
        text       = "#E8E8F2"
        text_muted = "#7878A0"
        primary    = "#2CBA75"
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
        primary    = "#2CBB75"
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

/* ── CANCEL BUTTON ───────────────────────────────────── */
QPushButton#cancel_btn {{
    background-color: {danger};
    color: #FFFFFF;
    border: none;
    border-radius: 7px;
    padding: 7px 5px;
    font-weight: 700;
    font-size: 13px;
}}
QPushButton#cancel_btn:hover {{
    background-color: {danger_h};
}}
QPushButton#cancel_btn:pressed {{
    background-color: {danger_h};
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

/* ── PROGRESS BAR ────────────────────────────────────── */
QProgressBar {{
    background-color: {surface2};
    color: {text};
    border: 1.5px solid {border};
    border-radius: 6px;
    text-align: center;
    font-weight: 700;
    font-size: 11px;
}}
QProgressBar::chunk {{
    background-color: {primary};
    border-radius: 4px;
    margin: 1px;
}}
"""
