# constants.py

APP_VERSION = "0.7.7"

# ══════════════════════════════════════════════════════════════════════
#  CATEGORIAS DE CONFIGURAÇÃO (EC)
# ══════════════════════════════════════════════════════════════════════

EC_CATEGORIES = {
    "Geral": [
        "LOGIN", "SENHA_MENU", "LEITOR_VER_DIG", "TAM_BOB", "EVENTO_ON", 
        "EXP_NR_REP", "TECLADO_MANUT", "SENSOR_CORTE", "FEW_PAPER", 
        "DIGITO_OCULTO", "ACENTOS", "MENSAGEM", "NOBREAK", "GMT", 
        "BEEP_TECLADO", "MODO_CADASTRO", "BIO_PREVIEW", "TEMPLATE", 
        "ACORDO_SIND", "TEMPO_LIB"
    ],
    "REDE RJ45": [
        "IP", "MASC_SUBREDE", "DNS", "GATEWAY", "MAC", "PORTA_TCP", 
        "TIPO_COM", "CON_SEGURA", "IP_CON_SEGURA", "DHCP", "MODE", 
        "RECONEXAO_IMEDIATA", "IP_SERVER", "SERVER_PORT", "HOSTNAME"
    ],
    "NTP": ["NTP", "NTP_SERVER", "NTP_TIMEOUT"],
    "REDE WIFI": [
        "IP_W", "MASC_SUBREDE_W", "DNS_W", "GATEWAY_W", "MAC_W", 
        "PORTA_TCP_W", "CON_SEGURA_W", "IP_CON_SEGURA_W", "DHCP_W", 
        "MODE_W", "RECONEXAO_IMEDIATA_W", "IP_SERVER_W", "SERVER_PORT_W", 
        "USAR_DNS_W", "ADDR_SERVER_W", "NET_NAME", "NET_PWD", 
        "NET_NAME_02", "NET_PWD_02"
    ]
}

# ══════════════════════════════════════════════════════════════════════
#  CATEGORIAS DE CONFIGURAÇÃO (RC)
# ══════════════════════════════════════════════════════════════════════

RC_CATEGORIES = {
    "Geral": [
        "LOGIN", "SENHA_MENU", "LEITOR_VER_DIG", "TAM_BOB", "EVENTO_ON", 
        "EXP_NR_REP", "TECLADO_MANUT", "SENSOR_CORTE", "FEW_PAPER", 
        "DIGITO_OCULTO", "ACENTOS", "MENSAGEM", "NOBREAK", "GMT", 
        "BEEP_TECLADO", "MODO_CADASTRO", "BIO_PREVIEW", "TEMPLATE", 
        "ACORDO_SIND", "TEMPO_LIB"
    ],
    "Equipamento": [
        "NR_REP", "LEITOR_CARTAO", "LEITOR_BIOMETRIA", "MODELO", 
        "ID_SOFTWARE", "CHAVE_PUBLICA", "VERSAO_PRODUTO", "VERSAO_MEM", 
        "VERSAO_PROTOCOLO"
    ],
    "REDE RJ45": [
        "IP", "MASC_SUBREDE", "DNS", "GATEWAY", "MAC", "PORTA_TCP", 
        "TIPO_COM", "CON_SEGURA", "IP_CON_SEGURA", "DHCP", "MODE", 
        "RECONEXAO_IMEDIATA", "IP_SERVER", "SERVER_PORT", "HOSTNAME"
    ],
    "NTP": ["NTP", "NTP_SERVER", "NTP_TIMEOUT"],
    "REDE WIFI": [
        "IP_W", "MASC_SUBREDE_W", "DNS_W", "GATEWAY_W", "MAC_W", 
        "PORTA_TCP_W", "CON_SEGURA_W", "IP_CON_SEGURA_W", "DHCP_W", 
        "MODE_W", "RECONEXAO_IMEDIATA_W", "IP_SERVER_W", "SERVER_PORT_W", 
        "USAR_DNS_W", "ADDR_SERVER_W", "NET_NAME", "NET_PWD", 
        "NET_NAME_02", "NET_PWD_02"
    ]
}


# ══════════════════════════════════════════════════════════════════════
#  CHOICES DO COMANDO EC
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
    "MODO_CADASTRO":        [{"label": "P - Padrão",  "value": "P"}, {"label": "D - Dinâmico", "value": "D"}],
    "COR_SENSOR":           [{"label": "G - Green",   "value": "G"}, {"label": "R - Red",      "value": "R"}, {"label": "B - Blue", "value": "B"}],
    "TEMPLATE":             [{"label": "P - Padrão",  "value": "P"}, {"label": "I - ISO",       "value": "I"}, {"label": "A - ANSI", "value": "A"}],
    "VEL_SERIAL":           [{"label": "9600",   "value": "9600"},   {"label": "19200",  "value": "19200"},
                             {"label": "57600",  "value": "57600"},  {"label": "115200", "value": "115200"}],
    "TIPO_COM":             [{"label": "S - Serial",  "value": "S"}, {"label": "T - TCP",     "value": "T"}],
    "MODE":                 [{"label": "C - Cliente", "value": "C"}, {"label": "S - Servidor", "value": "S"}],
    "MODE_W":               [{"label": "C - Cliente", "value": "C"}, {"label": "S - Servidor", "value": "S"}],
}
