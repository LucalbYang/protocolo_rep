# report_config.py
# Valores utilizados pelo Relatório de Testes (F5).
# Edite conforme necessário antes de gerar o relatório.

# ── EH (Enviar Data/Hora) ─────────────────────────────────────────────
# Serão preenchidos dinamicamente com datetime.now() no worker. Não editar.
EH_DATA  = "DINAMICO"   # DD/MM/AA — substituído em runtime
EH_HORA  = "DINAMICO"   # HH:MM:SS — substituído em runtime

# ── EE (Enviar Empregador) ────────────────────────────────────────────
EE_ID    = "44880091000172"                  # CNPJ (14 dígitos) ou CPF (11)
EE_NOME  = "EVO Sistemas Inteligentes LTDA"
EE_LOCAL = "Rio Piquiri, 400"

# ── EU (Enviar Colaborador) ───────────────────────────────────────────
EU_CPF = "26571383063"
EU_NOME      = "Colaborador Teste"
EU_BIO    = "0"
EU_QMAT     = "2"   # Qtd de matriculas
EU_MAT1      = "1"   # Primeira matrícula
EU_MAT2      = "4132669"   # Segunda matrícula

# ── RU (Receber Colaboradores) ────────────────────────────────────────
RU_QUANTIDADE = 5
RU_INDICE     = 0
RU_MATRICULA  = "1"
RU_CPF        = "26571383063"

# ── RR (Receber Registros) ────────────────────────────────────────────
RR_QUANTIDADE = 5
RR_ENDERECO   = 0      # Para RR_MEMORIA
RR_NSR        = 1      # Para RR_NSR
RR_DATA       = "01/01/2025"   # DD/MM/AAAA — Para RR_DATA
RR_HORA       = "00:00:00"   # HH:MM:SS — Para RR_DATA

# ── RD (Receber Biometria) ────────────────────────────────────────────
RD_QUANTIDADE = 10
RD_INDICE     = 0
RD_MATRICULA  = "1"

# ── ED (Biometria — Cadastrar/Deletar) ────────────────────────────────
ED_MATRICULA  = "1"

# ── RQ (Status) — todas as variantes serão enviadas automaticamente ───
# Nenhuma configuração necessária.

# ── RC (Receber Configuração) — lista das configurações a consultar ───
# Edite para incluir/remover configurações do relatório.
RC_PARAMS = [
    "LOGIN", "SENHA_MENU", "LEITOR_VER_DIG", "TAM_BOB", "EVENTO_ON", "EXP_NR_REP", 
    "TECLADO_MANUT", "SENSOR_CORTE", "FEW_PAPER", "DIGITO_OCULTO", "ACENTOS", 
    "MENSAGEM", "NOBREAK", "GMT", "BEEP_TECLADO", "NR_REP", "LEITOR_CARTAO", 
    "LEITOR_BIOMETRIA", "MODELO", "ID_SOFTWARE", "CHAVE_PUBLICA", "VERSAO_PRODUTO", 
    "VERSAO_MEM", "VERSAO_PROTOCOLO", "MODO_CADASTRO", "BIO_PREVIEW", "TEMPLATE", 
    "ACORDO_SIND", "TEMPO_LIB", "IP", "MASC_SUBREDE", "DNS", "GATEWAY", "MAC", 
    "PORTA_TCP", "TIPO_COM", "CON_SEGURA", "IP_CON_SEGURA", "DHCP", "MODE", 
    "RECONEXAO_IMEDIATA", "IP_SERVER", "SERVER_PORT", "HOSTNAME", "NTP", 
    "NTP_SERVER", "NTP_TIMEOUT", "IP_W", "MASC_SUBREDE_W", "DNS_W", "GATEWAY_W", 
    "MAC_W", "PORTA_TCP_W", "CON_SEGURA_W", "IP_CON_SEGURA_W", "DHCP_W", "MODE_W", 
    "RECONEXAO_IMEDIATA_W", "IP_SERVER_W", "SERVER_PORT_W", "USAR_DNS_W", 
    "ADDR_SERVER_W", "NET_NAME", "NET_PWD", "NET_NAME_02", "NET_PWD_02"
]
