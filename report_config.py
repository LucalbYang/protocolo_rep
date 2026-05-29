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

# ── ES (Enviar Usuário do Sistema) ────────────────────────────────────
ES_CPF   = "26571383063"
ES_LOGIN = "teste fabrica"
ES_SENHA = "111111"
ES_CARTAO = "525521"

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
    "LOGIN", "LEITOR_VER_DIG", "TAM_BOB", "EVENTO_ON", "SENSOR_CORTE",
    "GMT", "MODO_CADASTRO", "TEMPLATE", "IP", "PORTA_TCP",
    "TIPO_COM", "CON_SEGURA", "MODE", "NTP", "NTP_SERVER",
    "VERSAO_PRODUTO", "VERSAO_PROTOCOLO", "NR_REP", "MODELO"
]
