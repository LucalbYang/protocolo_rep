# comandos_protocolo.py
from dataclasses import dataclass, field
from typing import List, Any, Dict

@dataclass
class CommandParam:
    name: str
    type: type
    default: Any = ""
    description: str = ""
    required: bool = True
    choices: List[Dict[str, str]] = field(default_factory=list) # Lista de {'label': ..., 'value': ...}

@dataclass
class CommandDefinition:
    code: str
    description: str
    template: str
    params: List[CommandParam] = field(default_factory=list)

    def build(self, **kwargs) -> str:
        """
        Valida os parâmetros recebidos e formata a string do comando baseada no template.
        """
        safe_kwargs = {}
        
        # Iterar sobre os parâmetros exigidos pelo comando
        for param in self.params:
            val = kwargs.get(param.name, param.default)
            
            # Validação de campos obrigatórios
            if param.required and (val is None or val == ""):
                raise ValueError(f"O parâmetro obrigatório '{param.name}' não pode estar vazio.")
            
            # Se houver choices, validar se o valor é um dos valores permitidos (ou uma combinação válida separada por ])
            if param.choices:
                valid_values = [c['value'] for c in param.choices]
                
                # Se o valor completo já é válido, não precisamos processar split
                if val in valid_values:
                    pass
                # Se o valor contém ']', tentamos validar como uma combinação (exceto se o valor completo for o válido acima)
                elif ']' in str(val):
                    parts = str(val).split(']')
                    # Remove partes vazias resultantes de split no final (ex: "A]B]" -> ["A", "B", ""])
                    parts = [p for p in parts if p]
                    for part in parts:
                        if part not in valid_values:
                            raise ValueError(f"O valor '{part}' dentro da combinação não é válido para o parâmetro '{param.name}'.")
                else:
                    # Tenta encontrar o valor pelo label caso o usuário tenha passado o texto do combo
                    val_by_label = next((c['value'] for c in param.choices if c['label'] == val), None)
                    if val_by_label:
                        val = val_by_label
                    else:
                        raise ValueError(f"Valor '{val}' inválido para o parâmetro '{param.name}'.")

            safe_kwargs[param.name] = str(val)

        # 🔹 REQUISITO: Incluir outros kwargs que podem ter sido injetados manualmente (ex: Tipo no EE)
        for key, value in kwargs.items():
            if key not in safe_kwargs:
                safe_kwargs[key] = str(value)

        try:
            # Constrói a string injetando o código e os parâmetros dinâmicos
            res = self.template.format(code=self.code, **safe_kwargs)
            # Se o comando termina em + porque o último parâmetro opcional está vazio, removemos o +
            if res.endswith('+') and not self.template.endswith('+'):
                res = res.rstrip('+')
            return res
        except KeyError as e:
            raise ValueError(f"Erro na formatação do comando: Placeholder {e} não fornecido.")

# Dicionário de registro para armazenar os comandos disponíveis
COMMANDS_REGISTRY: Dict[str, CommandDefinition] = {}

def registrar_comando(cmd: CommandDefinition):
    """Adiciona um comando ao catálogo."""
    COMMANDS_REGISTRY[cmd.code] = cmd


# ==========================================
# CATÁLOGO DE COMANDOS (Adicione novos aqui)
# ==========================================

registrar_comando(CommandDefinition(
    code="RQ",
    description="Quantidades e Status: Retorna informações sobre o estado e contadores do equipamento.",
    template="01+{code}+00+{Parâmetro}",
    params=[
        CommandParam(
            name="Parâmetro",
            type=str,
            description="Selecione o tipo de informação desejada",
            required=True,
            choices=[
                {"label": "U - Retorna a quantidade de colaboradores cadastrados.", "value": "U"},
                {"label": "D - Retorna a quantidade de digitais cadastradas.", "value": "D"},
                {"label": "TD - Retorna a quantidade total de digitais que o módulo suporta.", "value": "TD"},
                {"label": "R - Retorna a quantidade de registros na memória.", "value": "R"},
                {"label": "TP - Informa se o equipamento está bloqueado.", "value": "TP"},
                {"label": "MRPE - Informa se há erro ao comunicar com a MRP.", "value": "MRPE"},
                {"label": "SEMP - Indica se não há empregador cadastrado.", "value": "SEMP"},
                {"label": "PP - Informa se o sensor de pouco papel está ativado.", "value": "PP"},
                {"label": "SP - Informa se o equipamento está sem papel.", "value": "SP"},
                {"label": "QP - Quantidade de tickets que podem ser impressos / tamanho atual / tamanho total da bobina.", "value": "QP"},
                {"label": "PRN - Retorna a situação da impressora E (Não comunica) / F (Falta papel) / P (Papel enroscado) / O (OK)  / W (Pouco Papel)", "value": "PRN"},
            ]
        )
    ]
))

registrar_comando(CommandDefinition(
    code="RH",
    description="Receber Data/Hora: Obtém o relógio atual do equipamento.",
    template="01+{code}+00",
    params=[]
))

registrar_comando(CommandDefinition(
    code="EH",
    description="Enviar Data/Hora: Ajusta o relógio interno do equipamento.",
    template="01+{code}+00+{Data} {Hora}]00/00/00]00/00/00",
    params=[
        CommandParam(
            name="Data", 
            type=str, 
            default="", 
            required=True, 
            description="DD/MM/AA"
        ),
        CommandParam(
            name="Hora", 
            type=str, 
            default="", 
            required=True, 
            description="HH:MM:SS"
        )
    ]
))

registrar_comando(CommandDefinition(
    code="RC",
    description="Receber Configuração: Obtém configurações específicas do equipamento.",
    template="01+{code}+00+{Configuração}",
    params=[
        CommandParam(
            name="Configuração",
            type=str,
            description="Selecione as configurações desejadas",
            required=True,
            choices=[
                {"label": "LOGIN - Nome do usuário que dá acesso ao administrador no sistema", "value": "LOGIN"},
                {"label": "SENHA_MENU - Senha numérica que dá acesso ao administrador do sistema", "value": "SENHA_MENU"},
                {"label": "LEITOR_VER_DIG - Indica se os leitores de cartão devem ou não solicitar biometria do colaborador.", "value": "LEITOR_VER_DIG"},
                {"label": "TAM_BOB - Mostra o comprimento da bobina no equipamento", "value": "TAM_BOB"},
                {"label": "EVENTO_ON - Indica se o equipamento deve enviar eventos online", "value": "EVENTO_ON"},
                {"label": "EXP_NR_REP - Indica se deve salvar o arquivo de coleta com numero do rep na descrição", "value": "EXP_NR_REP"},
                {"label": "TECLADO_MANUT - Indica se teclado será desativado", "value": "TECLADO_MANUT"},
                {"label": "SENSOR_CORTE - Configuração do funcionamento do Sensor anti atolamento do papel", "value": "SENSOR_CORTE"},
                {"label": "FEW_PAPER - Configuração do sensor de pouco papel (sensor bobina)", "value": "FEW_PAPER"},
                {"label": "DIGITO_OCULTO - Ativa uma máscara quando da digitação da matricula", "value": "DIGITO_OCULTO"},
                {"label": "ACENTOS - Trata a impressão de acentos nos tickets", "value": "ACENTOS"},
                {"label": "MENSAGEM - Mostra uma mensagem no display do equipamento", "value": "MENSAGEM"},
                {"label": "NOBREAK - Habilita o monitoramento do nobreak do equipamento", "value": "NOBREAK"},
                {"label": "GMT - Fuso horário no qual o equipamento está localizado", "value": "GMT"},
                {"label": "BEEP_TECLADO - Configura o som do teclado do equipamento", "value": "BEEP_TECLADO"},
                {"label": "NR_REP - Número do REP", "value": "NR_REP"},
                {"label": "LEITOR_CARTAO - Tipo do leitor de cartão", "value": "LEITOR_CARTAO"},
                {"label": "LEITOR_BIOMETRIA - Tipo do leitor de biometria", "value": "LEITOR_BIOMETRIA"},
                {"label": "MODELO - Retorna o modelo configurado no equipamento", "value": "MODELO"},
                {"label": "ID_SOFTWARE - Retorna o identificador do software", "value": "ID_SOFTWARE"},
                {"label": "CHAVE_PUBLICA - Retorna a chave pública", "value": "CHAVE_PUBLICA"},
                {"label": "VERSAO_PRODUTO - Retorna a versão do firmware do equipamento", "value": "VERSAO_PRODUTO"},
                {"label": "VERSAO_MEM - Retorna a versão do firmware da MRP", "value": "VERSAO_MEM"},
                {"label": "VERSAO_PROTOCOLO - Retorna a versão do protocolo do equipamento", "value": "VERSAO_PROTOCOLO"},
                {"label": "MODO_CADASTRO - Configura o modo de cadastro do equipamento", "value": "MODO_CADASTRO"},
                {"label": "COR_SENSOR - Configura a cor do sensor de biometria do equipamento", "value": "COR_SENSOR"},
                {"label": "BIO_PREVIEW - Mostra ou não a amostra de captura do equipamento facial", "value": "BIO_PREVIEW"},
                {"label": "TEMPLATE - Retorna tipo de template da biometria", "value": "TEMPLATE"},
                {"label": "ACORDO_SIND - Número do contrato do acordo sindical composto de 17 números", "value": "ACORDO_SIND"},
                {"label": "TEMPO_LIB - Tempo de liberação do catraca ou porta configurado no equipamento", "value": "TEMPO_LIB"},
                {"label": "IP - IP do equipamento.", "value": "IP"},
                {"label": "MASC_SUBREDE - Máscara de subrede.", "value": "MASC_SUBREDE"},
                {"label": "DNS - DNS.", "value": "DNS"},
                {"label": "GATEWAY - Gateway.", "value": "GATEWAY"},
                {"label": "MAC - MAC do equipamento.", "value": "MAC"},
                {"label": "PORTA_TCP - Porta de comunicação Tcp/IP.", "value": "PORTA_TCP"},
                {"label": "VEL_SERIAL - Velocidade de comunicação Serial.", "value": "VEL_SERIAL"},
                {"label": "TIPO_COM - Tipo de comunicação.", "value": "TIPO_COM"},
                {"label": "CON_SEGURA - Indica se o REP deverá utilizar comunicação segura.", "value": "CON_SEGURA"},
                {"label": "IP_CON_SEGURA - IP que será utilizado na comunicação segura.", "value": "IP_CON_SEGURA"},
                {"label": "DHCP - Indica se equipamento deve ou não utilizar recurso de DHCP.", "value": "DHCP"},
                {"label": "MODE - Modo de conexão da comunicação TcpIP (cliente ou servidor).", "value": "MODE"},
                {"label": "RECONEXAO_IMEDIATA - Configuração do modo de reconexão com servidor client.", "value": "RECONEXAO_IMEDIATA"},
                {"label": "IP_SERVER - IP em que o equipamento irá conectar quando estiver no modo cliente.", "value": "IP_SERVER"},
                {"label": "SERVER_PORT - Porta em que o equipamento irá conectar quando estiver no modo cliente.", "value": "SERVER_PORT"},
                {"label": "HOSTNAME - Nome de rede que o equipamento assume.", "value": "HOSTNAME"},
                {"label": "NTP - Ativa a sincronização de horário com a internet.", "value": "NTP"},
                {"label": "NTP_SERVER - IP do servidor de consulta de horário.", "value": "NTP_SERVER"},
                {"label": "NTP_TIMEOUT - Tolerância entre consultas.", "value": "NTP_TIMEOUT"},
                {"label": "IP_W - IP do equipamento.", "value": "IP_W"},
                {"label": "MASC_SUBREDE_W - Máscara de subrede.", "value": "MASC_SUBREDE_W"},
                {"label": "DNS_W - DNS.", "value": "DNS_W"},
                {"label": "GATEWAY_W - Gateway.", "value": "GATEWAY_W"},
                {"label": "MAC_W - MAC do equipamento.", "value": "MAC_W"},
                {"label": "PORTA_TCP_W - Porta de comunicação Tcp/IP.", "value": "PORTA_TCP_W"},
                {"label": "CON_SEGURA_W - Indica se o REP deverá utilizar comunicação segura.", "value": "CON_SEGURA_W"},
                {"label": "IP_CON_SEGURA_W - IP que será utilizado na comunicação segura.", "value": "IP_CON_SEGURA_W"},
                {"label": "DHCP_W - Indica se equipamento deve ou não utilizar recurso de DHCP.", "value": "DHCP_W"},
                {"label": "MODE_W - Modo de conexão da comunicação TcpIP (cliente ou servidor).", "value": "MODE_W"},
                {"label": "RECONEXAO_IMEDIATA_W - Configuração do modo de reconexão com servidor client.", "value": "RECONEXAO_IMEDIATA_W"},
                {"label": "IP_SERVER_W - IP em que o equipamento irá conectar quando estiver no modo cliente.", "value": "IP_SERVER_W"},
                {"label": "SERVER_PORT_W - Porta em que o equipamento irá conectar quando estiver no modo cliente.", "value": "SERVER_PORT_W"},
                {"label": "USAR_DNS_W - Sinaliza se a conexão com o servidor deve ser via IP ou via nome.", "value": "USAR_DNS_W"},
                {"label": "ADDR_SERVER_W - Nome do servidor a conectar.", "value": "ADDR_SERVER_W"},
                {"label": "NET_NAME - SSID WiFi Principal (32 caracteres)", "value": "NET_NAME"},
                {"label": "NET_PWD - Senha WiFi Principal (32 caracteres)", "value": "NET_PWD"},
                {"label": "NET_NAME_02 - Nome da rede do access point secundário.", "value": "NET_NAME_02"},
                {"label": "NET_PWD_02 - Senha da rede do access point secundário.", "value": "NET_PWD_02"},
            ]
        )
    ]
))

registrar_comando(CommandDefinition(
    code="EC",
    description="Enviar Configuração: Ajusta configurações específicas do equipamento.",
    template="01+{code}+00+{Configuração}[{Valor}",
    params=[
        CommandParam(
            name="Configuração",
            type=str,
            description="Selecione a configuração a ser alterada",
            required=True,
            choices=[
                {"label": "LOGIN - Nome do usuário - Max. 16 caracteres (Apenas ADM)", "value": "LOGIN"},
                {"label": "SENHA_MENU - Senha numérica - 6 dígitos (Apenas ADM)", "value": "SENHA_MENU"},
                {"label": "LEITOR_VER_DIG - Solicitar biometria: H (Habilitado) / D (Desabilitado)", "value": "LEITOR_VER_DIG"},
                {"label": "TAM_BOB - Comprimento da bobina (0 ~ 400)", "value": "TAM_BOB"},
                {"label": "EVENTO_ON - Enviar eventos online: H (Habilitado) / D (Desabilitado)", "value": "EVENTO_ON"},
                {"label": "EXP_NR_REP - REP na descrição da coleta: H (Habilitado) / D (Desabilitado)", "value": "EXP_NR_REP"},
                {"label": "TECLADO_MANUT - Desativar teclado: H (Habilitado) / D (Desabilitado)", "value": "TECLADO_MANUT"},
                {"label": "SENSOR_CORTE - Sensor anti atolamento: H (Habilitado) / D (Desabilitado)", "value": "SENSOR_CORTE"},
                {"label": "FEW_PAPER - Sensor pouco papel: H (Habilitado) / D (Desabilitado)", "value": "FEW_PAPER"},
                {"label": "DIGITO_OCULTO - Máscara matrícula: H (Habilitado) / D (Desabilitado)", "value": "DIGITO_OCULTO"},
                {"label": "ACENTOS - Impressão de acentos: H (Habilitado) / D (Desabilitado)", "value": "ACENTOS"},
                {"label": "MENSAGEM - Mensagem no display (20 caracteres)", "value": "MENSAGEM"},
                {"label": "NOBREAK - Monitoramento nobreak: H (Habilitado) / D (Desabilitado)", "value": "NOBREAK"},
                {"label": "GMT - Fuso horário (-2 a -5)", "value": "GMT"},
                {"label": "BEEP_TECLADO - Som teclado: H (Habilitado) / D (Desabilitado)", "value": "BEEP_TECLADO"},
                {"label": "MODO_CADASTRO[P] - P (Padrão) / D (Dinâmico)", "value": "MODO_CADASTRO"},
                {"label": "COR_SENSOR[G] - G (Green) / R (Red) / B (Blue)", "value": "COR_SENSOR"},
                {"label": "BIO_PREVIEW - Preview facial: H (Habilitado) / D (Desabilitado)", "value": "BIO_PREVIEW"},
                {"label": "TEMPLATE[P] - P (Padrão) / I (ISO) / A (ANSI)", "value": "TEMPLATE"},
                {"label": "ACORDO_SIND - Contrato (17 dígitos)", "value": "ACORDO_SIND"},
                {"label": "TEMPO_LIB - Tempo liberação (0 a 60)", "value": "TEMPO_LIB"},
                {"label": "IP - IP do equipamento", "value": "IP"},
                {"label": "MASC_SUBREDE - Máscara de subrede", "value": "MASC_SUBREDE"},
                {"label": "DNS - DNS", "value": "DNS"},
                {"label": "GATEWAY - Gateway", "value": "GATEWAY"},
                {"label": "MAC - MAC do equipamento", "value": "MAC"},
                {"label": "PORTA_TCP - Porta (1000 ~ 65535)", "value": "PORTA_TCP"},
                {"label": "VEL_SERIAL - 9600 / 19200 / 57600 / 115200", "value": "VEL_SERIAL"},
                {"label": "TIPO_COM - S / T", "value": "TIPO_COM"},
                {"label": "CON_SEGURA - Comunicação segura: H (Habilitado) / D (Desabilitado)", "value": "CON_SEGURA"},
                {"label": "IP_CON_SEGURA - IP comunicação segura", "value": "IP_CON_SEGURA"},
                {"label": "DHCP - Usar DHCP", "value": "DHCP"},
                {"label": "MODE - Modo TCP: C (Cliente) / S (Servidor)", "value": "MODE"},
                {"label": "RECONEXAO_IMEDIATA - Reconexão imediata: H (Habilitado) / D (Desabilitado)", "value": "RECONEXAO_IMEDIATA"},
                {"label": "IP_SERVER - IP do servidor (modo cliente)", "value": "IP_SERVER"},
                {"label": "SERVER_PORT - Porta do servidor (modo cliente)", "value": "SERVER_PORT"},
                {"label": "HOSTNAME - Nome de rede (15 caracteres)", "value": "HOSTNAME"},
                {"label": "NTP - Sincronização NTP: H (Habilitado) / D (Desabilitado)", "value": "NTP"},
                {"label": "NTP_SERVER - IP servidor NTP", "value": "NTP_SERVER"},
                {"label": "NTP_TIMEOUT - Tolerância NTP (1 ~ 99)", "value": "NTP_TIMEOUT"},
                {"label": "IP_W - IP do equipamento (WiFi)", "value": "IP_W"},
                {"label": "MASC_SUBREDE_W - Máscara de subrede (WiFi)", "value": "MASC_SUBREDE_W"},
                {"label": "DNS_W - DNS (WiFi)", "value": "DNS_W"},
                {"label": "GATEWAY_W - Gateway (WiFi)", "value": "GATEWAY_W"},
                {"label": "MAC_W - MAC do equipamento (WiFi)", "value": "MAC_W"},
                {"label": "PORTA_TCP_W - Porta (WiFi)", "value": "PORTA_TCP_W"},
                {"label": "CON_SEGURA_W - Comunicação segura (WiFi): H / D", "value": "CON_SEGURA_W"},
                {"label": "IP_CON_SEGURA_W - IP comunicação segura (WiFi)", "value": "IP_CON_SEGURA_W"},
                {"label": "DHCP_W - DHCP (WiFi)", "value": "DHCP_W"},
                {"label": "MODE_W - Modo TCP (WiFi): C (Cliente) / S (Servidor)", "value": "MODE_W"},
                {"label": "RECONEXAO_IMEDIATA_W - Reconexão (WiFi): H / D", "value": "RECONEXAO_IMEDIATA_W"},
                {"label": "IP_SERVER_W - IP servidor (WiFi)", "value": "IP_SERVER_W"},
                {"label": "SERVER_PORT_W - Porta servidor (WiFi)", "value": "SERVER_PORT_W"},
                {"label": "USAR_DNS_W - Conexão via IP ou Nome (WiFi): H / D", "value": "USAR_DNS_W"},
                {"label": "ADDR_SERVER_W - Nome do servidor (WiFi) (127 caracteres)", "value": "ADDR_SERVER_W"},
                {"label": "NET_NAME - SSID WiFi Principal (32 caracteres)", "value": "NET_NAME"},
                {"label": "NET_PWD - Senha WiFi Principal (32 caracteres)", "value": "NET_PWD"},
                {"label": "NET_NAME_02 - SSID WiFi Secundário (32 caracteres)", "value": "NET_NAME_02"},
                {"label": "NET_PWD_02 - Senha WiFi Secundário (32 caracteres)", "value": "NET_PWD_02"},
            ]
        ),
        CommandParam(
            name="Valor",
            type=str,
            description="Valor a ser definido",
            required=False
        )
    ]
))

registrar_comando(CommandDefinition(
    code="EU",
    description="Enviar Colaborador: Cadastra um novo colaborador no equipamento.",
    template="01+{code}+00+1+I[{CPF}[{Nome}[{Bio}[{QMat}[{Matrícula}{Matrícula2}{Senha}",
    params=[
        CommandParam(
            name="CPF", 
            type=str, 
            default="", 
            required=True, 
            description="CPF"
            
        ),
        CommandParam(
            name="Nome", 
            type=str, 
            default="", 
            required=True, 
            description="Nome completo"

        ),
        CommandParam(
            name="Bio",
            type=str, 
            default="", 
            required=True, 
            description="Biometria",
            choices=[
                {"label": "0 - Não verificar biometria.", "value": "0"},
                {"label": "1 - Verificar biometria.", "value": "1"},
            ]
        ),
        CommandParam(
            name="QMat",
            type=str, 
            default="", 
            required=True, 
            description="Quantidade de matrículas",
            choices=[
                {"label": "1 - Uma matrícula ", "value": "1"},
                {"label": "2 - Duas matrículas", "value": "2"},
            ]
        ),
        CommandParam(
            name="Matrícula",
            type=str, 
            default="", 
            required=True, 
            description="Matrícula 1"
        ),
        CommandParam(
            name="Matrícula2", 
            type=str, 
            default="", 
            required=False, 
            description="Matrícula 2"
        ),
        CommandParam(
            name="Senha",
            type=str, 
            default="", 
            required=False, 
            description="Senha (Deve ter exatamente 6 dígitos se fornecida)"
        )   
    ]
))

registrar_comando(CommandDefinition(
    code="EU'",
    description="Excluir Colaborador: Remove um colaborador existente do equipamento.",
    template="01+EU+00+1+E[{CPF}",
    params=[
        CommandParam(
            name="CPF", 
            type=str, 
            default="", 
            required=True, 
            description="CPF"    
        ) 
    ]
))

registrar_comando(CommandDefinition(
    code="EE",
    description="Enviar Empregador: Cadastra o empregador no equipamento.",
    template="01+{code}+00+{Tipo}]{ID}]]{Nome}]{Local}",
    params=[
        CommandParam(
            name="ID",
            type=str,
            description="CNPJ (14 dígitos) ou CPF (11 dígitos)",
            required=True
        ),
        CommandParam(
            name="Nome",
            type=str,
            description="Razão Social do empregador",
            required=True
        ),
        CommandParam(
            name="Local",
            type=str,
            description="Local da empresa",
            required=True
        )
    ]
))

registrar_comando(CommandDefinition(
    code="RE",
    description="Receber Empregador: Obtém os dados do empregador cadastrado.",
    template="01+{code}+00",
    params=[]
))

registrar_comando(CommandDefinition(
    code="ES",
    description="Enviar Usuário do Sistema (Apenas ADM): Cadastra um usuário para acesso ao sistema/webserver.",
    template="01+{code}+00+1+I[{CPF}[{Login}[{Senha}[{Cartão}[111111",
    params=[
        CommandParam(
            name="CPF",
            type=str,
            description="CPF do usuário",
            required=True
        ),
        CommandParam(
            name="Login",
            type=str,
            description="Login do webserver",
            required=True
        ),
        CommandParam(
            name="Senha",
            type=str,
            description="Senha de 6 dígitos",
            required=True
        ),
        CommandParam(
            name="Cartão",
            type=str,
            description="Número do cartão para menu",
            required=False,
            default=""
        )
    ]
))

# Internal RR commands - not directly exposed in main dropdown
registrar_comando(CommandDefinition(
    code="RR_MEMORIA",
    description="Receber registros (Por Memória): Solicita registros a partir de um endereço.",
    template="01+RR+00+M]{QTD}]{Endereço}",
    params=[
        CommandParam(
            name="QTD",
            type=int,
            default=10,
            required=True,
            description="Quantidade de registros"
        ),
        CommandParam(
            name="Endereço",
            type=int,
            default=0,
            required=True,
            description="Endereço de memória inicial (apenas números)"
        )
    ]
))

registrar_comando(CommandDefinition(
    code="RR_NSR",
    description="Receber registros (Por NSR): Solicita registros a partir de um NSR.",
    template="01+RR+00+N]{QTD}]{NSR}",
    params=[
        CommandParam(
            name="QTD",
            type=int,
            default=10,
            required=True,
            description="Quantidade de registros"
        ),
        CommandParam(
            name="Endereço", # Note: should probably be NSR based on template, but keeping original param name for safety if used elsewhere
            type=int,
            default=1,
            required=True,
            description="NSR inicial (apenas números)"
        )
    ]
))
# Fix for RR_NSR param name consistency
COMMANDS_REGISTRY["RR_NSR"].params[1].name = "NSR"

registrar_comando(CommandDefinition(
    code="RR_DATA",
    description="Receber registros (Por Data): Solicita registros a partir de uma data/hora.",
    template="01+RR+00+D]{QTD}]{Data} {Hora}",
    params=[
        CommandParam(
            name="QTD",
            type=int,
            default=10,
            required=True,
            description="Quantidade de registros"
        ),
        CommandParam(
            name="Data",
            type=str,
            required=True,
            description="Data inicial (DD/MM/AAAA)"
        ),
        CommandParam(
            name="Hora",
            type=str,
            required=True,
            description="Hora inicial (HH:MM:SS)"
        )
    ]
))

# Internal RU commands - not directly exposed in main dropdown
registrar_comando(CommandDefinition(
    code="RU_QUANTIDADE",
    description="Receber Colaboradores (Por Quantidade): Solicita dados de colaboradores a partir de um índice.",
    template="01+RU+00+{Quantidade}]{Índice}",
    params=[
        CommandParam(
            name="Quantidade",
            type=int,
            default=10,
            required=True,
            description="Quantidade de colaboradores"
        ),
        CommandParam(
            name="Índice",
            type=int,
            default=0,
            required=True,
            description="Índice inicial (0 para o primeiro)"
        )
    ]
))

registrar_comando(CommandDefinition(
    code="RU_MATRICULA",
    description="Receber Colaboradores (Por Matrícula): Solicita dados de um colaborador pela matrícula.",
    template="01+RU+00+-1]{Matrícula}",
    params=[
        CommandParam(
            name="Matrícula",
            type=str,
            default="",
            required=True,
            description="Matrícula do colaborador"
        )
    ]
))

registrar_comando(CommandDefinition(
    code="RU_CPF",
    description="Receber Colaboradores (Por CPF): Solicita dados de um colaborador pelo CPF.",
    template="01+RU+00+-2]{CPF}",
    params=[
        CommandParam(
            name="CPF",
            type=str,
            default="",
            required=True,
            description="CPF do colaborador (apenas números)"
        )
    ]
))

# Comando RU consolidado para a interface
registrar_comando(CommandDefinition(
    code="RU",
    description="Receber Colaboradores: Selecione o tipo de filtro (Por Quantidade, Matrícula ou CPF).",
    template="01+RU+00",  # O template real será substituído no main.py
    params=[
        CommandParam(
            name="Tipo",
            type=str,
            description="Tipo de filtro para receber colaboradores",
            required=True,
            choices=[
                {"label": "Por Quantidade", "value": "RU_QUANTIDADE"},
                {"label": "Por Matrícula", "value": "RU_MATRICULA"},
                {"label": "Por CPF", "value": "RU_CPF"},
            ]
        )
    ]
))

# Comando RR consolidado para a interface
registrar_comando(CommandDefinition(
    code="RR",
    description="Receber Registros: Selecione o tipo de filtro (Memória, NSR ou Data).",
    template="01+RR+00", # O template real será substituído no main.py
    params=[
        CommandParam(
            name="Tipo",
            type=str,
            description="Tipo de filtro para receber registros",
            required=True,
            choices=[
                {"label": "Por Memória", "value": "RR_MEMORIA"},
                {"label": "Por NSR", "value": "RR_NSR"},
                {"label": "Por Data", "value": "RR_DATA"},
            ]
        )
    ]
))

# ========== Comandos ED (Enviar/Cadastrar/Deletar Biometria) ==========

registrar_comando(CommandDefinition(
    code="ED_CADASTRAR",
    description="Cadastrar Biometria: Registra a biometria de um colaborador.",
    template="01+ED+00+R]{Matricula}",
    params=[
        CommandParam(
            name="Matricula",
            type=str,
            description="Matrícula do colaborador",
            required=True
        )
    ]
))

registrar_comando(CommandDefinition(
    code="ED_DELETAR",
    description="Deletar Biometria: Remove a biometria de um colaborador.",
    template="01+ED+00+E]{Matricula}",
    params=[
        CommandParam(
            name="Matricula",
            type=str,
            description="Matrícula do colaborador",
            required=True
        )
    ]
))

registrar_comando(CommandDefinition(
    code="ED_SUPREMA",
    description="Enviar Biometria (Suprema): Cadastra até 10 templates no módulo Suprema.",
    template="01+ED+00+D]{Matricula}}}3}}{TP_DATA}",
    params=[
        CommandParam(
            name="Matricula",
            type=str,
            description="Matrícula do colaborador",
            required=True
        ),
        CommandParam(
            name="TP_DATA",
            type=str,
            description="Templates (até 10)",
            required=True
        )
    ]
))

registrar_comando(CommandDefinition(
    code="ED_BIO_AZUL",
    description="Enviar Biometria (EVO Bio Azul): Cadastra template no módulo Bio Azul.",
    template="01+ED+00+T]{Matricula}}K}B}{Index}}00810",
    params=[
        CommandParam(
            name="Matricula",
            type=str,
            description="Matrícula do colaborador",
            required=True
        ),
        CommandParam(
            name="Index",
            type=str,
            description="Index da template",
            required=True
        )
    ]
))

registrar_comando(CommandDefinition(
    code="ED_FACE",
    description="Enviar Biometria (EVO Face): Cadastra template no módulo Facial.",
    template="01+ED+00+T]{Matricula}}R}B}{Index}}02048",
    params=[
        CommandParam(
            name="Matricula",
            type=str,
            description="Matrícula do colaborador",
            required=True
        ),
        CommandParam(
            name="Index",
            type=str,
            description="Index da template",
            required=True
        )
    ]
))

registrar_comando(CommandDefinition(
    code="ED_FACE_CORP",
    description="Enviar Biometria (Face Corp): Cadastra template no módulo Face Corp.",
    template="01+ED+00+T]{Matricula}}X}B}{Index}}01072",
    params=[
        CommandParam(
            name="Matricula",
            type=str,
            description="Matrícula do colaborador",
            required=True
        ),
        CommandParam(
            name="Index",
            type=str,
            description="Index da template",
            required=True
        )
    ]
))

# Comando ED consolidado para a interface
registrar_comando(CommandDefinition(
    code="ED",
    description="Enviar/Cadastrar/Deletar Biometria: Selecione a operação desejada.",
    template="01+ED+00", # O template real será substituído no main.py
    params=[
        CommandParam(
            name="Operação",
            type=str,
            description="Tipo de operação",
            required=True,
            choices=[
                {"label": "Cadastrar Biometria", "value": "ED_CADASTRAR"},
                {"label": "Deletar Biometria", "value": "ED_DELETAR"},
                {"label": "Enviar - Módulo Suprema (Placeholder apenas. Só Base64 da para copiar e colar)", "value": "ED_SUPREMA"},
                {"label": "Enviar - EVO Bio Azul", "value": "ED_BIO_AZUL"},
                {"label": "Enviar - EVO Face", "value": "ED_FACE"},
                {"label": "Enviar - Face Corp", "value": "ED_FACE_CORP"},
            ]
        )
    ]
))

registrar_comando(CommandDefinition(
    code="RD",
    description="Receber Biometria: Solicita lista, quantidade ou templates biométricos.",
    template="01+RD+00",
    params=[
        CommandParam(
            name="Operação",
            type=str,
            choices=[
                {"label": "Solicitar Lista", "value": "RD_LISTA"},
                {"label": "Solicitar Quantidade", "value": "RD_QTD"},
                {"label": "Receber Template", "value": "RD_TEMPLATE"},
            ]
        )
    ]
))

# Sub-comandos RD
registrar_comando(CommandDefinition(
    code="RD_LISTA",
    description="Solicitar Lista de Biometrias",
    template="01+RD+00+L]{Quantidade}}{Indice}",
    params=[
        CommandParam(name="Quantidade", type=int, default=10, description="Quantidade de registros"),
        CommandParam(name="Indice", type=int, default=0, description="Índice inicial")
    ]
))

registrar_comando(CommandDefinition(
    code="RD_QTD",
    description="Solicitar Quantidade de Biometrias (Suprema/EVO)",
    template="01+RD+00+Q]{Matricula}",
    params=[
        CommandParam(name="Matricula", type=str, required=True, description="Matrícula do colaborador")
    ]
))

registrar_comando(CommandDefinition(
    code="RD_TEMPLATE",
    description="Receber Template Biométrico",
    template="01+RD+00+D]{Matricula}",
    params=[
        CommandParam(name="Matricula", type=str, required=True, description="Matrícula do colaborador"),
        CommandParam(name="Index", type=int, default=0, description="Index da template (Digital 0~9, Facial 0~7)")
    ]
))
