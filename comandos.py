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
                # Se o valor contém ']', dividimos e validamos cada parte individualmente
                if ']' in str(val):
                    parts = str(val).split(']')
                    for part in parts:
                        if part not in valid_values:
                            raise ValueError(f"O valor '{part}' dentro da combinação não é válido para o parâmetro '{param.name}'.")
                elif val not in valid_values:
                    # Tenta encontrar o valor pelo label caso o usuário tenha passado o texto do combo
                    val_by_label = next((c['value'] for c in param.choices if c['label'] == val), None)
                    if val_by_label:
                        val = val_by_label
                    else:
                        raise ValueError(f"Valor '{val}' inválido para o parâmetro '{param.name}'.")

            safe_kwargs[param.name] = str(val)

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
                {"label": "U - Retorna a quantidade de usuários cadastrados.", "value": "U"},
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
                {"label": "LEITOR_VER_DIG - Indica se os leitores de cartão devem ou não solicitar biometria do usuário.", "value": "LEITOR_VER_DIG"},
                {"label": "TAM_BOB - Mostra o comprimento da bobina no equipamento", "value": "TAM_BOB"},
                {"label": "EVENTO_ON - Indica se o equipamento deve enviar eventos online", "value": "EVENTO_ON"},
                {"label": "EXP_NR_REP - Indica se deve salvar o arquivo de coleta com numero do rep na descrição", "value": "EXP_NR_REP"},
                {"label": "TECLADO_MANUT - Indica se teclado será desativado", "value": "TECLADO_MANUT"},
                {"label": "SENSOR_CORTE - Configuração do funcionamento do Sensor anti atolamento do papel", "value": "SENSOR_CORTE"},
                {"label": "FEW_PAPER - Configuração do sensor de pouco papel (sensor bobina)", "value": "FEW_PAPER"},
                {"label": "DIGITO_OCULTO - Ativa uma máscara quando da digitação da matricula", "value": "DIGITO_OCULTO"},
                {"label": "ACENTOS - Trata a impressão de acentos nos tickets", "value": "ACENTOS"},
            ]
        )
    ]
))

registrar_comando(CommandDefinition(
    code="EU",
    description="Enviar Usuário: Cadastra um novo usuário no equipamento.",
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
    description="Excluir Usuário: Remove um usuário existente do equipamento.",
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