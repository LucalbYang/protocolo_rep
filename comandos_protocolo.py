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
            
            safe_kwargs[param.name] = str(val)

        try:
            # Constrói a string injetando o código e os parâmetros dinâmicos
            return self.template.format(code=self.code, **safe_kwargs)
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
    code="RH",
    description="Relógio de Hardware: Leitura ou ajuste de data e hora do equipamento.",
    template="01+{code}+00+{data_hora}",
    params=[
        CommandParam(
            name="data_hora", 
            type=str, 
            default="", 
            required=False, 
            description="Ex: 07/04/2026 09:00:00 (Deixe vazio apenas para ler)"
        )
    ]
))

# registrar_comando(CommandDefinition(
#     code="RC",
#     description="Receber Configurações: Obtém os parâmetros operacionais atuais do REP.",
#     template="01+{code}+00",
#     params=[] # Comando simples sem parâmetros adicionais
# ))

# registrar_comando(CommandDefinition(
#     code="EU",
#     description="Enviar Usuário: Cadastra ou atualiza as credenciais de um funcionário no REP.",
#     template="01+{code}+00+{pis}+{nome}+{senha}",
#     params=[
#         CommandParam(name="pis", type=str, required=True, description="PIS (11 dígitos, sem pontuação)"),
#         CommandParam(name="nome", type=str, required=True, description="Nome do funcionário"),
#         CommandParam(name="senha", type=str, required=False, default="", description="Senha numérica (opicional)")
#     ]
# ))