# REPLink — Protocolo EVO REP-A/C

REPLink é uma aplicação desktop desenvolvida em Python para a comunicação e gerenciamento de equipamentos de registro de ponto (REP) compatíveis com o protocolo EVO REP-A/C.

## Funcionalidades

- **Handshake Seguro:** Implementação de troca de chaves RSA e criptografia AES (modo CBC) para o estabelecimento de sessões seguras.
- **Autenticação de Operador:** Suporte nativo à autenticação (Comando 009) durante a conexão nas abas de Servidor e Cliente.
- **Interface Versátil:** Interface gráfica desenvolvida em PyQt6 com suporte a temas claro e escuro e navegação estruturada (Abas F1, F2, F3, F5, F7).
- **Catálogo de Comandos Organizado:** Suporte integrado para as principais operações do protocolo com categorização avançada:
  - Consulta de status e contadores (RQ).
  - Sincronização de data e hora (EH/RH).
  - Gerenciamento de dados do empregador (EE/RE).
  - Administração de colaboradores (EU).
  - Gerenciamento e transferência de templates biométricos (ED/RD).
  - Configurações do Equipamento (EC) e Consulta de Configurações (RC).
- **Modos de Conexão e Abas Especializadas:**
  - **F1 (Servidor):** Conexão direta ao endereço IP do equipamento.
  - **F2 (Cliente):** Atuação como servidor de escuta para conexões iniciadas pelo equipamento.
  - **F3 (Desbloqueio):** Procedimentos de desbloqueio de equipamentos com ciclos de reconexão automática e tolerância a falhas.
  - **F5 (Testes):** Rotinas automatizadas de envio de comandos e extração completa de **AFD** (Arquivo Fonte de Dados) com geração de cabeçalhos (sem travar a interface principal).
  - **F7 (Logs):** Monitoramento de Tráfego detalhado (texto e hexadecimal).
- **Ferramentas de Automação (Macro):** Funcionalidades de geração, exclusão em massa de registros e carga rápida de dados para testes em ambas conexões (Servidor/Cliente).

## Pré-requisitos

O sistema requer Python 3.10 ou superior. As bibliotecas fundamentais são:

- `PyQt6`: Framework para a interface gráfica.
- `pycryptodome`: Processamento de algoritmos criptográficos (RSA e AES).

## Instalação

Instale as dependências necessárias:
```bash
pip install PyQt6 pycryptodome
```

## Instruções de Uso

Para iniciar a aplicação, execute o script principal:
```bash
python main.py
```

**Orientações de operação:**
- **Configuração de Rede:** Defina o endereço IP e a porta de comunicação. Escolha o modo de conexão adequado à topologia da rede (Servidor ou Cliente).
- **Execução de Comandos:** Utilize o menu de seleção para carregar um comando. Os campos de parâmetros serão gerados dinamicamente conforme a especificação do protocolo.
- **Interação Direta:** O modo manual permite o envio de sequências de caracteres customizadas para testes específicos.
- **Customização Visual:** O botão de alternância de tema no cabeçalho permite ajustar a visualização conforme a preferência do operador.

## Guia de Desenvolvimento

Para mais informações sobre a arquitetura do projeto e como contribuir com o código, consulte o arquivo **[DEV_GUIDE.md](./DEV_GUIDE.md)**, que detalha a estrutura de arquivos e o funcionamento dos módulos.

---
Desenvolvido por Lucas C Albuquerque.
