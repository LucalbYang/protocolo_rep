# REPLink — Protocolo EVO REP-A/C

REPLink é uma aplicação desktop desenvolvida em Python para a comunicação e gerenciamento de equipamentos de registro de ponto (REP) compatíveis com o protocolo EVO REP-A/C.

## Funcionalidades

- Handshake Seguro: Implementação de troca de chaves RSA e criptografia AES (modo CBC) para o estabelecimento de sessões seguras.
- Interface Versátil: Interface gráfica desenvolvida em PyQt6 com suporte a temas claro e escuro.
- Catálogo de Comandos: Suporte integrado para as principais operações do protocolo, incluindo:
  - Consulta de status e contadores (RQ).
  - Sincronização de data e hora (EH/RH).
  - Gerenciamento de dados do empregador (EE/RE).
  - Administração de colaboradores (EU).
  - Gerenciamento e transferência de templates biométricos (ED/RD).
- Modos de Conexão:
  - Servidor: Conexão direta ao endereço IP do equipamento.
  - Cliente: Atuação como servidor de escuta para conexões iniciadas pelo equipamento.
  - F3: Procedimentos de desbloqueio de equipamentos.
- Ferramentas de Automação: Macros para geração e exclusão em massa de registros para fins de homologação e carga de dados.
- Monitoramento de Tráfego: Registro detalhado das comunicações enviadas e recebidas em formato de texto e hexadecimal.

## Pré-requisitos

O sistema requer Python 3.10 ou superior. As bibliotecas fundamentais são:

- PyQt6: Framework para a interface gráfica.
- PyCryptodome: Processamento de algoritmos criptográficos (RSA e AES).

## Instalação

1. Obtenha o código fonte do projeto:
   git clone https://github.com/usuario/protocolo-rep.git
   cd protocolo-rep

2. Instale as dependências necessárias:
   pip install PyQt6 pycryptodome

## Instruções de Uso

Para iniciar a aplicação, execute o script principal:

python main.py

Orientações de operação:
- Configuração de Rede: Defina o endereço IP e a porta de comunicação. Escolha o modo de conexão adequado à topologia da rede (Servidor ou Cliente).
- Execução de Comandos: Utilize o menu de seleção para carregar um comando. Os campos de parâmetros serão gerados dinamicamente conforme a especificação do protocolo.
- Interação Direta: O modo manual permite o envio de sequências de caracteres customizadas para testes específicos.
- Customização Visual: O botão de alternância de tema no cabeçalho permite ajustar a visualização conforme a preferência do operador.

## Licença

Este software é distribuído sob a licença MIT.

Desenvolvido por Lucas C Albuquerque.
