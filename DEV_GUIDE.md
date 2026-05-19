# Guia de Arquitetura - REPLink Protocolo EVO

Este documento serve como um mapa técnico para desenvolvedores se situarem na estrutura modular do projeto. O código foi separado para garantir que a lógica de interface (UI), comunicação (Rede/Protocolo) e segurança (Criptografia) não fiquem entrelaçadas.

---

## 📂 Estrutura de Arquivos

### 1. `main.py`
**Papel:** Ponto de entrada e Orquestrador da Interface.
*   **O que faz:** Inicializa a `QApplication`, gerencia o `QStackedWidget` (abas F1 a F5) e conecta os sinais dos botões aos Workers de rede.
*   **Principais Classes:**
    *   `EvoRepAuthApp`: Classe principal que mantém o estado de cada aba (`tab_data`).
*   **Principais Métodos:**
    *   `_setup_ui()`: Constrói a estrutura visual.
    *   `on_connect_clicked()`: Dispara a conexão usando os Workers.
    *   `on_send_command_clicked()`: Constrói as strings de comando baseadas nos inputs e envia ao equipamento.
    *   `handle_afd_flow()`: Gerencia a máquina de estados complexa para extração de AFD.

### 2. `comandos.py` (ou `comandos_protocolo.py`)
**Papel:** Catálogo de Comandos.
*   **O que faz:** Define a estrutura de dados de cada comando aceito pelo protocolo EVO.
*   **Principais Classes:**
    *   `CommandDefinition`: Define o template da string (ex: `01+{code}+00+{Valor}`) e como validar seus parâmetros.
    *   `CommandParam`: Define tipo, escolhas (choices) e obrigatoriedade de cada campo.
*   **Onde mexer:** Adicione novos comandos no final deste arquivo usando `registrar_comando`.

### 3. `workers.py`
**Papel:** Processamento em Background (Multi-threading).
*   **O que faz:** Contém todas as tarefas que "travariam" a interface se rodassem na thread principal (sockets, loops de espera).
*   **Principais Classes:**
    *   `NetworkWorker`: Realiza o handshake RSA/AES inicial (Modo Servidor).
    *   `ClientNetworkWorker`: Escuta conexões do REP (Modo Cliente).
    *   `CommandWorker`: Envia um comando criptografado e finaliza.
    *   `ListenerWorker`: Fica em loop escutando respostas do socket e emitindo sinais para a UI.

### 4. `evo_protocol.py`
**Papel:** Baixo nível do Protocolo.
*   **O que faz:** Lida com os bytes puros da comunicação (STX, Tamanho, Payload, Checksum, ETX).
*   **Principais Métodos:**
    *   `pack(payload)`: Transforma string/bytes em um pacote válido com checksum.
    *   `unpack(packet)`: Valida checksum e extrai o payload.
    *   `receive_full(sock)`: Garante a leitura completa de um pacote do buffer do socket.

### 5. `evo_crypto.py`
**Papel:** Segurança e Criptografia.
*   **O que faz:** Isola a complexidade das bibliotecas `pycryptodome` ou `cryptography`.
*   **Principais Métodos:**
    *   `encrypt_aes` / `decrypt_aes`: Criptografia de comandos e respostas.
    *   `encrypt_credentials_with_rsa`: Usado apenas no handshake inicial.
    *   `extract_rsa_key_from_payload`: Converte a resposta `RA` do REP em chaves utilizáveis.

### 6. `widgets.py`
**Papel:** Componentes Reutilizáveis de UI.
*   **O que faz:** Define widgets customizados que dão a "cara" do app.
*   **Principais Classes:**
    *   `HeaderBar`: A barra superior com abas e toggle de tema.
    *   `NoScrollComboBox`: ComboBox que não muda o valor sem querer ao usar o scroll.
    *   `NotificationCard`: Os avisos flutuantes no canto da tela.

### 7. `macro.py`
**Papel:** Automação de Testes.
*   **O que faz:** Lida com a janela de Macro e a lógica de envio em lote de colaboradores.
*   **Principais Métodos:**
    *   `on_bulk_clicked()`: Envia múltiplos comandos `EU` em um único pacote.
    *   `on_delete_rep_clicked()`: Inicia o processo de ler a lista de CPFs (`RU`) e depois deletar um por um.

### 8. `utils.py`
**Papel:** Ferramentas Diversas.
*   **Métodos:** `get_local_ip()`, `generate_cpf()`, `resource_path()`.

### 9. `ui_styles.py` e `constants.py`
**Papel:** Estética e Configuração Fixa.
*   `build_qss()`: O CSS do aplicativo (Dark/Light mode).
*   `APP_VERSION` e `EC_VAL_CHOICES`: Constantes globais.

---

## 💡 Dicas para o Dev

1.  **Fluxo de Resposta:** Quando o REP responde, o dado passa por:
    `ListenerWorker` (Thread) -> `EvoRepProtocol.unpack` -> `EvoRepCrypto.decrypt_aes` -> SINAL `received_signal` -> `main.py` (`append_received`).
2.  **Adicionar novo campo na UI:** Se for um parâmetro de comando, altere apenas o `comandos.py`. Se for um campo fixo de configuração, altere o `_create_rep_tab` no `main.py`.
3.  **Logs:** Use sempre `self.append_log()` dentro do `main.py` ou emita um sinal para ele a partir de um Worker para ver o que está acontecendo na aba de Logs (F7).
