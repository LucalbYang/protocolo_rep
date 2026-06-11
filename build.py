import os
import subprocess
import sys

def build():
    # Nome do arquivo principal
    main_file = "main.py"
    # Nome do ícone/logo
    logo_file = "logo.png"
    # Nome do executável final
    app_name = "REPLink"

    if not os.path.exists(main_file):
        print(f"Erro: {main_file} não encontrado.")
        return

    if not os.path.exists(logo_file):
        print(f"Aviso: {logo_file} não encontrado. O executável será criado sem ícone personalizado.")
        icon_param = []
        data_param = []
    else:
        # --add-data "origem;destino" (no Windows o separador é ;)
        icon_param = ["--icon", logo_file]
        data_param = ["--add-data", f"{logo_file};."]

    # Adiciona a logo-evo se existir
    if os.path.exists("logo-evo.png"):
        data_param.extend(["--add-data", "logo-evo.png;."])

    # Comando do PyInstaller
    command = [
        "pyinstaller",
        "--noconfirm",
        "--onefile",
        "--windowed",
        "--name", app_name,
    ] + icon_param + data_param + [main_file]

    print(f"Iniciando build do {app_name}...")
    print(f"Comando: {' '.join(command)}")

    try:
        subprocess.check_call(command)
        print("\nBuild concluído com sucesso!")
        print(f"O executável pode ser encontrado na pasta 'dist'.")
    except subprocess.CalledProcessError as e:
        print(f"\nErro durante o build: {e}")
    except FileNotFoundError:
        print("\nErro: PyInstaller não encontrado. Instale-o com 'pip install pyinstaller'.")

if __name__ == "__main__":
    build()
