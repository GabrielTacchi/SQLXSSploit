import time
import os
import sqli
import xss
import re
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import NoAlertPresentException, UnexpectedAlertPresentException
from selenium.webdriver.common.by import By
from webdriver_manager.chrome import ChromeDriverManager
from urllib.parse import urlparse

# Configuração do WebDriver com algumas opções para executar o navegador em modo headless e ignorar certos erros
chrome_options = Options()
chrome_options.add_argument("--headless=old")
chrome_options.add_argument("--disable-gpu")
chrome_options.add_argument("--no-sandbox")
chrome_options.add_argument("--disable-dev-shm-usage")
chrome_options.add_argument("--ignore-certificate-errors")
chrome_options.add_argument('--log-level=3')

# Inicializa o WebDriver com as opções configuradas
driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=chrome_options)

# Função que lida com alertas em páginas web
def trata_alerts(url):

    driver.get(url)
    try:
        alert = driver.switch_to.alert
        alert_text = alert.text
        alert.dismiss()
        if "XSS encontrado" in alert_text:
            print(f"[*]Identificado um Alert com texto: {alert_text}, é possível que esteja com XSS Stored\n"
                  f"[*]Não será possível prosseguir com a função.")

            return True
        return False

    except NoAlertPresentException:
        return False
# Função que manipula cookies na página
def get_cookies(url):
    try:
        # Deleta qualquer cookie que possa existir previamente no site e possa vir a atrapalhar.
        driver.delete_all_cookies()

        # Acessa o site para inicializar o WebDriver
        driver.get(url)
        url_base = urlparse(url).netloc

        cookies_armazenados = {}

        if os.path.exists(f'{url_base}.txt'):
            with open(f'{url_base}.txt', 'r') as cookies_file:
                lines = cookies_file.readlines()

                # Carrega cookies do arquivo em um dicionário
                for line in lines:
                    partes = line.split("    ")
                    nome = partes[0].replace("nome: ", "").strip()
                    valor = partes[1].replace("valor: ", "").strip()
                    cookies_armazenados[nome] = valor

            if cookies_armazenados:
                print(f"[*]Cookies encontrados para {url_base}:\n")
                for nome, valor in cookies_armazenados.items():
                    print(f"nome: {nome}    valor: {valor}")

                while True:
                    usar_cookies_salvos = input(f"[!]Deseja utilizá-los? (Y/N): ").upper()

                    if usar_cookies_salvos == "Y":
                        for nome_cookie_armazenado, valor_cookie_armazenado in cookies_armazenados.items():
                            driver.add_cookie({'name': nome_cookie_armazenado, 'value': valor_cookie_armazenado})
                        break

                    elif usar_cookies_salvos == "N":
                        excluir_cookies = input("[!]Deseja excluí-los? (Y/N): ").upper()
                        if excluir_cookies == "Y":
                            os.remove(f'{url_base}.txt')
                        break
                    else:
                        print("[*]Opção inválida")

        while True:
            # Pergunta ao usuário se deseja adicionar ou editar cookies
            add_cookies = input("[!]Adicionar ou editar cookies? (A/E/N): ").upper()

            if add_cookies == "A":
                with open(f'{url_base}.txt', 'w') as cookies_file:
                    while True:
                        nome = input("[!]Cookie nome: ")
                        valor = input("[!]Cookie valor: ")
                        driver.add_cookie({'name': nome, 'value': valor})
                        cookies_file.write(f"nome: {nome}    valor: {valor}\n")

                        more_cookies = input("[!]Adicionar mais cookies? (Y/N): ").upper()

                        if more_cookies == "N":
                            break
                        elif more_cookies != "Y":
                            print("[*]Opção inválida.")

            elif add_cookies == "E":
                with open(f'{url_base}.txt', 'w') as cookies_file:
                    while True:
                        # Exibe cookies existentes e pede ao usuário para selecionar um para editar
                        print("[*]Cookies atuais:")
                        for i, (nome, valor) in enumerate(cookies_armazenados.items(), start=1):
                            print(f"{i}. nome: {nome}    valor: {valor}")

                        edit_index = int(input("[!]Digite o número do cookie a ser editado (ou 0 para cancelar): "))

                        if edit_index == 0:
                            break

                        if 1 <= edit_index <= len(cookies_armazenados):
                            nome_existente = list(cookies_armazenados.keys())[edit_index - 1]
                            novo_nome = input(
                                f"[!]Novo nome para o cookie (deixe em branco para manter '{nome_existente}'): ")
                            novo_valor = input(
                                f"[!]Novo valor para o cookie (deixe em branco para manter '{cookies_armazenados[nome_existente]}'): ")

                            if novo_nome:
                                nome_existente = novo_nome
                            if novo_valor:
                                cookies_armazenados[nome_existente] = novo_valor

                            # Regrava todos os cookies no arquivo
                            for nome, valor in cookies_armazenados.items():
                                cookies_file.write(f"nome: {nome}    valor: {valor}\n")

                            print(f"[!]Cookie '{nome_existente}' atualizado.")

                            for nome_cookie_armazenado, valor_cookie_armazenado in cookies_armazenados.items():
                                driver.add_cookie({'name': nome_cookie_armazenado, 'value': valor_cookie_armazenado})
                        else:
                            print("[*]Opção inválida.")

            elif add_cookies != "N":
                print("[*]Opção inválida")

            else:
                break

        # Acessa o site para aplicar cookies modificados
        driver.get(url)

    except UnexpectedAlertPresentException:
        if trata_alerts(url):
            return
        else:
            pass

    except Exception as e:
        print(f"[X]Falha ao se conectar em {url}: {e}")

# Função que pega todas URLs
def catch_urls(url):
    try:
        driver.get(url)
        alert = driver.switch_to.alert
        alert_text = alert.text
        alert.dismiss()
        if "XSS encontrado" in alert_text:
            print(f"[*]Identificado um Alert com texto: {alert_text}, é possível que esteja com XSS Stored\n"
                  f"[*]Não será possível prosseguir com a função.")
            return

    except NoAlertPresentException:
        pass

    except UnexpectedAlertPresentException:
        driver.get(url)
        alert = driver.switch_to.alert
        alert_text = alert.text
        alert.dismiss()
        if "XSS encontrado" in alert_text:
            print(f"[*]Identificado um Alert com texto: {alert_text}, é possível que esteja com XSS Stored\n"
                  f"[*]Não será possível prosseguir com a função.")
            return

    except Exception as e:
        print(f"[X]Erro ao conectar em {url}: {e}")
        return []

    # Esta parte vai ser executada fora dos blocos try/except
    time.sleep(5)  # Aguarda a página carregar completamente
    elements = driver.find_elements(By.XPATH, "//a[@href]")

    base_domain = urlparse(url).netloc  # Domínio base da URL de origem
    base_url_set = set()  # Conjunto para armazenar URLs únicas do mesmo domínio
    full_url_list = [url]  # Lista final de URLs únicas do mesmo domínio

    for element in elements:
        href = element.get_attribute('href')
        if href:
            parsed_href = urlparse(href)
            # Verifica se a URL pertence ao mesmo domínio
            if parsed_href.netloc == base_domain:
                base_url = f"{parsed_href.scheme}://{parsed_href.netloc}{parsed_href.path}"
                # Adiciona apenas URLs do mesmo domínio, sem parâmetros repetidos
                if base_url not in base_url_set:
                    base_url_set.add(base_url)
                    if base_url not in full_url_list:
                        full_url_list.append(base_url)

    return full_url_list

if __name__ == "__main__":

    banner = r"""
     ____________________________________________________________________________
    |    _____  _____  _     __   __ _____  _____         _         _  _         |
    |   /  ___||  _  || |    \ \ / //  ___|/  ___|       | |       (_)| |        |
    |   \ `--. | | | || |     \ V / \ `--. \ `--.  _ __  | |  ___   _ | |_       | 
    |    `--. \| | | || |     /   \  `--. \ `--. \| '_ \ | | / _ \ | || __|      |
    |   /\__/ /\ \/' /| |____/ /^\ \/\__/ //\__/ /| |_) || || (_) || || |_       |
    |   \____/  \_/\ \\_____/\/   \/\____/ \____/ | .__/ |_| \___/ |_| \__|      |
    |               \ \                           | |                            |
    |                \_\                          |_|                            |
    |                                                                            |
    |                       |-Criado por: Gabriel Tacchi                         |
    |                       |-Estudante da Univiçosa                             |
    |                       |-Versão: 0.1                                        |
    |____________________________________________________________________________|
        """
    print(banner)
try:
    url = input("[!]Digite a URL: ")
    if not re.match(r'^https?://', url):
        url = 'http://' + url

    # Chama a função de cookies
    get_cookies(url)

    # Menu de opção para decisão das URLS
    while True:
        pegar_caminhos = input("[!]Pegar todos os caminhos da página? (Y/N): ").upper()

        if pegar_caminhos == "Y":
            todas_urls = catch_urls(url)
            # Pergunta se o usuário deseja excluir alguma URL
            if todas_urls:
                while True:
                    print("[*]URLs coletadas:")
                    for i, caminho in enumerate(todas_urls, start=1):
                        print(f"{i}. {caminho}")

                    excluir_urls = input("[!]Deseja excluir alguma URL? (Y/N): ").upper()
                    if excluir_urls == "Y":
                        # Permite exclusão de páginas da lista
                        while True:
                            try:
                                index_excluir = int(input("[!]Digite o número da URL a ser excluída (0 para cancelar): "))
                                if index_excluir == 0:
                                    break
                                elif 1 <= index_excluir <= len(todas_urls):
                                    url_removida = todas_urls.pop(index_excluir - 1)
                                    print(f"[+]URL '{url_removida}' excluída.")
                                else:
                                    print("[-]Número inválido. Tente novamente.")
                            except ValueError:
                                print("[-]Entrada inválida. Por favor, digite um número.")
                    elif excluir_urls == "N":
                        break
                    else:
                        print("[-]Opção inválida.")
                break
            else:
                print("[*]Não foi possível pegar as URLs")

        # Armazena a única url a ser testada
        elif pegar_caminhos == "N":
            todas_urls = [url]
            break
        else:
            print("[-]Opção inválida.")

    # Menu de opção para os testes
    while True:
        print("[*]Selecione o teste que deseja realizar:")
        print("[*]1. SQL Injection")
        print("[*]2. Cross-Site Scripting (XSS)")
        print("[*]3. Sair")

        opcao_principal = input("[!]Digite o número da sua escolha: ")

        if opcao_principal == "1":
            # Chama o código de SQL injection
            sqli.rodar_sqli_teste(todas_urls, driver, pegar_caminhos)
            break

        elif opcao_principal == "2":
            try:
                # Chama o código de XSS
                xss.rodar_xss_teste(todas_urls, driver, pegar_caminhos)
                break
            except UnexpectedAlertPresentException:
                alert = driver.switch_to.alert
                alert.dismiss()  # Fecha o alerta

        elif opcao_principal == "3":

            # Sai do aplicativo
            print("[*]Saindo...")
            break
        else:
            print("[-]Opção inválida")

except Exception as e:
    print(f"[X]Falha ao conectar ERRO: {e}")

finally:
    input("Pressione Enter para fechar o terminal...")
    driver.quit()