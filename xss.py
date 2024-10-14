import time
import datetime
import openpyxl
import re
from datetime import datetime
from selenium.webdriver.support.ui import WebDriverWait, Select
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.common.exceptions import NoAlertPresentException, UnexpectedAlertPresentException, TimeoutException
from selenium.webdriver.support import expected_conditions as EC
from urllib.parse import urlparse, parse_qs, urlunparse, parse_qsl

#URLs alteradas sem valor no parametro
urls_sem_parametro = []

# Cookies que serão inseridos para testes
cookies_armazenados = {}

# Urls testadas em stored
urls_xss_stored = []

# Armazenar as falhas
possiveis_falhas = []

# Animação de carregamento
animacao = ["[■□□□□□□□□□]", "[■■□□□□□□□□]", "[■■■□□□□□□□]", "[■■■■□□□□□□]", "[■■■■■□□□□□]",
            "[■■■■■■□□□□]", "[■■■■■■■□□□]", "[■■■■■■■■□□]", "[■■■■■■■■■□]", "[■■■■■■■■■■]"]

def animacao_carregamento(indice):
    # Exibe a animação correspondente ao índice
    indice = round(indice)
    indice = min(indice, len(animacao)-1)  # Limita o índice a 10
    print("\r" + animacao[indice], end='', flush=True)
    time.sleep(0.2)
def exibir_relatorio(url, pegar_caminhos):
    print("Site / Campo Vulnerável / Payload Injetável / Cookie gerado")

    # Cria uma nova pasta de trabalho
    wb = openpyxl.Workbook()
    ws = wb.active
    # Titulo relatorio
    ws.title = "Relatório XSS"
    # Cabeçalhos das colunas
    ws.append(["Site", "Campo Vulnerável", "Payload Injetável", "Cookie Gerado"])

    # Conjunto para rastrear combinações únicas
    combinacoes_unicas = set()

    for falha in possiveis_falhas:
        site = falha[0][0]  # URL do site
        campo_vulneravel = falha[1][0]  # Campo vulnerável
        payload = falha[2][0].strip()  # Payload injetável
        cookie_info = ': '.join(falha[3]) if len(falha[3]) == 2 else 'N/A'  # Cookie gerado, se existir

        # Cria uma tupla única para a combinação, incluindo cookie_info
        chave = (site, campo_vulneravel, payload, cookie_info)

        # Verifica se a combinação já foi exibida
        if chave not in combinacoes_unicas:
            # Adiciona a combinação ao conjunto para evitar duplicatas
            combinacoes_unicas.add(chave)

            # Impressão formatada
            print(f"{site} / {campo_vulneravel} / {payload} / {cookie_info}")
            # Adicionando ao excel
            ws.append([site, campo_vulneravel, payload, cookie_info])

    # Gerar o nome do arquivo a partir do domínio da URL
    if pegar_caminhos == "Y":
        dominio = urlparse(url).netloc
    else:
        # Sanitiza a URL diretamente para evitar erro ([Errno 22])
        dominio = re.sub(r'[^\w\-_\. ]', '_', f'{url}')

    # Obtém a data e hora atual
    data_hora_atual = datetime.now().strftime("%d-%m-%Y %H-%M")

    # Combina o nome do domínio e a data/hora no formato desejado
    nome_arquivo = f"Teste XSS - {dominio} {data_hora_atual}.xlsx"

    # Salva o arquivo Excel
    wb.save(nome_arquivo)
def verificar_parametros(url):
    parsed_url = urlparse(url)
    parametros = parse_qs(parsed_url.query)

    if parametros:
        return True
    else:
        return False
def xss_stored_test(url, driver):
    driver.get(url)

    try:
        alert = driver.switch_to.alert
        alert_text = alert.text
        alert.dismiss()
        if "XSS encontrado" in alert_text:
            if url not in urls_xss_stored:
                urls_xss_stored.append(url)
                print(f"\n[*]Identificado um Alert com texto: {alert_text}\n"
                      f"[*]Possível XSS Stored encontrado, encerrando testes na {url}\n"
                      f"[*]Em casos de XSS Stored os testes na página são encerrados para evitar falsos positivos")
            return True
        return False

    except NoAlertPresentException:
        return False

    except Exception as e:
        print(f"[X]Possível erro: {e}")
        return False

# Testes de XSS
def xss(url, campos, driver):
    try:
        with open('xss_payloads', 'r') as file:
            payloads = file.readlines()

        for i in range(len(campos)):
            driver.get(url)
            # Esperar achar todos os campos para não dar erro de index
            campos = WebDriverWait(driver, 10).until(EC.presence_of_all_elements_located((By.XPATH,"//input[@type='text' or @type='email' or @type='password' or @type='search' or name() or @type='textarea'] | //textarea")))
            nome_campo = campos[i].get_attribute("name")
            progresso_total = 0
            incremento = 10 / len(payloads)

            for payload in payloads:
                # Verifica se o payload não pode ser executado com sucesso
                numero_erro = 0
                #Progresso da animação
                progresso_total += incremento
                #Animação
                animacao_carregamento(progresso_total)

                driver.get(url)
                if xss_stored_test(url, driver):
                    return

                while True:
                    try:
                        campos = driver.find_elements(By.XPATH,"//input[@type='text' or @type='email' or @type='password' or @type='search' or name() or @type='textarea'] | //textarea")
                        campo = campos[i]
                        maxlength = campo.get_attribute("maxlength")
                        if maxlength:
                            try:
                                novo_tamanho = int(maxlength) * 10  # Exemplo: aumentar o tamanho máximo 10x
                                driver.execute_script(f"arguments[0].setAttribute('maxlength', '{novo_tamanho}')", campo)
                            except Exception:
                                pass

                        if not campo.is_enabled():
                            break
                        try:
                            campo.clear()
                            campo.send_keys(payload)
                            # Pode ser que envie ao colocar o payload, sem precisar "enviar"
                            try:
                                # Verificar se um alert foi disparado.
                                WebDriverWait(driver, 3).until(EC.alert_is_present())
                                alert = driver.switch_to.alert
                                # Atraso antes de fechar o alert para observação
                                time.sleep(2)  # Espera 2 segundos antes de fechar o alert
                                alert_text = alert.text
                                alert.dismiss()  # Fechar o alert

                                # Se encontrar "XSS encontrado" pela frase que o alert deveria mostrar (Evitar falso positivo)
                                if "XSS encontrado" in alert_text:
                                    possiveis_falhas.append([[url], [nome_campo], [payload.strip()], ["N/A"]])
                                break
                            except Exception:
                                pass

                        except Exception:
                            break

                        # Enviar o formulário
                        submit_button = driver.find_element(By.XPATH, "//input[@type='submit'] | //button[@type='submit']")
                        if submit_button:
                            submit_button.click()
                        else:
                            # Evitar Stale element not found
                            campos = driver.find_elements(By.XPATH,"//input[@type='text' or @type='email' or @type='password' or @type='search' or name() or @type='textarea'] | //textarea")
                            nome_campo = campos[i].get_attribute("name")
                            campo.send_keys(Keys.RETURN)
                        try:
                            # Verificar se um alert foi disparado
                            WebDriverWait(driver, 3).until(EC.alert_is_present())
                            alert = driver.switch_to.alert
                            # Atraso antes de fechar o alert para observação
                            time.sleep(2)  # Espera 2 segundos antes de fechar o alert
                            alert_text = alert.text
                            alert.accept()  # Fechar o alert

                            # Se encontrar "XSS encontrado" pela frase que o alert deveria mostrar (Evitar falso positivo)
                            if "XSS encontrado" in alert_text:
                                possiveis_falhas.append([[url], [nome_campo], [payload.strip()], ["N/A"]])
                                pass
                        except NoAlertPresentException:
                            pass

                        # Verifica se o campo interagido afeta a URL da página
                        if driver.current_url != url and driver.current_url not in todas_urls:
                            # Faz o parse da URL atual
                            current_url_parsed = urlparse(driver.current_url)

                            # Constrói a query mantendo todas as chaves dos parâmetros, mesmo as que têm valores vazios ou especiais como "#"
                            query_params = parse_qsl(current_url_parsed.query, keep_blank_values=True)
                            nova_query = '&'.join(f"{key}=" for key, value in query_params)

                            # Constrói a URL base sem os parâmetros
                            url_com_nova_query = f"{current_url_parsed.scheme}://{current_url_parsed.netloc}{current_url_parsed.path}"

                            # Adiciona a nova query à URL, se existir
                            if nova_query:
                                url_com_nova_query += "?" + nova_query
                            # Percorre a lista de URLs já capturadas
                            for url_list in todas_urls:
                                url_parsed = urlparse(url_list)

                                # Constrói a query ignorando os valores para as URLs da lista
                                query_params_list = parse_qsl(url_parsed.query, keep_blank_values=True)
                                nova_query_p_url_normal = '&'.join(f"{key}=" for key, value in query_params_list)
                                url_normal = f"{url_parsed.scheme}://{url_parsed.netloc}{url_parsed.path}"

                                # Adiciona a query à URL, se existir
                                if nova_query_p_url_normal:
                                    url_normal += "?" + nova_query_p_url_normal

                                # Adiciona a URL normal à lista se não estiver presente
                                if url_normal not in urls_sem_parametro:
                                    urls_sem_parametro.append(url_normal)

                            # Verifica se a URL atual (com a query sem valores) já está armazenada
                            if url_com_nova_query not in urls_sem_parametro:
                                todas_urls.append(driver.current_url)
                        break


                    except Exception:
                        numero_erro += 1
                        if numero_erro == 2:
                            break

        print("\r" + "[■■■■■■■■■■]completo!\n", end='', flush=True)

    except UnexpectedAlertPresentException:
        alert = driver.switch_to.alert
        alert.accept()
        pass

    except Exception as e:
        print(f"[X]Erro ao acessar {url}: {e}")
def xss_todos_campos_for_stored(url, driver):
    try:
        with open('xss_payloads', 'r') as file:
            payloads = file.readlines()

        progresso_total = 0
        incremento = 10 / len(payloads)

        for payload in payloads:
            progresso_total += incremento
            animacao_carregamento(progresso_total)

            driver.get(url)
            # Localizar os campos relevantes para o XSS
            campos = WebDriverWait(driver, 10).until(EC.presence_of_all_elements_located((By.XPATH,"//input[@type='text' or @type='email' or @type='password' or @type='search' or name() or @type='textarea'] | //textarea")))

            # Loop por todos os campos
            for i in range(len(campos)):
                try:
                    # Recarregar a página antes de cada tentativa
                    driver.get(url)
                    # Chama novamente os campos, evitando stale element not found
                    campos = WebDriverWait(driver, 10).until(EC.presence_of_all_elements_located((By.XPATH,"//input[@type='text' or @type='email' or @type='password' or @type='search' or name() or @type='textarea'] | //textarea")))
                    nome_campo = campos[i].get_attribute("name")
                    # Preencher os campos: i será o campo que recebe o payload
                    for j, campo in enumerate(campos):
                        maxlength = campo.get_attribute("maxlength")
                        if maxlength:
                            try:
                                # Aumentar o valor do maxlength via JavaScript
                                novo_tamanho = int(maxlength) * 10  # Exemplo: aumentar o tamanho máximo 10x
                                driver.execute_script(f"arguments[0].setAttribute('maxlength', '{novo_tamanho}')", campo)
                            except Exception:
                                pass
                        if not campo.is_enabled():
                            break
                        try:
                            campo.clear()
                        except Exception:
                            # Se o campo principal não for interagivel, pula para o proximo
                            continue
                        if j == i:
                            try:
                                campo.send_keys(payload.strip())
                            except Exception:
                                continue
                        else:
                            try:
                                campo.send_keys("1")
                            except Exception:
                                # Se o campo não for interagivel, segue normalmente (sem preenche-lo)
                                pass

                    # Verificar e clicar no botão de submit
                    submit_button = WebDriverWait(driver, 10).until(EC.element_to_be_clickable((By.XPATH, "//input[@type='submit'] | //button[@type='submit']")))

                    if submit_button:
                        submit_button.click()
                    else:
                        campo.send_keys(Keys.RETURN)

                    # Verificar se um alert foi disparado
                    try:
                        #Tempo pra dar tempo caso alert exista
                        WebDriverWait(driver, 3).until(EC.alert_is_present())
                        alert = driver.switch_to.alert
                        alert_text = alert.text
                        alert.dismiss()
                        if "XSS encontrado" in alert_text:
                            possiveis_falhas.append([[url], [nome_campo], [payload.strip()], ["N/A"]])
                            pass
                    # Caso não tenha alert, prossegue normalmente
                    except Exception:
                        pass

                    # Verifica se o campo interagido afeta a URL da página
                    if driver.current_url != url and driver.current_url not in todas_urls:
                        # Faz o parse da URL atual
                        current_url_parsed = urlparse(driver.current_url)

                        # Constrói a query mantendo todas as chaves dos parâmetros, mesmo as que têm valores vazios ou especiais como "#"
                        query_params = parse_qsl(current_url_parsed.query, keep_blank_values=True)
                        nova_query = '&'.join(f"{key}=" for key, value in query_params)

                        # Constrói a URL base sem os parâmetros
                        url_com_nova_query = f"{current_url_parsed.scheme}://{current_url_parsed.netloc}{current_url_parsed.path}"

                        # Adiciona a nova query à URL, se existir
                        if nova_query:
                            url_com_nova_query += "?" + nova_query
                        # Percorre a lista de URLs já capturadas
                        for url_list in todas_urls:
                            url_parsed = urlparse(url_list)

                            # Constrói a query ignorando os valores para as URLs da lista
                            query_params_list = parse_qsl(url_parsed.query, keep_blank_values=True)
                            nova_query_p_url_normal = '&'.join(f"{key}=" for key, value in query_params_list)
                            url_normal = f"{url_parsed.scheme}://{url_parsed.netloc}{url_parsed.path}"

                            # Adiciona a query à URL, se existir
                            if nova_query_p_url_normal:
                                url_normal += "?" + nova_query_p_url_normal

                            # Adiciona a URL normal à lista se não estiver presente
                            if url_normal not in urls_sem_parametro:
                                urls_sem_parametro.append(url_normal)

                        # Verifica se a URL atual (com a query sem valores) já está armazenada
                        if url_com_nova_query not in urls_sem_parametro:
                            todas_urls.append(driver.current_url)

                except UnexpectedAlertPresentException:
                    if xss_stored_test(url, driver):
                        return

        print("\r" + "[■■■■■■■■■■]completo!\n", end='', flush=True)

    except UnexpectedAlertPresentException:
        alert = driver.switch_to.alert
        alert.dismiss()

    except Exception as e:
        print(f"[X]Erro ao acessar {url}: {e}")
def xss_em_opcao(url, driver):
    try:
        with open('xss_payloads', 'r') as file:
            payloads = file.readlines()

            select_elements = driver.find_elements(By.TAG_NAME, "select")

            for element in select_elements:
                # Para coordernar a animação de carregamento
                progresso_total = 0
                incremento = 10 / len(payloads)

                select_name = element.get_attribute('name')

                # Pega somente o primeiro elemento dos "selects"
                select = Select(element)
                options = select.options

                # Testar apenas a primeira opção
                if options:
                    option = options[0]

                for payload in payloads:
                    # Verifica se o payload não pode ser executado com sucesso
                    numero_erro = 0
                    # Soma progresso da animação
                    progresso_total += incremento

                    # Escapar aspas simples e barras invertidas no payload
                    escaped_payload = payload.strip().replace("'", "\\'").replace("\\", "\\\\")

                    animacao_carregamento(progresso_total)

                    while True:
                        try:
                            driver.get(url)
                            try:
                                # Alterar o valor da primeira opção para o payload
                                driver.execute_script("arguments[0].setAttribute('value', arguments[1]);", option,escaped_payload)
                                # Selecionar a opção pelo texto
                                select.select_by_visible_text(option.text)
                            except Exception:
                                try:
                                    driver.execute_script("""var option = document.createElement('option');option.text = arguments[1];option.value = arguments[1];arguments[0].add(option);""", element, escaped_payload)
                                    select = Select(element)
                                    select.select_by_value(escaped_payload)  # Selecionar pelo valor inserido
                                except Exception:
                                    pass
                            # Submeter o formulário (se houver)
                            submit_button = driver.find_element(By.XPATH,"//input[@type='submit'] | //button[@type='submit']")
                            if submit_button:
                                submit_button.click()

                            # Verifica se o campo interagido afeta a URL da página
                            if driver.current_url != url and driver.current_url not in todas_urls:
                                # Faz o parse da URL atual
                                current_url_parsed = urlparse(driver.current_url)

                                # Constrói a query mantendo todas as chaves dos parâmetros, mesmo as que têm valores vazios ou especiais como "#"
                                query_params = parse_qsl(current_url_parsed.query, keep_blank_values=True)
                                nova_query = '&'.join(f"{key}=" for key, value in query_params)

                                # Constrói a URL base sem os parâmetros
                                url_com_nova_query = f"{current_url_parsed.scheme}://{current_url_parsed.netloc}{current_url_parsed.path}"

                                # Adiciona a nova query à URL, se existir
                                if nova_query:
                                    url_com_nova_query += "?" + nova_query
                                # Percorre a lista de URLs já capturadas
                                for url_list in todas_urls:
                                    url_parsed = urlparse(url_list)

                                    # Constrói a query ignorando os valores para as URLs da lista
                                    query_params_list = parse_qsl(url_parsed.query, keep_blank_values=True)
                                    nova_query_p_url_normal = '&'.join(f"{key}=" for key, value in query_params_list)
                                    url_normal = f"{url_parsed.scheme}://{url_parsed.netloc}{url_parsed.path}"

                                    # Adiciona a query à URL, se existir
                                    if nova_query_p_url_normal:
                                        url_normal += "?" + nova_query_p_url_normal

                                    # Adiciona a URL normal à lista se não estiver presente
                                    if url_normal not in urls_sem_parametro:
                                        urls_sem_parametro.append(url_normal)

                                # Verifica se a URL atual (com a query sem valores) já está armazenada
                                if url_com_nova_query not in urls_sem_parametro:
                                    todas_urls.append(driver.current_url)

                            # Verificar se um alert foi disparado
                            WebDriverWait(driver, 3).until(EC.alert_is_present())
                            alert = driver.switch_to.alert

                            # Atraso antes de fechar o alert para observação
                            time.sleep(2)  # Espera 2 segundos antes de fechar o alert
                            alert.accept()  # Fechar o alert

                            possiveis_falhas.append([[url], [select_name], [payload.strip()], ["N/A"]])
                            break

                        except Exception:
                            numero_erro += 1
                            if numero_erro == 2:
                                break

            print("\r" + "[■■■■■■■■■■]completo!\n", end='', flush=True)

    except Exception as e:
        print(f"[X]Erro: {e}")
def xss_por_parametro(url, driver):
    try:
        with open('xss_payloads', 'r') as file:
            payloads = file.readlines()

            parsed_url = urlparse(url)
            parametros = parse_qs(parsed_url.query)

        for key in parametros.keys():
            # Para coordernar a animação de carregamento
            progresso_total = 0
            incremento = 10 / len(payloads)

            for payload in payloads:
                # Tenta duas vezes para evitar erro
                tentativas = 0
                # Verifica se o payload não pode ser executado com sucesso
                numero_erro = 0

                progresso_total += incremento
                animacao_carregamento(progresso_total)

                # Constrói a nova URL sem codificar os parâmetros
                parametros_modificados = parametros.copy()
                parametros_modificados[key] = [payload.strip()]  # Aplica o payload diretamente

                # Constrói manualmente a query string
                query_string = '&'.join([f'{k}={v[0]}' for k, v in parametros_modificados.items()])

                if xss_stored_test(url, driver):
                    return

                while tentativas < 2:
                    try:
                        # Gera nova URL
                        nova_url = urlunparse(parsed_url._replace(query=query_string))
                        # Acessa o site com a nova URL (injeta)
                        driver.get(nova_url)

                        # Verificar se um alert foi disparado
                        try:
                            WebDriverWait(driver, 3).until(EC.alert_is_present())
                            alert = driver.switch_to.alert

                            # Atraso antes de fechar o alert para observação
                            time.sleep(2)  # Espera 2 segundos antes de fechar o alert
                            alert.accept()  # Fechar o alert

                            possiveis_falhas.append([[url], [key + " em URL"], [payload.strip()], ["N/A"]])
                            break

                        except NoAlertPresentException:
                            # Não houve alert; continuar testando outros payloads
                            break

                    except Exception:
                        numero_erro += 1
                        # Caso tenha dado dois erros, passa próximo payload
                        if numero_erro >= 2:
                            break

        print("\r" + "[■■■■■■■■■■]completo!\n", end='', flush=True)
    except Exception as e:
        print(f"[-] Erro ao acessar {url}: {e}")
def rodar_xss_teste(urls, driver, pegar_caminhos):

    #Feito para que URLS encontradas durante a execução possam ser adicionadas no final do loop
    global todas_urls
    todas_urls = urls

    #Loop
    for url in todas_urls:
        print(f"[+]Acessando {url}")
        try:
            driver.get(url)

            if url == driver.current_url:
                campos = driver.find_elements(By.XPATH, "//input[@type='text' or @type='email' or @type='password' or @type='search' or name() or @type='textarea'] | //textarea")
                select_elements = driver.find_elements(By.TAG_NAME, "select")
                parametro = verificar_parametros(url)

                if campos:
                    print("[*]Iniciando XSS em campos")
                    xss(url, campos, driver)
                    print("[*]Iniciando XSS c/ todos campos preenchidos")
                    xss_todos_campos_for_stored(url, driver)
                if select_elements:
                    print("[*]Iniciando XSS em opções")
                    xss_em_opcao(url, driver)
                if parametro:
                    print("[*]Iniciando XSS em parâmetros")
                    xss_por_parametro(url, driver)

        except UnexpectedAlertPresentException:
            # Pula para a próxima página
            if xss_stored_test(url, driver):
                continue
            else:
                pass

        except Exception as e:
            print(f"[X]Erro: {e}")

    if possiveis_falhas:
        exibir_relatorio(url, pegar_caminhos)
    else:
        print("[-]Nenhuma vulnerabilidade detalhada encontrada com 'SQLXSSploit'")
