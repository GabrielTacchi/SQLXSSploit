import time
import re
import os
import openpyxl
import difflib
from datetime import datetime
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.common.exceptions import UnexpectedAlertPresentException, NoAlertPresentException, TimeoutException
from selenium.webdriver.support.ui import WebDriverWait, Select
from selenium.webdriver.support import expected_conditions as EC
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, parse_qsl

#URLs alteradas sem valor no parametro
urls_sem_parametro = []

#Cookies que serão inseridos para testes
cookies_armazenados = {}

#Armazenar as falhas
possiveis_falhas = []

# Animação de carregamento, utilizada para feedback visual durante execuções longas
animacao = ["[■□□□□□□□□□]", "[■■□□□□□□□□]", "[■■■□□□□□□□]", "[■■■■□□□□□□]", "[■■■■■□□□□□]",
            "[■■■■■■□□□□]", "[■■■■■■■□□□]", "[■■■■■■■■□□]", "[■■■■■■■■■□]", "[■■■■■■■■■■]"]

# Função que exibe uma animação de carregamento na tela
def animacao_carregamento(indice):
    # Exibe a animação correspondente ao índice
    indice = round(indice) # Arredonda o valor do índice
    indice = min(indice, len(animacao)-1)  # Limita o índice a 10
    print("\r" + animacao[indice], end='', flush=True) # Atualiza a animação no terminal
    time.sleep(0.2) # Pausa para simular o carregamento

# Função para verificar se há erros comuns de SQL Injection na resposta ou nos elementos da página
def verificar_erros_sql(driver, response_text):
    # Lista de mensagens de erro comuns de SQL em diferentes bancos de dados
    erros_comuns = [
        "You have an error in your SQL syntax",  # MySQL/MariaDB
        "Warning: mysql_fetch_",  # MySQL/MariaDB, específico para falha na query
        "Unclosed quotation mark after the character string",  # SQL Server
        "Microsoft SQL Native Client error '80040e14'",  # SQL Server, erro de sintaxe
        "Syntax error converting the varchar value",  # SQL Server
        "Incorrect syntax near",  # SQL Server
        "Warning: mssql_query():",  # SQL Server, erro de execução de query
        "ORA-00933: SQL command not properly ended",  # Oracle
        "ORA-00907: missing right parenthesis",  # Oracle
        "ORA-01756: quoted string not properly terminated",  # Oracle
        "pg_query(): Query failed",  # PostgreSQL, erro de execução
        "ERROR: syntax error at or near",  # PostgreSQL, erro de sintaxe
        "ERROR: unterminated quoted string at or near",  # PostgreSQL, erro de string malformada
        "PostgreSQL query failed: ERROR: invalid input syntax",  # PostgreSQL
        "Unable to access user database: The used SELECT statements have a different number of columns" # Erro causado por queries malformadas
    ]

    # Itera sobre a lista de erros comuns
    for erro in erros_comuns:
        # Verificar no conteúdo da página
        if erro in response_text:
            return True, erro # Retorna verdadeiro se o erro foi encontrado

        # Verificar nos elementos da página usando XPath
        try:
            elements = driver.find_elements(By.XPATH, f"//*[contains(text(), '{erro}')]")
            if elements:
                return True, erro
        except Exception:
            pass

    return False, None

# Função para verificar se uma URL possui parâmetros
def verificar_parametros(url):
    parsed_url = urlparse(url) # Faz o parsing da URL
    parametros = parse_qs(parsed_url.query) # Extrai os parâmetros da URL

    if parametros:
        return True # Retorna verdadeiro se houver parâmetros
    else:
        return False # Retorna falso se não houver parâmetros

# Função para exibir um relatório e salvar as informações de falhas em um arquivo Excel
def exibir_relatorio(url, pegar_caminhos):
    print("Site / Campo Vulnerável / Payload Injetável / Cookie gerado")

    # Cria uma nova pasta de trabalho
    wb = openpyxl.Workbook()
    ws = wb.active
    # Titulo relatorio
    ws.title = "Relatório SQL Injection"
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
    nome_arquivo = f"Teste SQL Injection - {dominio} {data_hora_atual}.xlsx"

    # Salva o arquivo Excel
    wb.save(nome_arquivo)

#SQLi
def sqli(url, campos, driver):
    try:
        with open('direct_sql_payload', 'r') as file:
            payloads = file.readlines()

        for i in range(len(campos)):
            # Função para evitar que dê erro e ajudar campos serem pegos.
            timeout_campos = 0
            while True:
                try:
                    # Pegar url a cada iteração para evitar erro.
                    driver.get(url)
                    # Pega os campos novamente para evitar State Element not Found
                    campos = WebDriverWait(driver, 10).until(EC.presence_of_all_elements_located((By.XPATH,"//input[@type='text' or @type='email' or @type='password' or @type='search' or name() or @type='textarea'] | //textarea")))
                    nome_campo = campos[i].get_attribute("name")
                    break

                except TimeoutException:
                    timeout_campos += 1
                    if timeout_campos == 2:
                        continue

            # Para coordernar a animação de carregamento
            progresso_total = 0
            incremento = 10 / len(payloads)

            for payload in payloads:
                #Verifica se a falha (vulnerabilidade) ocorre duas vezes
                certeza_erro = 0
                # Tentativas caso dê erro
                tentativas = 0
                #Progresso da animação
                progresso_total += incremento
                #Animação
                animacao_carregamento(progresso_total)

                while True:
                    try:
                        driver.get(url)
                        # Verifica a quantidade de cookies
                        cookies_antes = driver.get_cookies()
                        campos = WebDriverWait(driver, 10).until(EC.presence_of_all_elements_located((By.XPATH,"//input[@type='text' or @type='email' or @type='password' or @type='search' or name() or @type='textarea'] | //textarea")))
                        campo = campos[i]

                        if not campo.is_enabled():
                            break


                        maxlength = campo.get_attribute("maxlength")
                        if maxlength:
                            try:
                                novo_tamanho = int(maxlength) * 10  # Exemplo: aumentar o tamanho máximo 10x
                                driver.execute_script(f"arguments[0].setAttribute('maxlength', '{novo_tamanho}')", campo)
                            except Exception:
                                pass
                        try:
                            campo.clear()
                            campo.send_keys(payload)
                        except Exception:
                            break

                        WebDriverWait(driver, 10).until(EC.presence_of_all_elements_located((By.XPATH, "//input[@type='submit'] | //button[@type='submit']")))
                        botoes_submit = driver.find_elements(By.XPATH,"//input[@type='submit'] | //button[@type='submit']")

                        if botoes_submit:
                            botoes_submit[0].click()
                        else:
                            campo.send_keys(Keys.RETURN)

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

                        # Verificar os cookies após o login
                        cookies_depois = driver.get_cookies()

                        # Verificações fora do Exception
                        if len(cookies_depois) > len(cookies_antes):
                            novos_cookies = [cookie for cookie in cookies_depois if cookie not in cookies_antes]
                            for novo_cookie in novos_cookies:
                                possiveis_falhas.append([[url], [nome_campo], [payload], [novo_cookie['name'], novo_cookie['value']]])
                                # Armazena Cookie para ser testado futuramente
                                cookies_armazenados[novo_cookie['name']] = novo_cookie['value']
                                # Apaga Cookie para evitar que atrapalhe alguma parte do código
                                driver.delete_cookie(novo_cookie['name'])
                        response_text = driver.page_source
                        erro_detectado, erro = verificar_erros_sql(driver, response_text)

                        if erro_detectado:
                            certeza_erro += 1
                            if certeza_erro == 2:
                                possiveis_falhas.append([[url], [nome_campo], [payload], ['N/A']])
                                break
                        else:
                            break

                    except UnexpectedAlertPresentException:
                        try:
                            alert = driver.switch_to.alert
                            alert.dismiss()
                            break  # Se o alerta for tratado, quebra o loop
                        except NoAlertPresentException:
                            pass  # Se não houver alerta, continua tentando

                    except Exception:
                        tentativas += 1
                        # Verificações nos erros do Exception
                        response_text = driver.page_source
                        erro_detectado, erro = verificar_erros_sql(driver, response_text)
                        if erro_detectado:
                            tentativas -= 1
                            certeza_erro += 1
                            if certeza_erro == 2:
                                possiveis_falhas.append([[url], [nome_campo], [payload], ['N/A']])
                                break
                        # Caso não tenha dado dois erros, zera para as tentativas testar sem erro
                        if tentativas >=  2:
                            break

        print("\r" + "[■■■■■■■■■■]completo!\n", end='', flush=True)

    except Exception as e:
        print(f"[-]Erro ao acessar {url}: {e}")
        # Se der erro, continua testando normal.
        pass
def sqli_em_opcao(url, driver):
    try:
        # Carregar os payloads a partir de um arquivo
        with open('direct_sql_payload', 'r') as file:
            payloads = file.readlines()

        select_elements = driver.find_elements(By.TAG_NAME, "select")
        for i, element in enumerate(select_elements):
            # Pegar url a cada iteração para evitar erro.
            driver.get(url)
            # Para coordernar a animação de carregamento
            progresso_total = 0
            incremento = 10 / len(payloads)

            # Procurar elementos select novamente após recarregar a página
            select_elements = driver.find_elements(By.TAG_NAME, "select")
            # Procurar elementos select novamente após recarregar a página
            select_name = select_elements[i].get_attribute('name')
            # Pega somente o primeiro elemento dos "selects"
            select = Select(select_elements[i])
            options = select.options

            # Testar apenas a primeira opção
            if options:
                option = options[0]

            for payload in payloads:
                # Verifica se a falha (vulnerabilidade) ocorre duas vezes
                certeza_erro = 0
                # Tentativas caso dê erro
                tentativas = 0
                # Soma progresso da animação
                progresso_total += incremento

                # Recarregar a página para cada novo payload
                driver.get(url)

                # Escapar aspas simples e barras invertidas no payload
                escaped_payload = payload.strip().replace("'", "\\'").replace("\\", "\\\\")

                animacao_carregamento(progresso_total)

                while True:
                    try:
                        # Alterar o valor da primeira opção para o payload
                        driver.execute_script("arguments[0].setAttribute('value', arguments[1]);",option, escaped_payload)

                        # Selecionar a opção pelo texto
                        select.select_by_visible_text(option.text)

                        # Submeter o formulário (se houver)
                        submit_button = driver.find_element(By.XPATH, "//input[@type='submit'] | //button[@type='submit']")
                        if submit_button:
                            submit_button.click()

                        # Verificar a resposta após o envio
                        response_text = driver.page_source
                        erro_detectado, erro = verificar_erros_sql(driver, response_text)

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

                        if erro_detectado:
                            certeza_erro += 1
                            if certeza_erro == 2:
                                possiveis_falhas.append([[url], [select_name], [payload], ['N/A', 'N/A']])
                                break
                        else:
                            break

                    except Exception:
                        tentativas += 1

                        # Verificações nos erros do Exception
                        response_text = driver.page_source
                        erro_detectado, erro = verificar_erros_sql(driver, response_text)

                        if erro_detectado:
                            certeza_erro += 1
                            tentativas -= 1
                            if certeza_erro == 2:
                                possiveis_falhas.append([[url], [select_name], [payload], ['N/A', 'N/A']])
                                break

                        # Caso tenha dado dois erros, passa próximo payload
                        if tentativas >= 2:
                            break

        print("\r" + "[■■■■■■■■■■]completo!\n", end='', flush=True)
    except Exception as e:
        print(f"Erro geral: {e}")
        # Se der erro, continua testando normal.
        pass
def sqli_por_parametro(url, driver):
    try:
        with open('direct_sql_payload', 'r') as file:
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
                # Obter duplicidade para confirmar erro (sucesso)
                certeza_erro = 0

                progresso_total += incremento
                animacao_carregamento(progresso_total)

                # Cria uma cópia dos parâmetros para alterar apenas o parâmetro em questão
                parametros_modificados = parametros.copy()
                parametros_modificados[key] = [payload.strip()]  # Aplica o payload apenas ao parâmetro atual

                # Reconstrói a URL com o parâmetro modificado
                query_string = urlencode(parametros_modificados, doseq=True)
                # Gera nova URL

                while tentativas < 2:
                    try:
                        nova_url = urlunparse(parsed_url._replace(query=query_string))
                        # Acessa o site com a nova URL (injeta)
                        driver.get(nova_url)

                        # Pegar a resposta da página
                        response_text = driver.page_source
                        # Verifica se os erros batem em erros comuns
                        erro_detectado, erro = verificar_erros_sql(driver, response_text)
                        if erro_detectado:
                            certeza_erro += 1
                            tentativas -= 1
                            if certeza_erro == 2:
                                possiveis_falhas.append([[url], [key + ', em URL'], [payload], ['N/A']])
                                break

                        else:
                            break

                    except Exception:
                        tentativas += 1

                        # Verificações nos erros do Exception
                        response_text = driver.page_source
                        erro_detectado, erro = verificar_erros_sql(driver, response_text)

                        if erro_detectado:
                            tentativas -= 1
                            certeza_erro += 1
                            if certeza_erro == 2:
                                possiveis_falhas.append([[url], [key,', em URL'], [payload], ['N/A', 'N/A']])
                                #Sai do loop
                                break

                        # Caso tenha dado dois erros, passa próximo payload
                        if tentativas >= 2:
                            break

        print("\r" + "[■■■■■■■■■■]completo!\n", end='', flush=True)
    except Exception as e:
        print(f"[-] Erro ao acessar {url}: {e}")
        # Se der erro, continua testando normal.
        pass
def sqli_em_cookies(url, driver):
    try:
        driver.get(url)
        url_base = urlparse(url).netloc

        cookies_originais = driver.get_cookies()

        # Verifica se o arquivo de cookies existe
        if os.path.exists(f'{url_base}.txt'):
            with open(f'{url_base}.txt', 'r') as cookies_file:
                lines = cookies_file.readlines()
                for line in lines:
                    partes = line.split("    ")
                    nome = partes[0].replace("nome: ", "").strip()
                    valor = partes[1].replace("valor: ", "").strip()
                    cookies_armazenados[nome] = valor

        if cookies_armazenados:
            with open('direct_sql_payload', 'r') as file:
                payloads = file.readlines()

            for nome, valor in cookies_armazenados.items():
                progresso_total = 0
                incremento = 10 / len(payloads)

                for payload in payloads:
                    # Obter duplicidade para confirmar erro (sucesso)
                    certeza_erro = 0

                    # Tentativas caso dê erro
                    tentativas = 0

                    progresso_total += incremento
                    animacao_carregamento(progresso_total)

                    while True:
                        try:
                            driver.get(url)
                            # Adiciona o payload como valor no cookie novo
                            driver.add_cookie({'name': nome, 'value': payload.strip()})
                            driver.refresh()

                            # Verifica se a página contém erros
                            response_text = driver.page_source
                            erro_detectado, erro = verificar_erros_sql(driver, response_text)

                            if erro_detectado:
                                certeza_erro += 1
                                if certeza_erro == 2:
                                    possiveis_falhas.append([[url],[f"Cookie: {nome}"], [payload], ["N/A"]])
                                    break

                            else:
                                break
                            #Remove o cookie antigo
                            driver.delete_cookie(nome)

                        except Exception:
                            tentativas += 1

                            # Verificações nos erros do Exception
                            response_text = driver.page_source
                            erro_detectado, erro = verificar_erros_sql(driver, response_text)

                            if erro_detectado:
                                certeza_erro += 1
                                tentativas -= 1
                                if certeza_erro == 2:
                                    possiveis_falhas.append([[url], [f"Cookie: {nome}"], [payload], ['N/A', 'N/A']])
                                    break

                            # Caso tenha dado dois erros, passa próximo payload
                            if tentativas >= 2:
                                break

                            if driver.get_cookies:
                                #Remove o cookie antigo
                                driver.delete_cookie(nome)

        else:
            print(f"[*]Cookie não encontrado, criando cookie 'teste'...")
            with open('direct_sql_payload', 'r') as file:
                payloads = file.readlines()

            progresso_total = 0
            incremento = 10 / len(payloads)

            for payload in payloads:
                # Obter duplicidade para confirmar erro (sucesso)
                certeza_erro = 0

                # Tentativas caso dê erro
                tentativas = 0

                progresso_total += incremento
                animacao_carregamento(progresso_total)

                while True:
                    try:
                        driver.get(url)
                        driver.add_cookie({'name': 'teste', 'value': payload.strip()})
                        driver.refresh()

                        # Verifica se a página contém erros
                        response_text = driver.page_source
                        erro_detectado, erro = verificar_erros_sql(driver, response_text)

                        if erro_detectado:
                            certeza_erro += 1
                            if certeza_erro == 2:
                                possiveis_falhas.append([[url],[f"Cookie: teste"], [payload], ["N/A","N/A"]])
                                break
                        else:
                            break

                        # Remove o cookie antigo
                        driver.delete_cookie('teste')

                    except Exception:
                        tentativas += 1

                        # Verificações nos erros do Exception
                        response_text = driver.page_source
                        erro_detectado, erro = verificar_erros_sql(driver, response_text)

                        if erro_detectado:
                            certeza_erro += 1
                            tentativas -= 1
                            if certeza_erro == 2:
                                possiveis_falhas.append([[url], [f"Cookie: teste"], [payload], ['N/A', 'N/A']])
                                break

                        # Caso tenha dado dois erros, passa próximo payload
                        if tentativas >= 2:
                            break

                        if driver.get_cookies:
                            # Remove o cookie antigo
                            driver.delete_cookie('teste')

        # Restaurar os cookies originais
        driver.delete_all_cookies()
        if cookies_originais:
            for cookie in cookies_originais:
                driver.add_cookie(cookie)
        driver.refresh()
        driver.get(url)
        print("\r" + "[■■■■■■■■■■]completo!\n", end='', flush=True)

    except Exception as e:
        print(f"[-]Erro ao acessar {url}: {e}")
        # Se der erro, continua testando normal.
        pass

#Time-Based Blind SQLi
def time_based_blind_sqli(url, campos, driver):
    try:
        with open('time_based_blind_sql_payload', 'r') as file:
            payloads = file.readlines()

        for i in range(len(campos)):
            # Função para evitar que dê erro e ajudar campos serem pegos.
            timeout_campos = 0
            while True:
                try:
                    # Pegar url a cada iteração para evitar erro.
                    driver.get(url)
                    # Pega os campos novamente para evitar State Element not Found
                    campos = WebDriverWait(driver, 10).until(EC.presence_of_all_elements_located((By.XPATH,"//input[@type='text' or @type='email' or @type='password' or @type='search' or name() or @type='textarea'] | //textarea")))
                    nome_campo = campos[i].get_attribute("name")
                    break

                except TimeoutException:
                    timeout_campos += 1
                    if timeout_campos == 2:
                        continue

            # Para coordernar a animação de carregamento
            progresso_total = 0
            incremento = 10 / len(payloads)

            for payload in payloads:
                # Progresso da animação
                progresso_total += incremento
                # Animação
                animacao_carregamento(progresso_total)
                # Zerar tentativas em caso de erro
                tentar_novamente = 0
                while True:
                    try:
                        # Recarrega a página para garantir que os elementos estejam atualizados
                        driver.get(url)
                        # Encontra todos os campos preenchíveis
                        campos = driver.find_elements(By.XPATH,"//input[@type='text' or @type='email' or @type='password' or @type='search' or name() or @type='textarea'] | //textarea")
                        campo = campos[i]

                        if not campo.is_enabled():
                            break
                        maxlength = campo.get_attribute("maxlength")
                        if maxlength:
                            try:
                                novo_tamanho = int(maxlength) * 10  # Exemplo: aumentar o tamanho máximo 10x
                                driver.execute_script(f"arguments[0].setAttribute('maxlength', '{novo_tamanho}')", campo)
                            except Exception:
                                pass
                        # Encontra todos os campos preenchíveis
                        campos = driver.find_elements(By.XPATH,"//input[@type='text' or @type='email' or @type='password' or @type='search' or name() or @type='textarea'] | //textarea")
                        campo = campos[i]
                        try:
                            campo.clear()
                            start_time = time.time()
                            campo.send_keys(payload)
                            end_time = time.time()
                            tempo_resposta = end_time - start_time

                            # As vezes roda sem enviar, algumas páginas podem ter mecanismos que façam isso.
                            if tempo_resposta >= 10:
                                possiveis_falhas.append([[url], [nome_campo], [payload], ['N/A']])
                                break
                        except Exception:
                            break

                        botoes_submit = driver.find_elements(By.XPATH,"//input[@type='submit'] | //button[@type='submit']")

                        if botoes_submit:
                            start_time = time.time()
                            botoes_submit[0].click()
                            end_time = time.time()
                            tempo_resposta = end_time - start_time
                            if tempo_resposta >= 10:
                                possiveis_falhas.append([[url], [nome_campo], [payload], ['N/A']])
                                break
                            else:
                                break
                        else:
                            start_time = time.time()
                            # Encontra todos os campos preenchíveis (stale element not found)
                            campos = driver.find_elements(By.XPATH,"//input[@type='text' or @type='email' or @type='password' or @type='search' or name() or @type='textarea'] | //textarea")
                            campo = campos[i]
                            #Envia payloads
                            campo.send_keys(Keys.RETURN)
                            end_time = time.time()
                            tempo_resposta = end_time - start_time
                            if tempo_resposta >= 10:
                                possiveis_falhas.append([[url], [nome_campo], [payload], ['N/A']])
                                break
                            else:
                                break

                    except Exception:
                        tentar_novamente += 1
                        if tentar_novamente == 2:
                            break

        print("\r" + "[■■■■■■■■■■]completo!\n", end='', flush=True)

    except Exception as e:
        print(f"[-]Erro ao acessar {url}: {e}")
        # Se der erro, continua testando normal.
        pass
def time_based_blind_sqli_em_opcao(url, driver):
    try:
        # Carregar os payloads a partir de um arquivo
        with open('time_based_blind_sql_payload', 'r') as file:
            payloads = file.readlines()

        # Pega página para evitar erro
        driver.get(url)

        # Procurar elementos select novamente após recarregar a página
        select_elements = WebDriverWait(driver, 10).until(EC.presence_of_all_elements_located((By.TAG_NAME, "select")))

        for i, select_element in enumerate(select_elements):
            # Pegar url a cada iteração para evitar erro.
            driver.get(url)

            # Para coordenar a animação de carregamento
            progresso_total = 0
            incremento = 10 / len(payloads) if payloads else 0

            for payload in payloads:
                # Recarregar a página para cada novo payload
                driver.get(url)
                # Procurar elementos select novamente após recarregar a página
                select_elements = driver.find_elements(By.TAG_NAME, "select")
                # Procurar elementos select novamente após recarregar a página
                select_name = select_elements[i].get_attribute('name')
                # Pega somente o primeiro elemento dos "selects"
                select = Select(select_elements[i])
                options = select.options

                # Progresso da animação
                progresso_total += incremento
                # Animação (supondo que você tenha uma função chamada animacao_carregamento)
                animacao_carregamento(progresso_total)

                # Tentativas caso dê erro
                tentativas = 0

                # Testar a primeira opção se houver
                if options:
                    option = options[0]  # Aqui, 'option' é um WebElement

                    # Obter o nome do campo a partir do select
                    nome_campo = select_name  # Usando o nome do select, não da opção

                    # Escapar aspas simples e barras invertidas no payload
                    escaped_payload = payload.strip().replace("'", "\\'").replace("\\", "\\\\")

                    while True:
                        try:
                            # Alterar o valor da primeira opção para o payload
                            driver.execute_script("arguments[0].setAttribute('value', arguments[1]);", option, escaped_payload)
                            # Selecionar a opção pelo texto
                            select.select_by_visible_text(option.text)

                            # Submeter o formulário (se houver)
                            botoes_submit = driver.find_elements(By.XPATH, "//input[@type='submit'] | //button[@type='submit']")

                            if botoes_submit:
                                start_time = time.time()
                                botoes_submit[0].click()
                                end_time = time.time()
                                tempo_resposta = end_time - start_time

                                if tempo_resposta >= 10:  # Ajuste o valor de acordo com sua necessidade
                                    possiveis_falhas.append([[url], [nome_campo], [payload], ['N/A']])
                                    break
                                else:
                                    break

                        except Exception as e:
                            tentativas += 1
                            if tentativas >= 2:
                                print(f"Erro ao tentar enviar o payload: {e}")
                                break

        print("\r" + "[■■■■■■■■■■] completo!\n", end='', flush=True)

    except Exception as e:
        print(f"Erro geral: {e}")
        # Se der erro, continua testando normal.
        pass
def time_based_blind_qli_por_parametro(url, driver):
    try:
        with open('time_based_blind_sql_payload', 'r') as file:
            payloads = file.readlines()

        parsed_url = urlparse(url)
        parametros = parse_qs(parsed_url.query)

        for key in parametros.keys():
            # Pegar url a cada iteração para evitar erro.
            driver.get(url)
            # Para coordernar a animação de carregamento
            progresso_total = 0
            # Para que o total de payloads dê 10 (Total da animação)
            incremento = 10 / len(payloads)

            for payload in payloads:
                # Pegar url a cada iteração para evitar erro.
                driver.get(url)
                # Progresso da animação
                progresso_total += incremento
                # Animação
                animacao_carregamento(progresso_total)

                # Cria uma cópia dos parâmetros para alterar apenas o parâmetro em questão
                parametros_modificados = parametros.copy()
                parametros_modificados[key] = [payload.strip()]  # Aplica o payload apenas ao parâmetro atual

                # Reconstrói a URL com o parâmetro modificado
                query_string = urlencode(parametros_modificados, doseq=True)
                # Gera nova URL
                nova_url = urlunparse(parsed_url._replace(query=query_string))

                start_time = time.time()
                # Acessa o site com a nova URL (injeta)
                driver.get(nova_url)
                end_time = time.time()

                tempo_resposta = end_time - start_time

                if tempo_resposta >= 10:
                    possiveis_falhas.append([[url], [key, ', em URL'], [payload], ['N/A']])

        print("\r" + "[■■■■■■■■■■]completo!\n", end='', flush=True)
    except Exception as e:
        print(f"[-] Erro ao acessar {url}: {e}")
        # Se der erro, continua testando normal.
        pass
def time_based_sqli_em_cookies(url, driver):
    try:
        driver.get(url)
        url_base = urlparse(url).netloc

        cookies_originais = driver.get_cookies()

        # Verifica se o arquivo de cookies existe
        if os.path.exists(f'{url_base}.txt'):
            with open(f'{url_base}.txt', 'r') as cookies_file:
                lines = cookies_file.readlines()
                for line in lines:
                    partes = line.split("    ")
                    nome = partes[0].replace("nome: ", "").strip()
                    valor = partes[1].replace("valor: ", "").strip()
                    cookies_armazenados[nome] = valor

        if cookies_armazenados:
            with open('time_based_blind_sql_payload', 'r') as file:
                payloads = file.readlines()

            for nome, valor in cookies_armazenados.items():
                progresso_total = 0
                incremento = 10 / len(payloads)

                for payload in payloads:
                    # Tentativas caso dê erro
                    tentativas = 0

                    progresso_total += incremento
                    animacao_carregamento(progresso_total)

                    while True:
                        try:
                            driver.get(url)
                            # Adiciona o payload como valor no cookie novo, inicia contagem
                            start_time = time.time()
                            driver.add_cookie({'name': nome, 'value': payload.strip()})
                            driver.refresh()
                            end_time = time.time()
                            #Calcula tempo de resposta que pegou o cookie, se for mais do que o estibulado (10), é vulneravel.
                            tempo_resposta = end_time - start_time
                            if tempo_resposta >= 10:
                                possiveis_falhas.append([[url],[f"Cookie: {nome}"], [payload], ["N/A","N/A"]])

                            # Remove o cookie antigo
                            driver.delete_cookie(nome)
                            break

                        except Exception:
                            tentativas += 1
                            if tentativas == 2:
                                # Remove o cookie antigo
                                driver.delete_cookie('teste')
                                break
        else:
            print(f"[*]Cookie não identificado, criando cookie 'teste'.")
            with open('time_based_blind_sql_payload', 'r') as file:
                payloads = file.readlines()

            progresso_total = 0
            incremento = 10 / len(payloads)

            for payload in payloads:
                # Tentativas caso dê erro
                tentativas = 0

                progresso_total += incremento
                animacao_carregamento(progresso_total)

                while True:
                    try:
                        driver.get(url)
                        # Adiciona o payload como valor no cookie novo, inicia contagem
                        start_time = time.time()
                        driver.add_cookie({'name': nome, 'value': payload.strip()})
                        driver.refresh()
                        end_time = time.time()
                        # Calcula tempo de resposta que pegou o cookie, se for mais do que o estibulado (10), é vulneravel.
                        tempo_resposta = end_time - start_time
                        if tempo_resposta >= 10:
                            possiveis_falhas.append([[url], [f"Cookie: 'teste'"], [payload], ["N/A", "N/A"]])

                        # Remove o cookie antigo
                        driver.delete_cookie(nome)
                        break

                    except Exception:
                        tentativas += 1
                        if tentativas == 2:
                            # Remove o cookie antigo
                            driver.delete_cookie('teste')
                            break

        # Restaurar os cookies originais
        driver.delete_all_cookies()
        if cookies_originais:
            for cookie in cookies_originais:
                driver.add_cookie(cookie)
        driver.refresh()
        driver.get(url)
        print("\r" + "[■■■■■■■■■■]completo!\n", end='', flush=True)

    except Exception as e:
        print(f"[-]Erro ao acessar {url}: {e}")
        # Se der erro, continua testando normal.
        pass

#Error-Based Blind SQLi
def error_based_blind_sqli(url, campos, driver):
    try:
        with open('error_based_sql_payload', 'r') as file:
            payloads = [line.strip() for line in file.readlines()]

        # Encontrar campos de entrada
        for i in range(len(campos)):
            # Função para evitar que dê erro e ajudar campos serem pegos.
            timeout_campos = 0
            while True:
                try:
                    # Pegar url a cada iteração para evitar erro.
                    driver.get(url)
                    # Pega os campos novamente para evitar State Element not Found
                    campos = WebDriverWait(driver, 10).until(EC.presence_of_all_elements_located((By.XPATH,"//input[@type='text' or @type='email' or @type='password' or @type='search' or name() or @type='textarea'] | //textarea")))
                    nome_campo = campos[i].get_attribute("name")
                    break

                except TimeoutException:
                    timeout_campos += 1
                    if timeout_campos == 2:
                        continue

            # Para coordernar a animação de carregamento
            progresso_total = 0
            incremento = 10 / len(payloads)

            for payload in payloads:
                #Progresso da animação
                progresso_total += incremento
                #Animação
                animacao_carregamento(progresso_total)
                # Obter duplicidade para confirmar erro (sucesso)
                certeza_erro = 0
                # Tentativas caso dê erro
                tentativas = 0
                # Verifica se o índice do payload é par (true) ou ímpar (false)
                if payloads.index(payload) % 2 == 0:  # Payload "true"
                    payload_true = payload
                    payload_false = payloads[payloads.index(payload) + 1]  # Próximo payload (false)
                    while True:
                        try:
                            # Recarrega a página para continuar testes
                            driver.get(url)

                            # Stale element not found
                            campos = driver.find_elements(By.XPATH,"//input[@type='text' or @type='email' or @type='password' or @type='search' or name() or @type='textarea'] | //textarea")
                            campo = campos[i]

                            if not campo.is_enabled():
                                break

                            maxlength = campo.get_attribute("maxlength")
                            if maxlength:
                                try:
                                    novo_tamanho = int(maxlength) * 10  # Exemplo: aumentar o tamanho máximo 10x
                                    driver.execute_script(f"arguments[0].setAttribute('maxlength', '{novo_tamanho}')",campo)
                                except Exception:
                                    pass

                            try:
                                campo.clear()
                                campo.send_keys(payload)
                            except Exception:
                                break

                            botoes_submit = driver.find_elements(By.XPATH, "//input[@type='submit'] | //button[@type='submit']")
                            if botoes_submit:
                                botoes_submit[0].click()
                            else:
                                campo.send_keys(Keys.RETURN)

                            time.sleep(1)  # Esperar para garantir que a página tenha carregado
                            resposta_true = driver.page_source  # Capturar o conteúdo da página após o payload "true"

                            # Recarrega a página para continuar testes e evitar testar em página redirecionada por algum motivo
                            driver.get(url)

                            # Stale element not found
                            campos = driver.find_elements(By.XPATH,"//input[@type='text' or @type='email' or @type='password' or @type='search' or name() or @type='textarea'] | //textarea")
                            campo = campos[i]

                            maxlength = campo.get_attribute("maxlength")
                            if maxlength:
                                try:
                                    novo_tamanho = int(maxlength) * 10  # Exemplo: aumentar o tamanho máximo 10x
                                    driver.execute_script(f"arguments[0].setAttribute('maxlength', '{novo_tamanho}')",campo)
                                except Exception:
                                    pass

                            # Enviar payload "false"
                            campo.clear()
                            campo.send_keys(payload_false)

                            botoes_submit = driver.find_elements(By.XPATH, "//input[@type='submit'] | //button[@type='submit']")
                            if botoes_submit:
                                botoes_submit[0].click()
                            else:
                                campo.send_keys(Keys.RETURN)

                            time.sleep(1)  # Esperar para garantir que a página tenha carregado
                            resposta_false = driver.page_source  # Capturar o conteúdo da página após o payload "false"

                            # Remover payloads das respostas
                            resposta_true = re.sub(re.escape(payload_true), '', resposta_true)
                            resposta_false = re.sub(re.escape(payload_false), '', resposta_false)

                            # Comparar as respostas
                            if resposta_true != resposta_false:
                                certeza_erro += 1
                                if certeza_erro == 2:
                                    possiveis_falhas.append([[url], [nome_campo], [payload + ' Error Based '], ['N/A']])
                                    break
                            else:
                                break

                        except Exception:
                            tentativas += 1
                            if tentativas == 2:
                                break

        print("\r" + "[■■■■■■■■■■]completo!\n", end='', flush=True)

    except Exception as e:
        print(f"[-]Erro ao acessar {url}: {e}")
        # Se der erro, continua testando normal.
        pass
def error_based_blind_sqli_em_opcao(url, driver):
    try:
        # Carregar os payloads a partir de um arquivo
        with open('error_based_sql_payload', 'r') as file:
            payloads = [line.strip() for line in file.readlines()]

        # Procurar elementos select novamente após recarregar a página
        select_elements = driver.find_elements(By.TAG_NAME, "select")

        for i, element in enumerate(select_elements):
            # Pegar url a cada iteração para evitar erro.
            driver.get(url)

            # Para coordernar a animação de carregamento
            progresso_total = 0
            # Para que o total de payloads dê 10 (Total da animação)
            incremento = 10 / len(payloads)

            # Procurar elementos select novamente após recarregar a página
            select_elements = driver.find_elements(By.TAG_NAME, "select")

            for payload in payloads:
                if payloads.index(payload) % 2 == 0:  # Payload "true"
                    payload_true = payload
                    payload_false = payloads[payloads.index(payload) + 1]  # Próximo payload (false)

                    # Progresso da animação
                    progresso_total += incremento
                    # Animação
                    animacao_carregamento(progresso_total)

                    # Obter duplicidade para confirmar erro (sucesso)
                    certeza_erro = 0

                    # Tentativas caso dê erro
                    tentativas = 0

                    while True:
                        try:
                            # Procurar elementos select novamente após recarregar a página
                            select_elements = driver.find_elements(By.TAG_NAME, "select")
                            # Procurar elementos select novamente após recarregar a página
                            select_name = select_elements[i].get_attribute('name')
                            # Pega somente o primeiro elemento dos "selects"
                            select = Select(select_elements[i])
                            # Pegar a primeira opção
                            options = select.options

                            if options:
                                option = options[0]

                            # Alterar o valor da primeira opção para o payload
                            driver.execute_script("arguments[0].setAttribute('value', arguments[1]);",option, payload_true)
                            # Selecionar a opção pelo texto
                            select.select_by_visible_text(option.text)
                            # Submeter o formulário (se houver)
                            submit_button = driver.find_element(By.XPATH, "//input[@type='submit'] | //button[@type='submit']")
                            if submit_button:
                                submit_button.click()
                            # Verificar a resposta após o envio
                            time.sleep(1)
                            resposta_true = driver.page_source


                            select_element = WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.NAME, select_name)))

                            select = Select(select_element)
                            options = select.options

                            if options:
                                option = options[0]

                            driver.execute_script("arguments[0].setAttribute('value', arguments[1]);", option,payload_false)
                            # Submeter o formulário (se houver)
                            submit_button = driver.find_element(By.XPATH,"//input[@type='submit'] | //button[@type='submit']")
                            if submit_button:
                                submit_button.click()
                            time.sleep(1)
                            resposta_false = driver.page_source
                            # Remover payloads das respostas
                            resposta_true = re.sub(re.escape(payload_true), '', resposta_true)
                            resposta_false = re.sub(re.escape(payload_false), '', resposta_false)

                            # Comparar as respostas
                            if resposta_true != resposta_false:
                                certeza_erro += 1
                                if certeza_erro == 2:
                                    possiveis_falhas.append([[url], [select_name], [payload + ' Error Based '], ['N/A']])
                                    break

                            else:
                                break

                        except Exception:
                            tentativas += 1
                            if tentativas == 2:
                                break

            print("\r" + "[■■■■■■■■■■]completo!\n", end='', flush=True)

    except Exception as e:
        print(f"Erro geral: {e}")
        # Se der erro, continua testando normal.
        pass
def error_based_blind_qli_por_parametro(url, driver):
    try:
        # Carregar os payloads a partir de um arquivo
        with open('error_based_sql_payload', 'r') as file:
            payloads = [line.strip() for line in file.readlines()]

        parsed_url = urlparse(url)
        parametros = parse_qs(parsed_url.query)

        for key in parametros.keys():

            # Para coordernar a animação de carregamento
            progresso_total = 0
            # Para que o total de payloads dê 10 (Total da animação)
            incremento = 10 / len(payloads)

            for payload in payloads:
                if payloads.index(payload) % 2 == 0:
                    payload_true = payload
                    payload_false = payloads[payloads.index(payload) + 1]

                # Progresso da animação
                progresso_total += incremento
                # Animação
                animacao_carregamento(progresso_total)

                # Obter duplicidade para confirmar erro (sucesso)
                certeza_erro = 0

                # Tentativas caso dê erro
                tentativas = 0

                while True:
                    try:
                        # Cria uma cópia dos parâmetros para alterar apenas o parâmetro em questão
                        parametros_modificados = parametros.copy()
                        # Aplica o payload apenas ao parâmetro atual
                        parametros_modificados[key] = [payload_true.strip()]

                        # Reconstrói a URL com o parâmetro modificado
                        query_string = urlencode(parametros_modificados, doseq=True)
                        # Gera nova URL
                        nova_url = urlunparse(parsed_url._replace(query=query_string))

                        # Acessa o site com a nova URL (injeta)
                        driver.get(nova_url)

                        resposta_true = driver.page_source

                        # Cria uma cópia dos parâmetros para alterar apenas o parâmetro em questão
                        parametros_modificados = parametros.copy()
                        # Aplica o payload apenas ao parâmetro atual
                        parametros_modificados[key] = [payload_false.strip()]

                        # Reconstrói a URL com o parâmetro modificado
                        query_string = urlencode(parametros_modificados, doseq=True)
                        # Gera nova URL
                        nova_url = urlunparse(parsed_url._replace(query=query_string))

                        # Acessa o site com a nova URL (injeta)
                        driver.get(nova_url)

                        # Remover payloads das respostas
                        resposta_true = re.sub(re.escape(payload_true), '', resposta_true)
                        resposta_false = re.sub(re.escape(payload_false), '', resposta_false)

                        # Comparar as respostas
                        if resposta_true != resposta_false:
                            certeza_erro += 1
                            if certeza_erro == 2:
                                possiveis_falhas.append([[url], [key, ', em URL'], [payload], ['N/A']])
                                break
                        else:
                            break

                    except Exception:
                        tentativas += 1
                        if tentativas == 2:
                            break

        print("\r" + "[■■■■■■■■■■]completo!\n", end='', flush=True)
    except Exception as e:
        print(f"[-] Erro ao acessar {url}: {e}")
        # Se der erro, continua testando normal.
        pass
def error_based_sqli_em_cookies(url, driver):
    try:
        driver.get(url)
        url_base = urlparse(url).netloc

        cookies_originais = driver.get_cookies()

        # Verifica se o arquivo de cookies existe
        if os.path.exists(f'{url_base}.txt'):
            with open(f'{url_base}.txt', 'r') as cookies_file:
                lines = cookies_file.readlines()
                for line in lines:
                    partes = line.split("    ")
                    nome = partes[0].replace("nome: ", "").strip()
                    valor = partes[1].replace("valor: ", "").strip()
                    cookies_armazenados[nome] = valor

        if cookies_armazenados:
            with open('error_based_sql_payload', 'r') as file:
                payloads = file.readlines()

            for nome, valor in cookies_armazenados.items():
                progresso_total = 0
                incremento = 10 / len(payloads)

                for payload in payloads:
                    if payloads.index(payload) % 2 == 0:
                        payload_true = payload
                        payload_false = payloads[payloads.index(payload) + 1]

                    # Obter duplicidade para confirmar erro (sucesso)
                    certeza_erro = 0

                    # Tentativas caso dê erro
                    tentativas = 0

                    progresso_total += incremento
                    animacao_carregamento(progresso_total)

                    while True:
                        try:
                            driver.get(url)
                            # Adiciona o payload como valor no cookie novo
                            driver.add_cookie({'name': nome, 'value': payload_true.strip()})
                            driver.refresh()

                            # Verifica se a página contém erros
                            resposta_true = driver.page_source

                            driver.get(url)

                            # Adiciona o payload como valor no cookie novo
                            driver.add_cookie({'name': nome, 'value': payload_false.strip()})
                            driver.refresh()

                            resposta_false = driver.page_source

                            # Remover valores de cookies e tokens
                            resposta_true_limpa = re.sub(r'(?i)(value=".*?")', 'value="REDACTED"', resposta_true)
                            resposta_false_limpa = re.sub(r'(?i)(value=".*?")', 'value="REDACTED"', resposta_false)

                            # Comparar as respostas sem os valores dos cookies, neste caso, é irrelevante.
                            if resposta_true_limpa != resposta_false_limpa:
                                certeza_erro += 1
                                # Imprime as diferenças entre as respostas
                                print("Diferenças entre as respostas:")
                                diff = difflib.ndiff(resposta_true.splitlines(), resposta_false.splitlines())
                                for linha in diff:
                                    print(linha)
                                if certeza_erro == 2:
                                    possiveis_falhas.append([[url], [f"Cookie {nome}"], [payload_true], ['N/A']])
                                    break
                            else:
                                break

                            # Remove o cookie antigo
                            driver.delete_cookie(nome)

                        except Exception:
                            tentativas += 1
                            if tentativas >= 2:
                                break

                            if driver.get_cookies:
                                # Remove o cookie antigo
                                driver.delete_cookie(nome)

        else:
            print(f"[*]Cookie não encontrado, criando cookie 'teste'...")
            with open('error_based_sql_payload', 'r') as file:
                payloads = file.readlines()

            progresso_total = 0
            incremento = 10 / len(payloads)

            for payload in payloads:
                if payloads.index(payload) % 2 == 0:
                    payload_true = payload
                    payload_false = payloads[payloads.index(payload) + 1]

                # Obter duplicidade para confirmar erro (sucesso)
                certeza_erro = 0

                # Tentativas caso dê erro
                tentativas = 0

                progresso_total += incremento
                animacao_carregamento(progresso_total)

                while True:
                    try:
                        driver.get(url)
                        # Adiciona o payload como valor no cookie novo
                        driver.add_cookie({'name': 'teste', 'value': payload_true.strip()})
                        driver.refresh()

                        # Verifica se a página contém erros
                        resposta_true = driver.page_source

                        driver.get(url)

                        # Adiciona o payload como valor no cookie novo
                        driver.add_cookie({'name': 'teste', 'value': payload_false.strip()})
                        driver.refresh()

                        resposta_false = driver.page_source

                        # Remover os valores dos cookies antes de comparar as respostas
                        resposta_true_limpa = re.sub(r'(?i)(value=".*?")', 'value="REDACTED"', resposta_true)
                        resposta_false_limpa = re.sub(r'(?i)(value=".*?")', 'value="REDACTED"', resposta_false)

                        # Comparar as respostas sem os valores dos cookies, neste caso, é irrelevante.
                        if resposta_true_limpa != resposta_false_limpa:
                            certeza_erro += 1
                            if certeza_erro == 2:
                                possiveis_falhas.append([[url], [f"Cookie {nome}"], [payload_true], ['N/A']])
                                break
                        else:
                            break

                        # Remove o cookie antigo
                        driver.delete_cookie(nome)


                    except Exception:
                        tentativas += 1
                        if tentativas >= 2:
                            break

                        if driver.get_cookies:
                            # Remove o cookie antigo
                            driver.delete_cookie(nome)

        # Restaurar os cookies originais
        driver.delete_all_cookies()
        if cookies_originais:
            for cookie in cookies_originais:
                driver.add_cookie(cookie)
        driver.refresh()
        driver.get(url)
        print("\r" + "[■■■■■■■■■■]completo!\n", end='', flush=True)

    except Exception as e:
        print(f"[-]Erro ao acessar {url}: {e}")
        # Se der erro, continua testando normal.
        pass

#Inicio
def rodar_sqli_teste(urls, driver, pegar_caminhos):
    #Feito para que URLS encontradas durante a execução possam ser adicionadas no final do loop
    global todas_urls
    todas_urls = urls

    for url in todas_urls:
        print(f"[+]Acessando {url}")
        driver.get(url)

        if url != driver.current_url:
            print(f"[*]Página: {url} está sendo redirecionada para: {driver.current_url}")
            while True:
                testar = input(f"[!]Testar {driver.current_url} ? (Y/N) ").upper()
                if testar == "Y":
                    if driver.current_url not in todas_urls:
                        todas_urls.append(driver.current_url)
                    break
                elif testar == "N":
                    break
                else:
                    print("[*]Opção inválida")
            continue

        else:
            campos = WebDriverWait(driver, 10).until(EC.presence_of_all_elements_located((By.XPATH,"//input[@type='text' or @type='email' or @type='password' or @type='search' or name() or @type='textarea'] | //textarea")))
            select_elements = driver.find_elements(By.TAG_NAME, "select")
            parametro = verificar_parametros(url)

            if campos:
                print("[*]Iniciando SQLi Generico e Auth Bypass")
                sqli(url, campos, driver)
                print("[*]Iniciando Time-based blind SQLi")
                time_based_blind_sqli(url, campos, driver)
                print("[*]Iniciando Error-Based Blind SQLI")
                error_based_blind_sqli(url, campos, driver)

            if parametro:
                print("[*]Iniciando SQLi por parâmetro")
                sqli_por_parametro(url, driver)
                print("[*]Iniciando Time-based blind SQLi por parâmetroo")
                time_based_blind_qli_por_parametro(url, driver)
                print("[*]Iniciando Error-based blind por parâmetro")
                error_based_blind_qli_por_parametro(url, driver)

            if select_elements:
                print("[*]Iniciando SQLi em opção")
                sqli_em_opcao(url, driver)
                print("[*]Iniciando Time-based blind SQLi em opção")
                time_based_blind_sqli_em_opcao(url, driver)
                print("[*]Iniciando Error-based blind SQLI em opção")
                error_based_blind_sqli_em_opcao(url, driver)

    print("[*]Testando SQLI em Cookies")
    sqli_em_cookies(todas_urls[0], driver)
    print("[*]Testando Time Based SQLI em Cookies")
    time_based_sqli_em_cookies(todas_urls[0], driver)
    print("[*]Testando Error Based SQLI em Cookies")
    error_based_sqli_em_cookies(todas_urls[0], driver)

    if possiveis_falhas:
        exibir_relatorio(url, pegar_caminhos)
    else:
        print("[-]Nenhuma vulnerabilidade encontrada com 'SQLXSSploit'")