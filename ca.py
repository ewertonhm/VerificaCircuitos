from time import sleep
import selenium
from selenium import webdriver
import argparse
import configparser
import pathlib
import inspect
import os, sys
import txt_rw
import base64
from Cryptodome.Cipher import AES
from colorama import init, Fore, Back, Style
from termcolor import colored, cprint

# initialize colorama
init(convert=True)

# pip install selenium
# maquina que executar o script PRECISA ter um navegador instalado
# necessário ter o chromedriver compátivel com a versão do chrome instalada na maquina, salva no diretório do script (pode ser em outro diretório, mas dai precisa declarar o path na declaração do objeto driver)
# https://chromedriver.storage.googleapis.com/index.html


# configurações do parser, responsável por receber os parâmetros na hora de rodar o script
parser = argparse.ArgumentParser(description='Verifica status dos circuitos no Sistema de Ativação e lista separando por caixa de atendimento.\r\n Criado por Ewerton H. Marschalk')
parser.add_argument('-c', '--circuito', required=True)
args = parser.parse_args()

# recuperando parâmetros
Circuito = args.circuito

# criando objeto da biblioteta responsável por ler os credenciais do arquivo .ini
config = configparser.ConfigParser()

# setando nome e caminho do arquivo com as credenciais
filename = inspect.getframeinfo(inspect.currentframe()).filename
path = os.path.abspath(os.path.dirname(sys.argv[0]))

# criando objeto da biblioteca pathlib com o caminho do arquivo credentials.ini
p = pathlib.Path(str(path) + '\.credentials.ini')

# verifica se o arquivo credentials existe, se não, cria ele com o testo padrão
if not p.exists():
    p.touch()
    txt_rw.empty_credentials()

# lê o arquivo credentials.ini
config.read(str(path) + '\.credentials.ini')

# se o arquivo estiver com o seu padrão, exibe instruções para preencher ele e da quit
if config.get('credentials-sa', 'Login') == 'usuario@redeunifique.com.br' and config.get('credentials-sa',
                                                                                         'Senha') == 'senha':
    print(
        'Durante a execução, desse script, o mesmo irá necessitar logar no sistema de ativação para realizar consultas;')
    print('Para prosseguir, insira suas credenciais no arquivo: {0}'.format(p.absolute()))

    print('Por questões de segurança, a senha deve ser primeiramente criptografada usando o script: cripto.exe')
    sys.exit()

if config.get('credentials-erp', 'Login') == 'usuario' and config.get('credentials-erp', 'Senha') == 'senha':
    print('Durante a execução, desse script, o mesmo irá necessitar logar no ERP para realizar consultas;')
    print('Para prosseguir, insira suas credenciais no arquivo: {0}'.format(p.absolute()))

    print('Por questões de segurança, a senha deve ser primeiramente criptografada usando o script: cripto.exe')
    sys.exit()

# verifica se o arquivo webdriver se encontra na pasta certa, se não, exibe instruções para baixar ele
if not pathlib.Path("C:\webdriver\chromedriver.exe").exists():
    print("Para prosseguir, faça o download do chromedriver e salve no diretorio: 'C:/webdriver/chomedriver.exe'")
    print("Baixe o arquivo em: https://chromedriver.storage.googleapis.com/index.html")
    print("Baixe da mesma versão que o google chrome instalado no seu computador para evitar erros")
    sys.exit()

# define opções padrões e instancia o webdriver
options = selenium.webdriver.chrome.options.Options()
Keys = selenium.webdriver.common.keys.Keys
options.headless = True
options.add_argument('log-level=3')
options.add_experimental_option('excludeSwitches', ['enable-logging'])
driver = selenium.webdriver.Chrome(executable_path=r"C:\webdriver\chromedriver.exe", options=options)


# realiza o login no sistema de ativação
def sa_site_login():
    login = config.get('credentials-sa', 'Login')

    # descriptografa a senha
    secret_key = b'Glock9mmGlock9mm'
    cipher = AES.new(secret_key, AES.MODE_ECB)
    password = cipher.decrypt(base64.b64decode(config.get('credentials-sa', 'Senha').encode('utf-8')))
    password = password.decode('utf-8')
    password = password.strip()

    driver.get("http://ativacaofibra.redeunifique.com.br/")
    driver.find_element_by_name("login").send_keys(login)
    driver.find_element_by_name("senha").send_keys(password)
    driver.find_element_by_id("entrar").click()


# consulta o circuito e retorna uma String com o resultado
def verificar_circuito(circuito):
    driver.get("http://ativacaofibra.redeunifique.com.br/cadastro/interno.php?pg=interno&pg1=verificacoes_onu/status")

    driver.find_element_by_name("circ").send_keys(circuito)
    driver.find_element_by_name("circ").send_keys(Keys.ENTER)
    value = None
    try:
        driver.find_element_by_name("circ_id").send_keys(Keys.SPACE)
        driver.find_element_by_name("pesquisar").click()
        value = driver.find_element_by_id("maintable").text
    except:
        value = 'error'
    return value


# realiza o login na pagina do erp
def erp_site_login():
    login = config.get('credentials-erp', 'Login')

    secret_key = b'Glock9mmGlock9mm'
    cipher = AES.new(secret_key, AES.MODE_ECB)
    password = cipher.decrypt(base64.b64decode(config.get('credentials-erp', 'Senha').encode('utf-8')))
    password = password.decode('utf-8')
    password = password.strip()

    # descriptografa a senha
    driver.get("http://erp.redeunifique.com.br/")
    sleep(0.5)
    driver.find_element_by_name("login").send_keys(login)
    driver.find_element_by_name("senha").send_keys(password)
    driver.find_element_by_class_name("btn").click()


# busca as caixas, retorna o nome delas e o link dos cadastros dos clientes
def verificar_caixas_atendimento(circuito):
    driver.get("http://erp.redeunifique.com.br/engenharia/cm_gerenciar_caixa/")
    sleep(0.5)

    driver.find_element_by_id("cm_caixa").send_keys('CA-' + circuito[:-1] + '-' + circuito[-1:])
    driver.find_element_by_class_name("bt-pesquisar-caixas").click()
    sleep(0.5)
    Rows = driver.find_elements_by_tag_name("td")
    RowsText = []
    for row in Rows:
        RowsText.append(row.text)
    ca_names = []
    for row in RowsText:
        if row[:3] == 'CA-':
            ca_names.append(row[:15].strip())
    Buttons = driver.find_elements_by_class_name("btn_editarCaixa")
    CAS = [ca_names]
    for button in Buttons:
        button.click()
        sleep(1)
        Clientes = driver.find_elements_by_class_name("form-group-ocupacao")
        Links = []
        for cliente in Clientes:
            try:
                link = cliente.find_element_by_tag_name('a').get_attribute('href')
                codClientPosition = link.find('codCliente=')
                Links.append(link[codClientPosition + 11:])
            except:
                pass
        CAS.append(Links)
        sleep(0.5)
        driver.find_element_by_class_name('close').click()
        sleep(0.5)
    return CAS


## Define variáveis:
StatusCircuitos = []
Header = None
CAs = []
ClientesCAs = []
ClientesCAs_cod = []

# Realiza login no sistema de ativação
sa_site_login()

# para cada circuito na lista Circuitos,
# pega as informações do
sc = verificar_circuito(Circuito)
if sc == 'error':
    print(colored("Circuito não encontrado ou não existem ONUs cadastradas nesse circuito.", 'grey', attrs=['bold']))
else:
    circuito = sc.splitlines()
    Header = circuito[0]
    circuito.pop(0)

    CamposCircuito = []

    for c in circuito:
        c1 = c.split()
        CamposCircuito.append(c1)

    StatusCircuitos.append(CamposCircuito)

    erp_site_login()

    counter = 1
    cas = verificar_caixas_atendimento(Circuito)
    for ca in cas[0]:
        CAs.append(ca)
        ClientesCAs.append(cas[counter])
        counter = counter + 1

    counter = 0

    Header = Header.split()

    for ca in CAs:
        print("##################################################### {0} #####################################################".format(ca))
        print(colored("{0:16s} | {1:2s} | {2:9s} | {3:12s} | {4} {5} | {6} {7:6s} | {8} {9} | {10} {11}".format(Header[0],Header[1],Header[2],Header[3],Header[4],Header[5],Header[6],Header[7],Header[8],Header[9],Header[10],Header[11]), 'grey', attrs=['bold']))
        for c in ClientesCAs[counter]:
            for cs in StatusCircuitos[0]:
                if c == cs[4]:
                    if cs[2] == 'working':
                        print(
                            "{0:16s} | {1:2s} | {2:9s} | {3:12s} | {4:14s} | {5:12s} | {6:10} | {7}-{8}".format(cs[0],
                                                                                                                cs[1],
                                                                                                                cs[2],
                                                                                                                cs[3],
                                                                                                                cs[4],
                                                                                                                cs[5],
                                                                                                                cs[6],
                                                                                                                cs[7],
                                                                                                                cs[8]))
                    elif cs[2] == 'LOS':
                        print(colored(
                            "{0:16s} | {1:2s} | {2:9s} | {3:12s} | {4:14s} | {5:12s} | {6:10} | {7}-{8}".format(cs[0],
                                                                                                                cs[1],
                                                                                                                cs[2],
                                                                                                                cs[3],
                                                                                                                cs[4],
                                                                                                                cs[5],
                                                                                                                cs[6],
                                                                                                                cs[7],
                                                                                                                cs[8]),
                            'red'))
                    else:
                        print(colored(
                            "{0:16s} | {1:2s} | {2:9s} | {3:12s} | {4:14s} | {5:12s} | {6:10} | {7}-{8}".format(cs[0],
                                                                                                                cs[1],
                                                                                                                cs[2],
                                                                                                                cs[3],
                                                                                                                cs[4],
                                                                                                                cs[5],
                                                                                                                cs[6],
                                                                                                                cs[7],
                                                                                                                cs[8]),
                            'yellow'))
        counter = counter + 1

driver.quit()
driver = None
