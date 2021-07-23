from time import sleep
import selenium
from selenium import webdriver
#from selenium.webdriver.chrome.options import Options
#from selenium.webdriver.common.keys import Keys
import argparse
import configparser
import pathlib
import inspect
import os, sys
import txt_rw
import base64
from Cryptodome.Cipher import AES
import tabulate

# pip install selenium
# maquina que executar o script PRECISA ter um navegador instalado
# necessário ter o chromedriver compátivel com a versão do chrome instalada na maquina, salva no diretório do script (pode ser em outro diretório, mas dai precisa declarar o path na declaração do objeto driver)
# https://chromedriver.storage.googleapis.com/index.html


# configurações do parser, responsável por receber os parâmetros na hora de rodar o script
parser = argparse.ArgumentParser(description='Verifica status dos circuitos no Sistema de Ativação.')
parser.add_argument('-c', '--circuito', nargs='+', required=True)
parser.add_argument('-a', '--atendimento', nargs='+')
args = parser.parse_args()

# recuperando parâmetros
Circuitos = args.circuito
CircuitosCA = args.atendimento

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
if config.get('credentials-sa','Login') == 'usuario@redeunifique.com.br' and config.get('credentials-sa','Senha') == 'senha':
    print('Durante a execução, desse script, o mesmo irá necessitar logar no sistema de ativação para realizar consultas;')
    print('Para prosseguir, insira suas credenciais no arquivo: {0}'.format(p.absolute()))

    print('Por questões de segurança, a senha deve ser primeiramente criptografada usando o script: cripto.exe')
    sys.exit()

VerificarCA = False

if type(CircuitosCA) is list:
    VerificarCA = True
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
    password = cipher.decrypt(base64.b64decode(config.get('credentials-sa','Senha').encode('utf-8')))
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
        value = "Não foi encontrado o circuito: {0}".format(circuito)
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
    driver.find_element_by_name("login").send_keys(login)
    driver.find_element_by_name("senha").send_keys(password)
    driver.find_element_by_class_name("btn").click()

# busca as caixas, retorna o nome delas e o link dos cadastros dos clientes
def verificar_caixas_atendimento(circuito):
    driver.get("http://erp.redeunifique.com.br/engenharia/cm_gerenciar_caixa/")

    driver.find_element_by_id("cm_caixa").send_keys('CA-'+circuito[:-1]+'-'+circuito[-1:])
    driver.find_element_by_class_name("bt-pesquisar-caixas").click()
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
                Links.append(cliente.find_element_by_tag_name('a').get_attribute('href'))
            except:
                pass
        CAS.append(Links)
        driver.find_element_by_class_name('close').click()
        sleep(0.5)
    return CAS

sa_site_login()

if VerificarCA:
    StatusCircuitos = []

for circuito in Circuitos:
    print("############################ {0} ############################".format(circuito))
    sc = verificar_circuito(circuito)
    circuito = sc.splitlines()
    circuito.pop(0)

    CamposCircuito = []

    for c in circuito:
        print(c)
        if VerificarCA:
            c1 = c.split()
            CamposCircuito.append(c1)
    print()
    if VerificarCA:
        StatusCircuitos.append(CamposCircuito)

print(StatusCircuitos)

if VerificarCA:
    erp_site_login()
    for circuito in CircuitosCA:
        counter = 1
        cas = verificar_caixas_atendimento(circuito)
        for ca in cas[0]:
            print(ca)
            for cliente in cas[counter]:
                print(cliente)
        counter = counter + 1

driver.quit()
driver = None
