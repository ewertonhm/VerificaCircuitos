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

# pip install selenium
# maquina que executar o script PRECISA ter um navegador instalado
# necessário ter o chromedriver compátivel com a versão do chrome instalada na maquina, salva no diretório do script (pode ser em outro diretório, mas dai precisa declarar o path na declaração do objeto driver)
# https://chromedriver.storage.googleapis.com/index.html

parser = argparse.ArgumentParser(description='Verifica status dos circuitos no Sistema de Ativação.')
parser.add_argument('-c', '--circuito', nargs='+', required=True)
args = parser.parse_args()

Circuitos = args.circuito

config = configparser.ConfigParser()

filename = inspect.getframeinfo(inspect.currentframe()).filename
path = os.path.abspath(os.path.dirname(sys.argv[0]))

p = pathlib.Path(str(path) + '\.credentials.ini')

if not p.exists():
    p.touch()
    txt_rw.empty_credentials()

config.read(str(path) + '\.credentials.ini')

if config.get('credentials','Login') == 'usuario@redeunifique.com.br' and config.get('credentials','Senha') == 'senha':
    print('Para prosseguir, insira suas credenciais no arquivo: {0}'.format(p.absolute()))

    print('Por questões de segurança, a senha deve ser primeiramente criptografada usando o script: cripto.exe')
    sys.exit()


if not pathlib.Path("C:\webdriver\chromedriver.exe").exists():
    print("Para prosseguir, faça o download do chromedriver e salve no diretorio: 'C:/webdriver/chomedriver.exe'")
    print("Baixe o arquivo em: https://chromedriver.storage.googleapis.com/index.html")
    print("Baixe da mesma versão que o google chrome instalado no seu computador para evitar erros")
    sys.exit()

options = selenium.webdriver.chrome.options.Options()
Keys = selenium.webdriver.common.keys.Keys
options.headless = True
options.add_argument('log-level=3')
options.add_experimental_option('excludeSwitches', ['enable-logging'])
driver = selenium.webdriver.Chrome(executable_path=r"C:\webdriver\chromedriver.exe", options=options)


def openAtivacao():
    driver.get("http://ativacaofibra.redeunifique.com.br/")


def site_login():
    login = config.get('credentials', 'Login')

    secret_key = b'Glock9mmGlock9mm'
    cipher = AES.new(secret_key, AES.MODE_ECB)
    password = cipher.decrypt(base64.b64decode(config.get('credentials','Senha').encode('utf-8')))
    password = password.decode('utf-8')
    password = password.strip()

    openAtivacao()
    driver.find_element_by_name("login").send_keys(login)
    driver.find_element_by_name("senha").send_keys(password)
    driver.find_element_by_id("entrar").click()

def go_status():
    driver.get("http://ativacaofibra.redeunifique.com.br/cadastro/interno.php?pg=interno&pg1=verificacoes_onu/status")


def run():
    site_login()
    go_status()

def verificar_circuito(circuito):
    go_status()
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


run()
for circuito in Circuitos:
    print("############################ CIRCUITO {0} ############################".format(circuito))
    print(verificar_circuito(circuito))
    print()

driver.quit()
driver = None
