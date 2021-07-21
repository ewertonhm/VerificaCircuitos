import base64
from Cryptodome.Cipher import AES

pwd = input('Digite a senha:')

msg_text = bytes(pwd,'utf-8').rjust(32)
secret_key = b'Glock9mmGlock9mm'

cipher = AES.new(secret_key, AES.MODE_ECB) # never use ECB in strong systems obviously
encoded = base64.b64encode(cipher.encrypt(msg_text))
print('Aqui está sua senha criptografada:')
print('Senha:' + encoded.decode('utf-8'))
