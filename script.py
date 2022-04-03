# python3 -m pip install pycryptodome
import json
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
import requests
import binascii

keys=RSA.generate(2048)
message='signature'
h=SHA256.new(message.encode())
signature=pkcs1_15.new(keys).sign(h)
f=open('key.json','w')
f.write(keys.publickey().export_key().decode())
f.close()
url='http://localhost:5000/transactions/modify'
headers={'content-type': 'application/json'}
with open('path.json','w') as json_file:
    temp={'path':'key.json'}
    json.dump(temp,json_file)
payload=open('path.json').read()
r=requests.post(url,data=payload,headers=headers)
print("Añadiendo clave pública a senders (si sale 201 está bien)\n")
print(r)
print("\n")
url='http://localhost:5000/transactions/new'
chain=bytes()
for i in range(0,255,32):
    binascii.b2a_uu(signature[i:i+32])
with open('transaction.json','w') as json_file:
    temp={'sender':keys.publickey().export_key().decode(),"recipient":"b","signature":chain.decode()}
    json.dump(temp,json_file)
payload=open('transaction.json').read()
r=requests.post(url,data=payload,headers=headers)
print("Creando nueva transacción (si sale 201 está bien)\n")
print(r)
print("\n")
url='http://localhost:5000/mine'
r=requests.get(url)
print("Minando un bloque (si sale 200 está bien)\n")
print(r)
print("\n")
