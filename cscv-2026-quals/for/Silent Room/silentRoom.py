#!/usr/bin/python3
from Crypto.Cipher import AES
import sqlite3
import json
import base64
import hashlib

key = hashlib.sha256("chatapp-web-v2|fi-operator-73|FI-217".encode('utf8')).digest()

conn = sqlite3.connect('msg_cache.db')
cur = conn.cursor()
res = cur.execute("SELECT body FROM messages")
for body in res.fetchall():
    body = json.loads(body[0])
    iv, ct = base64.b64decode(body['iv']), base64.b64decode(body['ct'])
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    print(cipher.decrypt(ct).decode('utf8').strip())
    
    
    

