endbody = "\r\n\r\n\r\n\r\n"
headers = """POST / HTTP/1.1\nHost: localhost\nUser-Agent: curl/7.65.3\nAccept: */*\nContent-Length: %d\nContent-Type: application/x-www-form-urlencoded\n\n%s%s"""

import random 
import string
import sys
buf = ""
unwanted_chars = '\r\n\0'
for x in range(1, 10):
        r= random.random()
        if r >= 0.2:
                for i in range(1, random.randrange(1,int(9000*r))):
                      buf += chr(random.choice([s for s in range(0,256) if chr(s) not in unwanted_chars]))
headers = headers % (len(buf), buf, endbody)
print headers


