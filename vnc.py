import os
import sys

# Usage
# python vnc.py ip
# key files and start script will be generated under ./vnc/
# modify the start script with :2 and -xstartup

address = sys.argv[1]

os.mkdir("vnc")
os.system(
    f"cd vnc && openssl req -x509 -newkey rsa -days 365 -nodes -keyout vnc-server-private.pem -out vnc-server.pem -subj '/CN={address}' -addext \"subjectAltName=IP:{address}\""
)
with open("vnc/vnc-start.sh", "w") as f:
    f.write(
        "vncserver -localhost no -SecurityTypes X509Vnc -X509Key vnc-server-private.pem -X509Cert vnc-server.pem"
    )
