import socket
from datetime import datetime

HOST = "0.0.0.0"
PORT = 4444

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(5)

print("[C2] Fake C2 Server started on port 4444")

while True:
    client, addr = server.accept()
    print(f"[C2] Beacon received from {addr} at {datetime.now()}")
    client.close()
