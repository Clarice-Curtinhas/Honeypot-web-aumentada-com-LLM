import sys
from socket import *

if len(sys.argv) != 4:
    print('Uso: python3 cliente.py <host> <porta> <arquivo>')
    sys.exit(1)

host, porta, arquivo = sys.argv[1], int(sys.argv[2]), sys.argv[3]

clientSocket = socket(AF_INET, SOCK_STREAM)
clientSocket.connect((host, porta))

request = (f'GET /{arquivo} HTTP/1.1\r\n'
           f'Host: {host}:{porta}\r\n'
           'Connection: close\r\n'
           '\r\n')
clientSocket.sendall(request.encode())

resposta = b''
while True:                       # lê até o servidor fechar a conexão
    dados = clientSocket.recv(4096)
    if not dados:
        break
    resposta += dados

clientSocket.close()
print(resposta.decode(errors='replace'))