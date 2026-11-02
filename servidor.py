from socket import *

from threading import Thread, active_count

PORTA = 6789

def montar_resposta(message):
    """Recebe a requisição (bytes) e devolve a resposta HTTP completa (bytes)."""
    primeira_linha = message.decode(errors='ignore').split('\r\n')[0]
    partes = primeira_linha.split()            # ['GET', '/HelloWorld.html', 'HTTP/1.1']
    if len(partes) < 2:
        return b'HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n'
    filename = partes[1].lstrip('/')           # 'HelloWorld.html'

    try:
        with open(filename, 'rb') as f:        # binário: funciona também para imagens
            body = f.read()
        status = '200 OK'
    except (FileNotFoundError, IsADirectoryError):
        body = b'<html><body><h1>404 Not Found</h1></body></html>'
        status = '404 Not Found'

    header = (f'HTTP/1.1 {status}\r\n'
              'Content-Type: mimetypes.guess_type(sabrina.png)[0]; charset=utf-8\r\n'
              f'Content-Length: {len(body)}\r\n'
              'Connection: close\r\n'
              '\r\n')
    return header.encode() + body

def handle_client(connectionSocket):
    try:
        message = connectionSocket.recv(1024)
        if message:                            # vazio = cliente fechou sem enviar nada
            connectionSocket.sendall(montar_resposta(message))
    finally:
        connectionSocket.close()

if __name__ == '__main__':                     # só roda ao executar este arquivo diretamente
    serverSocket = socket(AF_INET, SOCK_STREAM)
    serverSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    serverSocket.bind(('', PORTA))
    serverSocket.listen(128)
    print(f'Servidor multithread na porta {PORTA}...')

    while True:
        connectionSocket, addr = serverSocket.accept()
        Thread(target=handle_client, args=(connectionSocket,), daemon=True).start()   # novidade
        print('Conexão de', addr, '| threads ativas:', active_count())