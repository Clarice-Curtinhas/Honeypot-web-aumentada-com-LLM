from socket import *
from threading import Thread, Lock, active_count
from datetime import datetime
import mimetypes
import json
import time
import os
import requests
import pandas as pd

PORTA = 6789

LOGS_DIR = "./logs"
CSV_PATH = os.path.join(LOGS_DIR, "prompts.csv")
COLUNAS = ["timestamp", "IP", "user_agent", "prompt", "latencia_ms", "status_llm", "resposta_engodo"]
csv_lock = Lock()  # Evita conflito de escrita entre threads simultâneas


os.makedirs(LOGS_DIR, exist_ok=True)
if not os.path.exists(CSV_PATH):
    pd.DataFrame(columns=COLUNAS).to_csv(CSV_PATH, index=False)

def salvar_csv(registro: dict) -> None:
    """Acrescenta um registro ao CSV de logs (thread-safe). Campos ausentes ficam vazios."""
    linha = pd.DataFrame([registro]).reindex(columns=COLUNAS)
    with csv_lock:
        linha.to_csv(CSV_PATH, mode="a", header=False, index=False)

def ler_requisicao_completa(conn: socket) -> tuple[str, str]:
    """Lê cabeçalhos HTTP até \\r\\n\\r\\n e depois lê o corpo conforme Content-Length."""
    buffer = b""
    while b"\r\n\r\n" not in buffer:
        chunk = conn.recv(4096)
        if not chunk:
            return "", ""
        buffer += chunk

    header_bytes, body_bytes = buffer.split(b"\r\n\r\n", 1)
    headers_str = header_bytes.decode("utf-8", errors="ignore")

    content_length = 0
    for linha in headers_str.split("\r\n")[1:]:
        if linha.lower().startswith("content-length:"):
            content_length = int(linha.split(":", 1)[1].strip())
            break

    while len(body_bytes) < content_length:
        chunk = conn.recv(4096)
        if not chunk:
            break
        body_bytes += chunk

    return headers_str, body_bytes.decode("utf-8", errors="ignore")

def formatar_resposta_http(status: str, content_type: str, body: bytes) -> bytes:
    header = (
        f"HTTP/1.1 {status}\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("utf-8")
    return header + body

def montar_resposta(headers_str: str, body_str: str, client_ip: str):
    linhas = headers_str.split("\r\n")
    partes = linhas[0].split()
    if len(partes) < 2:
        return formatar_resposta_http("400 Bad Request", "text/plain", b"Bad Request")

    metodo, caminho = partes[0], partes[1]

    # Extrai User-Agent dos cabeçalhos HTTP
    user_agent = "desconhecido"
    for linha in linhas[1:]:
        if linha.lower().startswith("user-agent:"):
            user_agent = linha.split(":", 1)[1].strip()
            break

    # Rota 1: Página inicial (templates/index.html)
    if metodo == "GET" and caminho == "/":
        try:
            with open(os.path.join("templates", "index.html"), "r", encoding="utf-8") as f:
                html = f.read()
            # Substitui tags do Flask por caminhos estáticos diretos
            html = html.replace("{{ url_for('static', filename='style.css') }}", "/static/style.css")
            html = html.replace("{{ url_for('static', filename='script.js') }}", "/static/script.js")
            return formatar_resposta_http("200 OK", "text/html; charset=utf-8", html.encode("utf-8"))
        except FileNotFoundError:
            return formatar_resposta_http("404 Not Found", "text/plain", b"index.html nao encontrado")

    # Rota 2: Arquivos estáticos (CSS, JS, imagens)
    if metodo == "GET" and caminho.startswith("/static/"):
        nome_arquivo = os.path.basename(caminho)
        caminho_local = os.path.join("static", nome_arquivo)
        if os.path.isfile(caminho_local):
            with open(caminho_local, "rb") as f:
                conteudo = f.read()
            mime, _ = mimetypes.guess_type(caminho_local)
            mime = mime or "application/octet-stream"
            return formatar_resposta_http("200 OK", mime, conteudo)
        return formatar_resposta_http("404 Not Found", "text/plain", b"Arquivo estatico nao encontrado")

    # Rota 3: Endpoint da API do Honeypot (POST /api/perguntar)
    if metodo == "POST" and caminho == "/api/perguntar":
        inicio = time.perf_counter()
        try:
            dados = json.loads(body_str) if body_str else {}
        except json.JSONDecodeError:
            dados = {}

        prompt = dados.get("prompt", "")
        data_hora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # resposta_engodo, status_llm = consultar_llm(prompt) (AQUI: DEVE-SE IMPLEMENTAR A FUNÇÃO CONSULTAR PROMPT)
        resposta_engodo = "Processando o seu pedido no modelo..."  # placeholder até consultar_llm existir
        latencia_ms = round((time.perf_counter() - inicio) * 1000, 2)

        # print(f"\n[HONEYPOT SOCKET CAPTURA] {data_hora} | IP: {client_ip} | {status_llm} ({latencia_ms} ms)")
        # print(f"Prompt: {prompt}\nEngodo: {resposta_engodo[:150]}...\n")

        salvar_csv({
            "timestamp": data_hora,
            "IP": client_ip,
            "user_agent": user_agent,
            "prompt": prompt,
            "latencia_ms": latencia_ms,
            # "status_llm": status_llm,
            # "resposta_engodo": resposta_engodo
        })

        payload_json = json.dumps({"status": "success", "resposta": resposta_engodo}, ensure_ascii=False).encode("utf-8")
        return formatar_resposta_http("200 OK", "application/json; charset=utf-8", payload_json)

    return formatar_resposta_http("404 Not Found", "text/html; charset=utf-8", b"<h1>404 Not Found</h1>")

def handle_client(connectionSocket: socket, addr: tuple):
    try:
        headers_str, body_str = ler_requisicao_completa(connectionSocket)
        if headers_str:                            # vazio = cliente fechou sem enviar nada
            connectionSocket.sendall(montar_resposta(headers_str, body_str, addr[0]))
    finally:
        connectionSocket.close()

if __name__ == '__main__':                     # só roda ao executar este arquivo diretamente
    serverSocket = socket(AF_INET, SOCK_STREAM)
    serverSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    serverSocket.bind(('0.0.0.0', PORTA))
    serverSocket.listen(128)
    print(f'Servidor multithread na porta {PORTA}...')

    while True:
        connectionSocket, addr = serverSocket.accept()
        Thread(target=handle_client, args=(connectionSocket, addr), daemon=True).start()   # novidade
        print('Conexão de', addr, '| threads ativas:', active_count())