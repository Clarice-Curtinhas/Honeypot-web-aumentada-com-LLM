from socket import *
from threading import Thread, Lock, Semaphore, active_count
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import select
import mimetypes
import json
import re
import time
import os
import requests
import psutil
import pandas as pd
import random

#=============================================
# Variáveis globais importantes

HOST = '127.0.0.1' # Endereço de IP do servidor (localhost)
PORTA = 6789 # Porta onde o servidor vai escutar 
MAX_CLIENTS = 20 # Número máximo de clientes

MAX_LLM = 2 # limite de chamadas simultâneas à LLM
llm_executor = ThreadPoolExecutor(max_workers=MAX_LLM) # Criação de um conjunto de threads que faz as requisições de llm separadamente (objetivo: não travar as respostas para outros usuários)
conexoes_semaforo = Semaphore(MAX_CLIENTS) # Cria um semáforo para as threads

LOGS_DIR = "./logs"

#=============================================
# Variaveis da llm
BASE_URL = os.getenv("LLM_BASE_URL", "http://127.0.0.1:4000/v1").rstrip("/")
CA_CERT = os.getenv("LLM_CA_CERT")
MODELO = os.getenv("LLM_MODEL", "qwen7b")
TIMEOUT_S = 10

LOGS_CSV_PATH = os.path.join(LOGS_DIR, "requisicao.csv")
COLUNAS_REQUISICAO = ["timestamp", "IP", "metodo", "path", "user_agent", "prompt", "latencia_llm_ms", "status_llm", "resposta_engodo"]

#=============================================
# PARÂMETRO DE REDE MEDIDOS:
# latencia_ms: latência total para a geração de uma resposta da requisição do atacante
# bytes_requisicao: quantos bytes foram usados na requisição da página pelo atacante
# bytes_resposta: quantos bytes foram usados para gerar a resposta à requisição do atacante
# cpu_pct: porcentagem de uso da cpu do servidor para responder as requisições atuais (mais interessante quando tivermos a llm funcionando)
# ram_mb: quantidade de RAM física utilizada pelo sistema em megabytes
LOGS_REDE_PATH = os.path.join(LOGS_DIR, "redes.csv")
COLUNAS_REDE = ["src_IP", "latencia_ms", "bytes_requisicao", "bytes_resposta", "cpu_pct", "ram_mb", "qnt_threads", "status_conexao"]

# vetor que armazena possiveis paginas alvo
pages_wordpress = ["wp-activate.php", "wp-config.php", "wp-cron.php", "wp-login.php", "wp-mail.php", "wp-settings.php"]

# vetor que armazena os arquivos html que servem como respostas aos ataques staticos previstos
fake_pages = ["activate.html", "config.html", "cron.html", "login.html", "mail.html", "settings.html"]
# ate entao não usado -^

csv_lock = Lock()  # Evita conflito de escrita entre threads simultâneas


os.makedirs(LOGS_DIR, exist_ok=True)
if not os.path.exists(LOGS_CSV_PATH):
    pd.DataFrame(columns=COLUNAS_REQUISICAO).to_csv(LOGS_CSV_PATH, index=False)
if not os.path.exists(LOGS_REDE_PATH):
    pd.DataFrame(columns=COLUNAS_REDE).to_csv(LOGS_REDE_PATH, index=False)

def salvar_csv(registro: dict, COLUNAS, CSV_PATH) -> None:
    """Acrescenta um registro ao CSV de logs (thread-safe). Campos ausentes ficam vazios."""
    linha = pd.DataFrame([registro]).reindex(columns=COLUNAS)
    with csv_lock:
        linha.to_csv(CSV_PATH, mode="a", header=False, index=False)

def ler_requisicao_completa(conn: socket, timeout_seg: float = 5.0) -> tuple[str, str, str]:
    """Lê cabeçalhos HTTP até \\r\\n\\r\\n e depois lê o corpo conforme Content-Length."""
    conn.settimeout(timeout_seg)
    buffer = b""
    try:
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

        return headers_str, body_bytes.decode("utf-8", errors="ignore"), "ok"
    
    except TimeoutError:
        return "", "", "timeout_leitura"

    except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
        return "", "", "conexao_resetada"
    except OSError as erro:
        return "", "", f"erro_socket:{erro.errno}"

def formatar_resposta_http(status: str, content_type: str, body: bytes) -> bytes:
    header = (
        f"HTTP/1.1 {status}\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("utf-8")
    return header + body

def consultar_llm(prompt: str) -> tuple[str, str]:
    """Envia o prompt à LLM e devolve (resposta, status_llm)."""
    api_key = os.getenv("LLM_API_KEY", "sk-...")
    # if not api_key:
    #     return "", "erro: LLM_API_KEY nao definida"

    try:
        r = requests.post(
            f"{BASE_URL}/chat/completions",
            headers={"Authorization": f"Bearer {api_key}"},
            json={
                "model": MODELO,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 400,
                "temperature": 0.3,
            },
            verify=CA_CERT or True,
            timeout=TIMEOUT_S,
        )
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"].strip(), "ok"
    except requests.exceptions.SSLError:
        return "", "erro: certificado (defina LLM_CA_CERT)"
    except requests.exceptions.ConnectionError:
        return "", "erro: LLM inacessivel"
    except requests.exceptions.Timeout:
        return "", "erro: timeout"
    except requests.exceptions.HTTPError as e:
        return "", f"erro: HTTP {e.response.status_code} - {e.response.text[:200]}"
    except (ValueError, KeyError, IndexError):
        return "", "erro: resposta inesperada"

def escreve_csv_rede(client_ip, inicio, headers_str, body_str, html, qnt_threads, status_con):

    latencia_ms = round((time.perf_counter() - inicio) * 1000, 2)
    cpu_pct = psutil.cpu_percent(interval=None)
    ram_mb = round(psutil.virtual_memory().used / (1024 * 1024), 1)

    bytes_requisicao = len(headers_str) + len(body_str)
    bytes_resp = len(html)
    
    salvar_csv({
        "src_IP": client_ip,
        "latencia_ms": latencia_ms,
        "bytes_requisicao": bytes_requisicao,
        "bytes_resposta": bytes_resp,
        "cpu_pct": cpu_pct,
        "ram_mb": ram_mb,
        "qnt_threads": qnt_threads,
        "status_conexao": status_con,
    }, COLUNAS_REDE, LOGS_REDE_PATH)

def escreve_csv_req(data_hora, client_ip, metodo, path, user_agent, prompt, latencia_llm_ms, status_llm, resposta_engodo):
    
    salvar_csv({
        "timestamp": data_hora,
        "IP": client_ip,
        "metodo": metodo,
        "path": path,
        "user_agent": user_agent,
        "prompt": prompt,
        "latencia_llm_ms": latencia_llm_ms,
        "status_llm": status_llm,
        "resposta_engodo": resposta_engodo
    }, COLUNAS_REQUISICAO, LOGS_CSV_PATH)

def renderizar_template(nome_template: str) -> str:
    """Lê um template e embute style.css / script.js diretamente no HTML,
    para que o navegador não precise (nem possa) buscá-los em /static/."""
    with open(os.path.join("templates", nome_template), "r", encoding="utf-8") as f:
        html = f.read()

    # Substitui <link ... style.css ...> por <style>conteúdo</style>
    if "filename='style.css'" in html:
        with open(os.path.join("static", "style.css"), "r", encoding="utf-8") as f:
            css = f.read()
        html = re.sub(
            r"<link[^>]*url_for\('static', filename='style\.css'\)[^>]*>",
            lambda _: f"<style>\n{css}\n</style>",
            html,
        )

    # Substitui <script src="... script.js ..."></script> por <script>conteúdo</script>
    if "filename='script.js'" in html:
        with open(os.path.join("static", "script.js"), "r", encoding="utf-8") as f:
            js = f.read()
        html = re.sub(
            r"<script[^>]*url_for\('static', filename='script\.js'\)[^>]*>\s*</script>",
            lambda _: f"<script>\n{js}\n</script>",
            html,
        )

    return html

def processa_llm_thread(prompt: str) -> tuple[str, float, str]:
    inicio_llm = time.perf_counter()
    resposta_engodo, status_llm = consultar_llm(prompt) # (AQUI: DEVE-SE IMPLEMENTAR A FUNÇÃO CONSULTAR PROMPT)
    # resposta_engodo = "Processando o seu pedido no modelo..."   placeholder até consultar_llm existir
    latencia_llm_ms = round((time.perf_counter() - inicio_llm) * 1000, 2)
    return resposta_engodo, latencia_llm_ms, status_llm

def montar_resposta(headers_str: str, body_str: str, client_ip: str, qnt_threads: int, status_con: str):
    
    psutil.cpu_percent(interval=None)
    inicio = time.perf_counter()

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
            # CSS e JS são embutidos no HTML (não existe rota /static/)
            html = renderizar_template("index.html")

            data_hora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            escreve_csv_req(data_hora, client_ip, metodo, caminho, user_agent, None, None, None, None)
            escreve_csv_rede(client_ip, inicio, headers_str, body_str, html.encode("utf-8"), qnt_threads, status_con)
            
            return formatar_resposta_http("200 OK", "text/html; charset=utf-8", html.encode("utf-8"))
        except FileNotFoundError:
            return formatar_resposta_http("404 Not Found", "text/plain", b"index.html nao encontrado")

    # Rota 2: Página estatica (templates)
    if metodo == "GET" and (caminho[1:] in pages_wordpress):
            page_name = caminho[1:].split("-")[1].split(".")[0]
            try:
                # CSS e JS são embutidos no HTML (não existe rota /static/)
                html = renderizar_template(page_name + ".html")

                data_hora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                escreve_csv_req(data_hora, client_ip, metodo, caminho, user_agent, None, None, None, None)
                escreve_csv_rede(client_ip, inicio, headers_str, body_str, html.encode("utf-8"), qnt_threads, status_con)

                return formatar_resposta_http("200 OK", "text/html; charset=utf-8", html.encode("utf-8"))
            except FileNotFoundError:
                return formatar_resposta_http("404 Not Found", "text/plain", f"{page_name}.html nao encontrado".encode("utf-8"))

    # Rota 3: Endpoint da API do Honeypot (POST /api/perguntar)
    if metodo == "POST" and caminho == "/api/perguntar":
        try:
            dados = json.loads(body_str) if body_str else {}
        except json.JSONDecodeError:
            dados = {}

        prompt = dados.get("prompt", "")
        data_hora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        with conexoes_semaforo:
            analise_llm = llm_executor.submit(processa_llm_thread, prompt)
            resposta_engodo, latencia_llm_ms, status_llm = analise_llm.result(timeout=TIMEOUT_S)

        print(f"\n[HONEYPOT SOCKET CAPTURA] {data_hora} | IP: {client_ip} | {status_llm} ({latencia_llm_ms} ms)")
        print(f"Prompt: {prompt}\nEngodo: {resposta_engodo[:150]}...\n")

        
        if status_llm != "ok":
            # O fetch() do script.js espera JSON; então indicamos para onde redirecionar
            # e o próprio navegador faz o GET /wp-login.php (que serve o login.html)
        
            payload_json = json.dumps({"status": "redirect", "url": f"/{pages_wordpress[random.randint(0 , 5)]}"}).encode("utf-8")

            escreve_csv_req(data_hora, client_ip, metodo, caminho, user_agent, prompt, latencia_llm_ms, status_llm, resposta_engodo)
            escreve_csv_rede(client_ip, inicio, headers_str, body_str, payload_json, qnt_threads, status_con)

            return formatar_resposta_http("200 OK", "application/json; charset=utf-8", payload_json)

        # Extrai só o documento HTML: do <!DOCTYPE até o último </html>, descartando
        # qualquer texto ou cerca de markdown que a LLM tenha colocado antes ou depois
        
        documento = re.search(r"<!DOCTYPE.*</html\s*>", resposta_engodo, re.S | re.I)
        if documento:
            resposta_engodo = documento.group(0)

        payload_json = json.dumps({"status": "success", "resposta": resposta_engodo}, ensure_ascii=False).encode("utf-8")
        escreve_csv_req(data_hora, client_ip, metodo, caminho, user_agent, prompt, latencia_llm_ms, status_llm, resposta_engodo)
        escreve_csv_rede(client_ip, inicio, headers_str, body_str, payload_json, qnt_threads, status_con)

        return formatar_resposta_http("200 OK", "application/json; charset=utf-8", payload_json)

    return formatar_resposta_http("404 Not Found", "text/html; charset=utf-8", b"<h1>404 Not Found</h1>")

def handle_client(connectionSocket: socket, addr: tuple, lock_socket, clients):
    inicio = time.perf_counter()
    ip_cliente = addr[0]
    status_conn = "ok"
    headers_str, body_str = "", ""

    try:
        headers_str, body_str, status_conn = ler_requisicao_completa(connectionSocket, timeout_seg=10.0)

        if status_conn == "ok" and headers_str:                # vazio = cliente fechou sem enviar nada
            resposta = montar_resposta(headers_str, body_str, addr[0], active_count(), status_conn)
            connectionSocket.settimeout(10.0)
            connectionSocket.sendall(resposta)

    except TimeoutError:
        status_conn = "timeout"

    except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
        status_conn = "erro_de_conexao"

    except OSError as e:
        status_conn = f"erro_envio:{e.errno}"

    finally:
        if status_conn != "ok":
            escreve_csv_rede(ip_cliente, inicio, headers_str, body_str, b"", active_count(), status_conn)

        with lock_socket:
            clients.discard(connectionSocket)

        try:
            connectionSocket.close()

        except OSError:
            pass

# Função principal para iniciar o servidor
def start_server():
    serverSocket = socket(AF_INET, SOCK_STREAM)
    serverSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    serverSocket.setblocking(0)
    serverSocket.bind((HOST, PORTA))
    serverSocket.listen(128)
    serverSocket.settimeout(1.0)

    lock_socket = Lock()

    # Lista de sockets que o select deve monitorar
    sockets_list = [serverSocket]

    clients = set()

    print(f'Servidor iniciado e escutado em {HOST}: {PORTA}...')

    while True: 
        try:
            connectionSocket, addr = serverSocket.accept()
        except TimeoutError:
            continue
        except OSError:
            break

        with lock_socket:
            if len(clients) >= MAX_CLIENTS:
                try:
                    connectionSocket.sendall(b'Servidor cheio. Tente mais tarde.')
                except OSError:
                    pass
                connectionSocket.close()
                continue

            clients.add(connectionSocket)
                
            print('Conexão de', addr, '| threads ativas:', active_count())

            Thread(target=handle_client, args=(connectionSocket, addr, lock_socket, clients), daemon=True).start()
    
if __name__ == '__main__':                     # só roda ao executar este arquivo diretamente

    start_server()