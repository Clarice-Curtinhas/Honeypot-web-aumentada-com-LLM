"""
Honeypot web aumentado com LLM.

Servidor HTTP implementado "na mão" sobre sockets TCP. Ele simula um site
(com páginas falsas de WordPress) para atrair atacantes e:
  - serve páginas estáticas de engodo (index e páginas wp-*.php);
  - expõe um endpoint POST /api/perguntar que repassa o prompt do atacante
    a uma LLM, devolvendo uma resposta "engodo" gerada dinamicamente;
  - registra tudo em dois CSVs: um com dados da requisição (logs/requisicao.csv)
    e outro com métricas de rede/sistema (logs/redes.csv).

Cada cliente é atendido em uma thread própria; as chamadas à LLM rodam em um
pool de threads separado para não travar o atendimento dos demais clientes.
"""

from socket import *                                   # API de sockets (socket, AF_INET, SOCK_STREAM, ...)
from threading import Thread, Lock, Semaphore, active_count
from concurrent.futures import ThreadPoolExecutor      # Pool de threads para as chamadas à LLM
from datetime import datetime
import select                                          # (importado, mas não utilizado atualmente)
import mimetypes                                       # (importado, mas não utilizado atualmente)
import json
import re
import time
import os
import requests                                        # Cliente HTTP usado para falar com a API da LLM
import psutil                                          # Métricas de CPU/RAM do sistema
import pandas as pd                                    # Escrita dos logs em CSV
import random

#=============================================
# Variáveis globais importantes

HOST = '127.0.0.1' # Endereço de IP do servidor (localhost)
PORTA = 6789 # Porta onde o servidor vai escutar
MAX_CLIENTS = 20 # Número máximo de clientes

MAX_LLM = 2 # limite de chamadas simultâneas à LLM
llm_executor = ThreadPoolExecutor(max_workers=MAX_LLM) # Criação de um conjunto de threads que faz as requisições de llm separadamente (objetivo: não travar as respostas para outros usuários)
conexoes_semaforo = Semaphore(MAX_CLIENTS) # Cria um semáforo para as threads

LOGS_DIR = "./logs" # Diretório onde os CSVs de log são gravados

#=============================================
# [SEGURANÇA] Limites de leitura da requisição HTTP
# Sem esses limites, um atacante pode esgotar a memória (cabeçalhos/corpo gigantes)
# ou prender uma thread indefinidamente enviando dados muito devagar (Slowloris).
MAX_HEADER_BYTES = 8 * 1024     # 8 KB: tamanho máximo dos cabeçalhos (valor próximo ao padrão do Apache/Nginx)
MAX_BODY_BYTES = 64 * 1024      # 64 KB: tamanho máximo do corpo (suficiente para um prompt)
PRAZO_REQUISICAO_S = 10.0       # Tempo TOTAL (s) para o cliente enviar a requisição inteira (anti-Slowloris)

# [SEGURANÇA] Traduz cada status de erro de leitura na resposta HTTP padrão correspondente.
# Responder com um código HTTP real (em vez de só fechar a conexão) deixa o honeypot
# com cara de servidor de verdade para o atacante.
RESPOSTAS_ERRO_LEITURA = {
    "headers_grandes":         "431 Request Header Fields Too Large",
    "corpo_grande":            "413 Content Too Large",
    "content_length_invalido": "400 Bad Request",
    "timeout_leitura":         "408 Request Timeout",
}

#=============================================
# Variaveis da llm (podem ser sobrescritas por variáveis de ambiente)
BASE_URL = os.getenv("LLM_BASE_URL", "http://127.0.0.1:4000/v1").rstrip("/") # URL base da API compatível com OpenAI
CA_CERT = os.getenv("LLM_CA_CERT")              # Certificado da CA (opcional) para conexões HTTPS
MODELO = os.getenv("LLM_MODEL", "qwen7b")       # Nome do modelo a ser usado
TIMEOUT_S = 10                                  # Tempo máximo (s) de espera pela resposta da LLM

# Log de requisições: o que o atacante pediu e o que a LLM respondeu
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


# Garante que a pasta de logs exista e cria os CSVs (só com cabeçalho) na primeira execução
os.makedirs(LOGS_DIR, exist_ok=True)
if not os.path.exists(LOGS_CSV_PATH):
    pd.DataFrame(columns=COLUNAS_REQUISICAO).to_csv(LOGS_CSV_PATH, index=False)
if not os.path.exists(LOGS_REDE_PATH):
    pd.DataFrame(columns=COLUNAS_REDE).to_csv(LOGS_REDE_PATH, index=False)

def salvar_csv(registro: dict, COLUNAS, CSV_PATH) -> None:
    """Acrescenta um registro ao CSV de logs (thread-safe). Campos ausentes ficam vazios."""
    # reindex garante a mesma ordem de colunas do cabeçalho (e preenche faltantes com vazio)
    linha = pd.DataFrame([registro]).reindex(columns=COLUNAS)
    with csv_lock:  # só uma thread escreve no arquivo por vez
        linha.to_csv(CSV_PATH, mode="a", header=False, index=False)

def ler_requisicao_completa(conn: socket, prazo_total: float = PRAZO_REQUISICAO_S) -> tuple[str, str, str]:
    """Lê cabeçalhos HTTP até \\r\\n\\r\\n e depois lê o corpo conforme Content-Length.

    Retorna (headers, corpo, status_leitura), onde status_leitura é "ok" ou
    uma descrição do erro ocorrido.

    [SEGURANÇA] A leitura é protegida contra:
      - cabeçalhos gigantes (limite MAX_HEADER_BYTES -> status "headers_grandes");
      - Content-Length inválido ou negativo ("content_length_invalido");
      - corpo gigante (limite MAX_BODY_BYTES -> "corpo_grande");
      - Slowloris: o cliente tem um prazo TOTAL (prazo_total) para enviar a
        requisição inteira, e não um timeout que reinicia a cada recv.
    """
    # [SEGURANÇA][Anti-Slowloris] Instante-limite para a requisição inteira.
    # Antes, o timeout era aplicado a cada recv: um atacante que enviasse 1 byte
    # a cada 9 s nunca estourava o timeout de 10 s e prendia a thread para sempre.
    # time.monotonic() é usado porque não muda se o relógio do sistema for ajustado.
    limite = time.monotonic() + prazo_total
    buffer = b""

    def receber() -> bytes:
        """[SEGURANÇA][Anti-Slowloris] recv que só pode esperar o tempo que ainda resta do prazo total."""
        restante = limite - time.monotonic()
        if restante <= 0:
            raise TimeoutError          # prazo total esgotado -> tratado como "timeout_leitura"
        conn.settimeout(restante)       # cada recv espera no máximo o que sobrou do prazo
        return conn.recv(4096)

    try:
        # 1) Lê do socket até encontrar o fim dos cabeçalhos (linha em branco)
        while b"\r\n\r\n" not in buffer:
            # [SEGURANÇA] Limite de tamanho dos cabeçalhos: sem ele, o buffer crescia
            # sem parar e um atacante podia esgotar a RAM do servidor.
            if len(buffer) > MAX_HEADER_BYTES:
                return "", "", "headers_grandes"
            chunk = receber()
            if not chunk:
                # [CORREÇÃO] Antes era `return "", ""` (2 valores), mas quem chama espera 3.
                # Isso gerava ValueError e matava a thread sem registrar a conexão no log.
                # Diferencia quem conectou e não mandou nada (ex.: port scan) de quem parou no meio.
                return "", "", ("fechou_antes" if buffer else "conexao_vazia")
            buffer += chunk

        # Separa cabeçalhos do início do corpo (que pode já ter vindo junto)
        header_bytes, body_bytes = buffer.split(b"\r\n\r\n", 1)

        # [SEGURANÇA] Confere de novo o tamanho: o último recv pode ter trazido o fim dos
        # cabeçalhos junto com bytes que ultrapassam o limite.
        if len(header_bytes) > MAX_HEADER_BYTES:
            return "", "", "headers_grandes"

        headers_str = header_bytes.decode("utf-8", errors="ignore")

        # 2) Procura o Content-Length para saber quantos bytes de corpo esperar
        content_length = 0
        for linha in headers_str.split("\r\n")[1:]:   # [1:] pula a linha de requisição (GET / HTTP/1.1)
            if linha.lower().startswith("content-length:"):
                valor = linha.split(":", 1)[1].strip()
                # [SEGURANÇA] Valida o Content-Length antes de converter. Antes, int("abc")
                # lançava ValueError não tratado (a thread morria) e valores negativos eram aceitos.
                # isdigit() rejeita de uma vez "abc", "-5", "1.5" e "" (vazio).
                if not valor.isdigit():
                    return headers_str, "", "content_length_invalido"
                content_length = int(valor)
                break

        # [SEGURANÇA] Limite de tamanho do corpo: impede que um Content-Length enorme
        # (ex.: 99999999999) faça o servidor esperar/acumular dados indefinidamente.
        if content_length > MAX_BODY_BYTES:
            return headers_str, "", "corpo_grande"

        # 3) Continua lendo até receber o corpo completo
        while len(body_bytes) < content_length:
            chunk = receber()           # [SEGURANÇA] também respeita o prazo total (anti-Slowloris)
            if not chunk:
                # [CORREÇÃO] Antes o laço só parava e a requisição seguia como "ok" com o corpo
                # pela metade; agora o corpo incompleto é sinalizado e registrado no log.
                return headers_str, "", "corpo_incompleto"
            body_bytes += chunk

        # [SEGURANÇA] Descarta bytes além do Content-Length declarado
        return headers_str, body_bytes[:content_length].decode("utf-8", errors="ignore"), "ok"

    except TimeoutError:
        # Cliente conectou mas não enviou dados a tempo
        return "", "", "timeout_leitura"

    except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
        # Cliente derrubou a conexão no meio da leitura
        return "", "", "conexao_resetada"
    except OSError as erro:
        # Qualquer outro erro de socket
        return "", "", f"erro_socket:{erro.errno}"

def formatar_resposta_http(status: str, content_type: str, body: bytes) -> bytes:
    """Monta uma resposta HTTP/1.1 completa (linha de status + cabeçalhos + corpo) em bytes."""
    header = (
        f"HTTP/1.1 {status}\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"        # sem keep-alive: uma requisição por conexão
    ).encode("utf-8")
    return header + body

def consultar_llm(prompt: str) -> tuple[str, str]:
    """Envia o prompt à LLM e devolve (resposta, status_llm)."""
    api_key = os.getenv("LLM_API_KEY", "sk-...")
    # if not api_key:
    #     return "", "erro: LLM_API_KEY nao definida"

    try:
        # Requisição no formato da API de chat completions (compatível com OpenAI)
        r = requests.post(
            f"{BASE_URL}/chat/completions",
            headers={"Authorization": f"Bearer {api_key}"},
            json={
                "model": MODELO,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 400,      # limita o tamanho da resposta
                "temperature": 0.3,     # baixa aleatoriedade -> respostas mais consistentes
            },
            verify=CA_CERT or True,     # usa o certificado customizado, se houver
            timeout=TIMEOUT_S,
        )
        r.raise_for_status()            # lança HTTPError para status 4xx/5xx
        return r.json()["choices"][0]["message"]["content"].strip(), "ok"
    # Cada falha vira um status descritivo, que é registrado no log
    except requests.exceptions.SSLError:
        return "", "erro: certificado (defina LLM_CA_CERT)"
    except requests.exceptions.ConnectionError:
        return "", "erro: LLM inacessivel"
    except requests.exceptions.Timeout:
        return "", "erro: timeout"
    except requests.exceptions.HTTPError as e:
        return "", f"erro: HTTP {e.response.status_code} - {e.response.text[:200]}"
    except (ValueError, KeyError, IndexError):
        # JSON inválido ou sem os campos esperados
        return "", "erro: resposta inesperada"

def escreve_csv_rede(client_ip, inicio, headers_str, body_str, html, qnt_threads, status_con):
    """Calcula as métricas de rede/sistema da requisição e grava em logs/redes.csv.

    `inicio` é o instante (perf_counter) em que o atendimento começou;
    `html` são os bytes da resposta enviada ao cliente.
    """

    latencia_ms = round((time.perf_counter() - inicio) * 1000, 2)       # tempo total de atendimento
    cpu_pct = psutil.cpu_percent(interval=None)                         # % de CPU desde a última chamada
    ram_mb = round(psutil.virtual_memory().used / (1024 * 1024), 1)     # RAM usada pelo sistema (MB)

    # Obs.: len() de str conta caracteres; é uma aproximação dos bytes recebidos
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
    """Grava em logs/requisicao.csv os dados da requisição do atacante (e da LLM, se houver)."""

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
        # lambda evita que caracteres especiais do CSS (ex.: "\") sejam interpretados pelo re.sub
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
    """Executada no pool `llm_executor`: consulta a LLM e mede a latência da chamada.

    Retorna (resposta_engodo, latencia_llm_ms, status_llm).
    """
    inicio_llm = time.perf_counter()
    resposta_engodo, status_llm = consultar_llm(prompt) # (AQUI: DEVE-SE IMPLEMENTAR A FUNÇÃO CONSULTAR PROMPT)
    # resposta_engodo = "Processando o seu pedido no modelo..."   placeholder até consultar_llm existir
    latencia_llm_ms = round((time.perf_counter() - inicio_llm) * 1000, 2)
    return resposta_engodo, latencia_llm_ms, status_llm

def montar_resposta(headers_str: str, body_str: str, client_ip: str, qnt_threads: int, status_con: str):
    """Roteia a requisição HTTP, registra os logs e devolve a resposta em bytes."""

    # A primeira chamada com interval=None só "zera" a medição de CPU;
    # a leitura real acontece depois, em escreve_csv_rede
    psutil.cpu_percent(interval=None)
    inicio = time.perf_counter()

    # Linha de requisição: "METODO CAMINHO HTTP/1.1"
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

            # Acesso sem prompt: campos da LLM ficam vazios no log
            escreve_csv_req(data_hora, client_ip, metodo, caminho, user_agent, None, None, None, None)
            escreve_csv_rede(client_ip, inicio, headers_str, body_str, html.encode("utf-8"), qnt_threads, status_con)

            return formatar_resposta_http("200 OK", "text/html; charset=utf-8", html.encode("utf-8"))
        except FileNotFoundError:
            return formatar_resposta_http("404 Not Found", "text/plain", b"index.html nao encontrado")

    # Rota 2: Página estatica (templates)
    # Ex.: GET /wp-login.php -> serve templates/login.html
    if metodo == "GET" and (caminho[1:] in pages_wordpress):
            # "wp-login.php" -> split("-")[1] = "login.php" -> split(".")[0] = "login"
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
        # Corpo esperado: {"prompt": "..."}; JSON inválido vira dicionário vazio
        try:
            dados = json.loads(body_str) if body_str else {}
        except json.JSONDecodeError:
            dados = {}

        prompt = dados.get("prompt", "")
        data_hora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Envia a consulta ao pool de threads da LLM (no máx. MAX_LLM simultâneas)
        # e espera o resultado por até TIMEOUT_S segundos
        with conexoes_semaforo:
            analise_llm = llm_executor.submit(processa_llm_thread, prompt)
            resposta_engodo, latencia_llm_ms, status_llm = analise_llm.result(timeout=TIMEOUT_S)

        print(f"\n[HONEYPOT SOCKET CAPTURA] {data_hora} | IP: {client_ip} | {status_llm} ({latencia_llm_ms} ms)")
        print(f"Prompt: {prompt}\nEngodo: {resposta_engodo[:150]}...\n")


        # Fallback: se a LLM falhou, manda o navegador para uma página wp-* estática aleatória
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

        # Sucesso: devolve o HTML gerado pela LLM dentro de um JSON para o front-end renderizar
        payload_json = json.dumps({"status": "success", "resposta": resposta_engodo}, ensure_ascii=False).encode("utf-8")
        escreve_csv_req(data_hora, client_ip, metodo, caminho, user_agent, prompt, latencia_llm_ms, status_llm, resposta_engodo)
        escreve_csv_rede(client_ip, inicio, headers_str, body_str, payload_json, qnt_threads, status_con)

        return formatar_resposta_http("200 OK", "application/json; charset=utf-8", payload_json)

    # Qualquer outra rota/método: 404
    return formatar_resposta_http("404 Not Found", "text/html; charset=utf-8", b"<h1>404 Not Found</h1>")

def handle_client(connectionSocket: socket, addr: tuple, lock_socket, clients):
    """Atende um único cliente (roda em uma thread própria): lê, responde e fecha a conexão."""
    inicio = time.perf_counter()
    ip_cliente = addr[0]
    status_conn = "ok"
    headers_str, body_str = "", ""

    try:
        # [SEGURANÇA] O prazo agora é TOTAL para a requisição inteira (anti-Slowloris)
        headers_str, body_str, status_conn = ler_requisicao_completa(connectionSocket, prazo_total=PRAZO_REQUISICAO_S)

        if status_conn == "ok" and headers_str:                # vazio = cliente fechou sem enviar nada
            resposta = montar_resposta(headers_str, body_str, addr[0], active_count(), status_conn)
            connectionSocket.settimeout(10.0)
            connectionSocket.sendall(resposta)                 # envia toda a resposta ao cliente

        elif status_conn in RESPOSTAS_ERRO_LEITURA:
            # [SEGURANÇA] Requisição rejeitada na leitura (cabeçalho/corpo grande demais,
            # Content-Length inválido ou prazo esgotado): responde com o código HTTP padrão
            # em vez de só derrubar a conexão, como faria um servidor web real.
            # Timeout curto no envio para que um cliente lento não prenda a thread aqui também.
            connectionSocket.settimeout(2.0)
            connectionSocket.sendall(
                formatar_resposta_http(RESPOSTAS_ERRO_LEITURA[status_conn], "text/plain", b"")
            )

    except TimeoutError:
        status_conn = "timeout"

    except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
        status_conn = "erro_de_conexao"

    except OSError as e:
        status_conn = f"erro_envio:{e.errno}"

    finally:
        # Requisições bem-sucedidas já foram logadas em montar_resposta;
        # aqui registramos apenas as conexões que falharam
        if status_conn != "ok":
            escreve_csv_rede(ip_cliente, inicio, headers_str, body_str, b"", active_count(), status_conn)

        # Libera a "vaga" deste cliente no conjunto de conexões ativas
        with lock_socket:
            clients.discard(connectionSocket)

        try:
            connectionSocket.close()

        except OSError:
            pass

# Função principal para iniciar o servidor
def start_server():
    """Cria o socket de escuta e aceita conexões, disparando uma thread por cliente."""
    serverSocket = socket(AF_INET, SOCK_STREAM)               # socket TCP/IPv4
    serverSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)      # permite reutilizar a porta logo após reiniciar
    serverSocket.setblocking(0)
    serverSocket.bind((HOST, PORTA))
    serverSocket.listen(128)                                  # fila de conexões pendentes
    serverSocket.settimeout(1.0)  # accept() acorda a cada 1s (permite interromper o loop com Ctrl+C)

    lock_socket = Lock()   # protege o conjunto `clients`, acessado por várias threads

    # Lista de sockets que o select deve monitorar
    sockets_list = [serverSocket]   # (não utilizada atualmente)

    clients = set()   # sockets dos clientes sendo atendidos no momento

    print(f'Servidor iniciado e escutado em {HOST}: {PORTA}...')

    while True:
        try:
            connectionSocket, addr = serverSocket.accept()
        except TimeoutError:
            continue    # nenhuma conexão nesse intervalo; tenta de novo
        except OSError:
            break       # socket do servidor fechado/erro grave: encerra o loop

        with lock_socket:
            # Limite de clientes simultâneos atingido: recusa a nova conexão
            if len(clients) >= MAX_CLIENTS:
                try:
                    connectionSocket.sendall(b'Servidor cheio. Tente mais tarde.')
                except OSError:
                    pass
                connectionSocket.close()
                continue

            clients.add(connectionSocket)

            print('Conexão de', addr, '| threads ativas:', active_count())

            # Uma thread por cliente; daemon=True faz ela morrer junto com o programa principal
            Thread(target=handle_client, args=(connectionSocket, addr, lock_socket, clients), daemon=True).start()

if __name__ == '__main__':                     # só roda ao executar este arquivo diretamente

    start_server()
