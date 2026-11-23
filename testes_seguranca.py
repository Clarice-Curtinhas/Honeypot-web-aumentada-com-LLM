#!/usr/bin/env python3
"""
Testes da trilha de segurança (Fase 1): dispara ataques contra a leitura da
requisição HTTP do honeypot e confere se cada um foi bloqueado. Só Python padrão.

Uso:
    python3 testes_seguranca.py HOST PORTA [--sem-slowloris]
Ex.: python3 testes_seguranca.py 127.0.0.1 6789

Ataques testados:
  1a) cabeçalho gigante              -> esperado 431
  1b) Content-Length inválido/negativo -> esperado 400
  1b) Content-Length gigante         -> esperado 413
  1c) cliente fecha no meio / conexão vazia -> servidor continua de pé
  2)  Slowloris (1 byte a cada 3 s)  -> esperado 408 em ~10 s (PRAZO_REQUISICAO_S)

Rodando contra a versão antiga do servidor, os testes devem FALHAR — isso serve
para a comparação "sem proteção × com proteção" no relatório.
"""
import argparse, socket, time

# Prazo total que o servidor dá para o cliente enviar a requisição inteira.
# Usado só para avaliar o teste de Slowloris (se o corte aconteceu "no prazo").
PRAZO_SERVIDOR_S = 10.0   # deve bater com PRAZO_REQUISICAO_S do servidor.py


def enviar_bruto(host, porta, dados: bytes, timeout=15.0) -> str:
    """Envia bytes crus e devolve a linha de status da resposta (ou o erro ocorrido).

    Usamos socket puro (e não requests/http.client) porque essas bibliotecas
    "consertam" a requisição sozinhas: calculam o Content-Length certo e não
    deixam enviar cabeçalhos malformados. Para atacar, precisamos mandar
    exatamente os bytes que queremos.
    """
    s = socket.create_connection((host, porta), timeout=timeout)
    try:
        s.sendall(dados)                 # envia a requisição maliciosa de uma vez
        resposta = s.recv(4096)          # basta o começo da resposta para ler a linha de status
        if not resposta:
            # recv vazio = servidor fechou a conexão sem responder nada
            # (comportamento da versão antiga quando a thread morria)
            return "conexão fechada sem resposta"
        # Só a primeira linha interessa, ex.: "HTTP/1.1 431 Request Header Fields Too Large"
        return resposta.split(b"\r\n", 1)[0].decode("utf-8", "replace")
    except socket.timeout:
        # Servidor ficou esperando mais dados e não respondeu dentro do timeout
        return f"sem resposta após {timeout:.0f}s"
    except OSError as e:
        # Conexão resetada, recusada etc.
        return f"erro: {e}"
    finally:
        s.close()


def checar(nome, obtido, esperado) -> bool:
    """Compara a resposta obtida com o código HTTP esperado, imprime o resultado e devolve True/False."""
    ok = esperado in obtido              # ex.: "431" in "HTTP/1.1 431 Request Header ..."
    print(f"[{'PASSOU' if ok else 'FALHOU'}] {nome:42s} esperado '{esperado}' | obtido '{obtido}'")
    return ok


def servidor_responde(host, porta) -> bool:
    """GET normal: garante que o servidor continua funcionando depois dos ataques."""
    return "200" in enviar_bruto(host, porta, b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")


def teste_slowloris(host, porta, intervalo=3.0) -> bool:
    """Envia 1 byte a cada `intervalo` segundos e mede quando o servidor corta a conexão.

    Como o intervalo (3 s) é menor que o timeout por recv da versão antiga (10 s),
    a versão antiga nunca corta a conexão. A versão nova deve cortar quando o
    prazo TOTAL (10 s) acabar, respondendo 408.
    """
    print(f"       (Slowloris: enviando 1 byte a cada {intervalo:.0f}s, aguarde ~{PRAZO_SERVIDOR_S:.0f}s...)")
    s = socket.create_connection((host, porta))
    inicio = time.time()
    status = "conexão continuou aberta"   # valor padrão caso o servidor nunca corte
    try:
        # Cabeçalhos que nunca terminam: falta o "\r\n\r\n" final,
        # então o servidor fica esperando o resto da requisição.
        for byte in b"GET / HTTP/1.1\r\nHost: " + b"x" * 40:
            s.sendall(bytes([byte]))                           # manda um único byte
            # Em vez de time.sleep(intervalo), espera a resposta com timeout = intervalo:
            # assim "dorme" o mesmo tempo, mas percebe na hora se o servidor respondeu/cortou.
            s.settimeout(intervalo)
            try:
                resposta = s.recv(4096)
                # Chegou algo (ex.: "HTTP/1.1 408 Request Timeout") ou recv vazio (conexão fechada)
                status = resposta.split(b"\r\n", 1)[0].decode() if resposta else "conexão fechada"
                break
            except socket.timeout:
                pass                                           # servidor ainda esperando: manda o próximo byte
            # Trava de segurança do próprio teste: se o servidor não cortou em 3x o prazo,
            # a proteção não existe (versão antiga) e não adianta esperar mais.
            if time.time() - inicio > PRAZO_SERVIDOR_S * 3:
                break
    except OSError as e:
        # Servidor resetou a conexão enquanto ainda enviávamos bytes: também conta como corte
        status = f"conexão encerrada ({e.__class__.__name__})"
    finally:
        s.close()

    duracao = time.time() - inicio
    # Tolerância: o corte pode ser percebido até um intervalo depois do prazo
    # (o teste só olha a resposta a cada `intervalo` segundos), mais 1 s de folga.
    cortou_no_prazo = duracao <= PRAZO_SERVIDOR_S + intervalo + 1
    return checar(f"2) Slowloris (cortado em {duracao:.1f}s)",
                  status if cortou_no_prazo else f"{status} após {duracao:.0f}s", "408")


def main():
    # Argumentos no mesmo formato do testes_honeypot.py: HOST PORTA [opções]
    ap = argparse.ArgumentParser()
    ap.add_argument("host"); ap.add_argument("porta", type=int)
    ap.add_argument("--sem-slowloris", action="store_true", help="pula o teste demorado de Slowloris")
    a = ap.parse_args()
    h, p = a.host, a.porta

    # Antes de atacar, confere se o servidor está no ar
    if not servidor_responde(h, p):
        print("Servidor não respondeu ao GET / — ele está rodando?"); return

    resultados = [
        # 1a) Cabeçalho de 20 KB (limite do servidor: 8 KB).
        # Versão antiga: aceita e responde 200. Versão nova: 431.
        checar("1a) cabeçalho de 20 KB", enviar_bruto(h, p,
               b"GET / HTTP/1.1\r\nX-Lixo: " + b"a" * 20000 + b"\r\n\r\n"), "431"),

        # 1b) Content-Length que não é número.
        # Versão antiga: int("abc") lança ValueError, a thread morre e a conexão cai sem resposta.
        checar("1b) Content-Length: abc", enviar_bruto(h, p,
               b"POST /api/perguntar HTTP/1.1\r\nContent-Length: abc\r\n\r\n"), "400"),

        # 1b) Content-Length negativo.
        # Versão antiga: int("-5") funciona e a requisição é aceita como se fosse válida.
        checar("1b) Content-Length: -5", enviar_bruto(h, p,
               b"POST /api/perguntar HTTP/1.1\r\nContent-Length: -5\r\n\r\n"), "400"),

        # 1b) Content-Length gigante (~100 GB) sem enviar o corpo.
        # Versão antiga: fica esperando/acumulando o corpo. Versão nova: rejeita na hora com 413.
        checar("1b) Content-Length: 99999999999", enviar_bruto(h, p,
               b"POST /api/perguntar HTTP/1.1\r\nContent-Length: 99999999999\r\n\r\n"), "413"),
    ]

    # 1c) Cliente fecha a conexão no meio dos cabeçalhos / sem enviar nada.
    # Antes isso matava a thread com ValueError (bug do `return "", ""`);
    # o servidor tem que seguir respondendo normalmente.
    s = socket.create_connection((h, p)); s.sendall(b"GET / HT"); s.close()   # fecha no meio
    socket.create_connection((h, p)).close()                                   # conecta e fecha sem enviar nada
    time.sleep(0.5)                                                            # dá tempo do servidor processar
    resultados.append(checar("1c) servidor de pé após conexões cortadas",
                             "200 OK" if servidor_responde(h, p) else "sem resposta", "200"))

    # 2) Slowloris: o teste mais demorado, por isso pode ser pulado com --sem-slowloris
    if not a.sem_slowloris:
        resultados.append(teste_slowloris(h, p))

    # sum() de uma lista de bool conta quantos True (testes que passaram)
    print(f"\nResumo: {sum(resultados)}/{len(resultados)} testes passaram.")
    print("Confira também o logs/redes.csv: cada ataque deve aparecer com seu status_conexao "
          "(headers_grandes, content_length_invalido, corpo_grande, fechou_antes, conexao_vazia, timeout_leitura).")


if __name__ == "__main__":   # só roda ao executar este arquivo diretamente
    main()
