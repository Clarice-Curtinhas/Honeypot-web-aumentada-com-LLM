## CONTRIBUIÇÃO: esse código foi disponibilizado pelo Rafael Ribeiro Carvalho para o grupo Clarice e Ellyas
#!/usr/bin/env python3
"""
Dispara as 54 requisicoes de atacantes (requisicoes.json) contra um honeypot HTTP
e avalia a resposta com as mesmas regras do projeto. So Python padrao.

Uso:
    python3 testar_honeypot.py HOST PORTA [--reps 3] [--grupo controle|trafego_real|validacao]
Ex.: python3 testar_honeypot.py 127.0.0.1 8080 --reps 3

Para cada resposta mostra: status, Content-Type, tamanho, tempo e se passou no
criterio de realismo. No fim, resumo por grupo e lista do que falhou.
"""
import argparse, http.client, json, re, socket, sys, time
from statistics import mean

ERRO = [r"(?i)\b404\b", r"(?i)not found", r"(?i)\b403\b", r"(?i)forbidden", r"(?i)\b500\b",
        r"(?i)internal server error", r"(?i)bad request", r"(?i)access denied"]
MIN_BODY = 40


def enviar(host, porta, req, timeout=60):
    head, _, body = req.partition("\n\n")
    linhas = [l for l in head.splitlines() if l.strip()]
    primeira, hdrs = linhas[0], linhas[1:]
    hdrs = [h for h in hdrs if not h.lower().startswith(("host:", "connection:", "content-length:"))]
    hdrs.insert(0, f"Host: {host}:{porta}")
    hdrs.append("Connection: close")
    dados = body.encode()
    if dados or primeira.split()[0] in ("POST", "PUT", "PATCH"):
        hdrs.append(f"Content-Length: {len(dados)}")
    raw = ("\r\n".join([primeira] + hdrs) + "\r\n\r\n").encode() + dados
    t0 = time.time()
    s = socket.create_connection((host, porta), timeout=timeout)
    s.sendall(raw)
    r = http.client.HTTPResponse(s); r.begin()
    corpo = r.read().decode("utf-8", "replace")
    ms = int((time.time() - t0) * 1000)
    hd = {k.lower(): v for k, v in r.getheaders()}
    s.close()
    return r.status, hd, corpo, ms


def avaliar(item, status, hd, corpo):
    """(passou, motivo). Mesmo criterio do benchmark do projeto."""
    ct = hd.get("content-type", "")
    esperado = item["esperado"]
    if status >= 500:
        return 0, f"erro {status} do honeypot"
    if esperado == "404":
        ok = status == 404 or any(re.search(p, corpo) for p in ERRO)
        return int(ok), "" if ok else "caminho aleatorio de scanner: deveria ser 404, inventou conteudo"
    if esperado == "cache":
        n = len(corpo.strip()); img = any(a.startswith("image/") for a in item["content_types_aceitos"])
        ok = (0 < n <= 2000) or (n == 0 and img) or status == 404
        return int(ok), "" if ok else "estatico: corpo vazio ou longo demais"
    ct_ok = any((a == "text" and "text/" in ct) or a in ct for a in item["content_types_aceitos"]) if ct else False
    regras = item.get("realismo") or {}
    if len(corpo.strip()) < regras.get("min_len", MIN_BODY):
        return 0, f"corpo muito curto ({len(corpo.strip())} chars)"
    if regras:
        hits = sum(1 for p in regras["expects"] if re.search(p, corpo))
        if any(re.search(p, corpo) for p in ERRO) and esperado != "200-generico":
            return 0, "pagina de erro"
        if hits < regras["min_hits"]:
            return 0, f"pouco convincente ({hits}/{regras['min_hits']} sinais esperados)"
    if not ct_ok:
        return 1, f"ok, mas Content-Type '{ct}' fora do esperado {item['content_types_aceitos']}"
    return 1, ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("host"); ap.add_argument("porta", type=int)
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--grupo", choices=["controle", "trafego_real", "validacao"])
    a = ap.parse_args()
    itens = json.load(open("requisicoes.json", encoding="utf-8"))
    if a.grupo:
        itens = [i for i in itens if i["grupo"] == a.grupo]
    res = []
    print(f"{len(itens)} requisicoes x {a.reps} contra {a.host}:{a.porta}\n")
    for it in itens:
        for k in range(a.reps):
            try:
                st, hd, corpo, ms = enviar(a.host, a.porta, it["requisicao_http"])
                ok, motivo = avaliar(it, st, hd, corpo)
            except Exception as e:
                st, hd, corpo, ms, ok, motivo = 0, {}, "", 0, 0, f"sem resposta: {e}"
            res.append((it, ok, st, ms))
            print(f"{it['id']} {it['metodo']:5s} {it['path'][:42]:42s} -> {st:3d} {hd.get('content-type','')[:22]:22s} {len(corpo):6d} B {ms:6d} ms  {'OK ' if ok else 'NAO'} {motivo}")
    print("\nresumo:")
    for g in ("controle", "trafego_real", "validacao", "todos"):
        rs = [r for r in res if g == "todos" or r[0]["grupo"] == g]
        if rs:
            print(f"  {g:13s} realismo {mean(r[1] for r in rs):5.0%}   latencia media {mean(r[3] for r in rs):6.0f} ms   erros/sem resposta {sum(1 for r in rs if r[2]==0 or r[2]>=500)}")
    falhas = sorted({r[0]["id"] + " " + r[0]["path"][:40] for r in res if not r[1]})
    if falhas:
        print("\nfalharam em pelo menos uma repeticao:\n  " + "\n  ".join(falhas))


if __name__ == "__main__":
    main()