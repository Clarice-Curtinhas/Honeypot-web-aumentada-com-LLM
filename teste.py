"""Teste: envia um prompt para a LLM (API compatível com OpenAI) e salva a resposta.

Uso:
    python teste.py "seu prompt aqui"
    python teste.py                      # usa o prompt padrão

Variáveis de ambiente:
    LLM_API_KEY   -> obrigatória (sk-...)
    LLM_BASE_URL  -> padrão http://127.0.0.1:4000/v1  (pela rede: https://<SERVIDOR>:8443/v1)
    LLM_CA_CERT   -> caminho do fullchain.pem (obrigatório com https + certificado autoassinado)
    LLM_MODEL     -> padrão qwen3-8b  (no servidor DGX: modelo-principal)
"""
import os
import sys
import time
from datetime import datetime

import pandas as pd
import requests

BASE_URL = os.getenv("LLM_BASE_URL", "http://127.0.0.1:4000/v1").rstrip("/")
CA_CERT = os.getenv("LLM_CA_CERT")
MODELO = os.getenv("LLM_MODEL", "qwen7b")
TIMEOUT_S = 600

LOGS_DIR = "./logs"
CSV_PATH = os.path.join(LOGS_DIR, "teste_llm.csv")
COLUNAS = ["timestamp", "modelo", "prompt", "latencia_ms", "status_llm", "resposta"]


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


def salvar_csv(registro: dict) -> None:
    os.makedirs(LOGS_DIR, exist_ok=True)
    novo = not os.path.exists(CSV_PATH)
    pd.DataFrame([registro]).reindex(columns=COLUNAS).to_csv(
        CSV_PATH, mode="a", header=novo, index=False
    )


if __name__ == "__main__":
    prompt = " ".join(sys.argv[1:]) or "Explique em uma frase o que é um honeypot."

    inicio = time.perf_counter()
    resposta, status = consultar_llm(prompt)
    latencia_ms = round((time.perf_counter() - inicio) * 1000, 2)

    salvar_csv({
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "modelo": MODELO,
        "prompt": prompt,
        "latencia_ms": latencia_ms,
        "status_llm": status,
        "resposta": resposta,
    })

    print(f"Prompt:   {prompt}")
    print(f"Status:   {status} ({latencia_ms} ms)")
    print(f"Resposta: {resposta}")
    print(f"\nSalvo em {CSV_PATH}")
