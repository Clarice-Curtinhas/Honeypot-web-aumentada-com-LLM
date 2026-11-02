from flask import Flask, render_template, request, jsonify
from datetime import datetime
import pandas as pd
import os

app = Flask(__name__)

# Configuração do caminho do arquivo CSV de logs
LOGS_DIR = "./logs"
CSV_PATH = os.path.join(LOGS_DIR, "prompts.csv")

# Garante que a pasta de logs existe e o CSV inicial possui as colunas corretas
os.makedirs(LOGS_DIR, exist_ok=True)
if not os.path.exists(CSV_PATH):
    df_inicial = pd.DataFrame(columns=["timestamp", "IP", "user_agent", "prompt"])
    df_inicial.to_csv(CSV_PATH, index=False)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/perguntar', methods=['POST'])
def capturar_prompt():
    dados = request.get_json()
    prompt = dados.get('prompt', '')
    
    # Captura dados de auditoria / Honeypot
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    user_agent = request.headers.get('User-Agent')
    data_hora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Registo no terminal
    print(f"\n[HONEYPOT AI CAPTURA] {data_hora}")
    print(f"IP: {ip} | User-Agent: {user_agent}")
    print(f"Prompt Enviado: {prompt}\n")

    # Cria o dicionário com o novo log
    novo_log = {"timestamp": data_hora, "IP": ip, "user_agent": user_agent, "prompt": prompt}

    # Carrega o CSV atual, atualiza com o Pandas e salva de volta
    try:
        df = pd.read_csv(CSV_PATH)
    except Exception:
        df = pd.DataFrame(columns=["timestamp", "IP", "user_agent", "prompt"])

    # Concatena o novo registro e salva no CSV
    df = pd.concat([df, pd.DataFrame([novo_log])], ignore_index=True)
    df.to_csv(CSV_PATH, index=False)
    
    return jsonify({
        "status": "success",
        "resposta": "Processando o seu pedido no modelo..."
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)
    