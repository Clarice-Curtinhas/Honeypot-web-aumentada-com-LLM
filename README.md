<div align="center">
<h1>Honeypot-web-aumentada-com-LLM </h1>
<p> Repositório do trabalho da disciplina de Redes de Computadores do curso de Engenharia de Computação da Universidade Federal do Espírito Santo. </p>
</div>

## Sumário
* [Sumário](#sumario)
* [Descrição](#descrição)
* [Tecnologias Utilizadas](#tecnologias-utilizadas)
* [Como Executar](#como-executar)
* [Como Testar](#como-testar)
* [Funcionalidades Implementadas](#funcionalidades-implementadas)
* [Possíveis Melhorias Futuras](#possíveis-melhorias-futuras)

## Descrição
O projeto consiste na integração de uma LLM local com um servidor de Honeypot para melhorar a qualidade das respostas à ataques.

*servidor.py*: Um servidor web (Honeypot) rodando em uma máquina que expõe uma interface HTTP (assistente de IA vulnerável).

*testes_honeypot*: Script de teste simulando a outra máquina envia queries prontas de ataques (como HTTP scanning), o servidor de rede intercepta a requisição TCP/HTTP, extrai o texto, encaminha para o servidor que irá análisar se alguma das respostas estáticas pode ser usada ou se uma LLM local deve processar a resposta e devolver a página HTML adaptada com o engodo.

## Tecnologias Utilizadas

* **Servidor, testes e análises:** Python (socket, threading, concurrent.futures, pandas, psutil, requests) e LLM local (Qwen2.5-7B).
* **Páginas estáticas:** HTML, CSS e JavaScript.
* **Simulação de Cenários de Rede:** Linux tc netem (iproute2).

## Como Executar


### Requisitos
* **Python 3+**
* **Ollama** (ou servidor de inferência local equivalente) rodando o modelo Qwen2.5-7B acessível em http://127.0.0.1:4000/v1 (ou configurado via variável de ambiente).
* Dependências Python:
```bash
pip install psutil pandas requests
```

### Instruções de Execução
1. Configurar variáveis de ambiente da LLM:
```bash
export LLM_BASE_URL="http://127.0.0.1:4000/v1"
export LLM_MODEL="qwen2.5-7b"
export LLM_API_KEY="sk-..."
```

2. Iniciar o Servidor Honeypot:
```bash
python3 servidor.py
```

## Como Testar
Em outro terminal, rode o script de testes que dispara as requisições maliciosas (*requisicoes.json*) contra o Honeypot:
```bash
python3 testes_honeypot.py 127.0.0.1 6789 --reps 3
```

### Testes com tc netem
1. **Descubra a interface com:**
```bash
ip route get 1.1.1.1
```

Exemplo de saída: 1.1.1.1 via 0.0.0.0 dev enp0s3 src 0.0.0.0 (interface nesse caso é enp0s3)

2. **Comandos para injeção de atraso e perda de pacotes:**

Delay fixo de 100ms:
```bash
sudo tc qdisc add dev enp0s3 root netem delay 100ms
```

Delay de 100 variando de ±10ms, com correlação de 25% entre o delay anterior:
```bash
sudo tc qdisc add dev eth0 root netem delay 100ms 10ms 25%
```

Remover as regras de rede (restaurar padrão):
```bash
sudo tc qdisc del dev enp0s3 root
```

## Funcionalidades Implementadas
* **Servidor HTTP TCP Multithread Dedicado:** Implementação sobre sockets nativos em Python, permitindo controle sobre o ciclo de vida da conexão, status HTTP e headers.

* **Arquitetura de Roteamento Híbrida:**

    * *Rotas Estáticas:* Atendimento de páginas simuladas do WordPress (/, /wp-login.php, /wp-config.php, /wp-cron.php, /wp-settings.php, etc.) com injeção automática dos conteúdos de CSS e JavaScript diretamente no documento entregue.

    * *Rotas Dinâmicas via LLM:* Endpoint /api/perguntar que encaminha os prompts de ataque para o modelo Qwen2.5-7B gerar engodos dinâmicos em formato HTML/JSON.

* **Processamento Assíncrono com ThreadPoolExecutor:** Isolamento das requisições pesadas da LLM em um pool separado de workers (MAX_LLM), garantindo que a consulta ao modelo não trave o aceite de novas conexões estáticas.

* **Instrumentação e Coleta de Métricas Thread-Safe em CSV:**

    * *requisicao.csv:* Registra timestamp, IP de origem, metodo, path, user_agent, prompt, latencia_llm_ms, status_llm e resposta_engodo.

    * *redes.csv:* Registra IP de origem (src_IP), latência total (latencia_ms), bytes_requisicao, bytes_resposta, uso de CPU (cpu_pct), uso de RAM (ram_mb), quantidade de threads ativas (qnt_threads) e o status do socket (status_conexao).

* **Diagnóstico de Conexão e Efeito Indireto de Rede:** Captura e categorização de falhas de socket (timeout, conexao_resetada, erro_envio) para medir o impacto indireto de perdas de pacote e degradação de rede.

## Possíveis Melhorias Futuras
* *Testes e análises com o uso da LLM*: Como fizemos o setup da nossa LLM em um computador do LPRM e o VPN para a máquina não estava funcionando durante grande parte da execução do projeto não conseguimos fazer testes usando a interface LLM e as análises atuais se baseiam nas respostas estáticas