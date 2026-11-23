import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

rede = pd.read_csv('./logs/redes.csv')
requisicao = pd.read_csv('./logs/requisicao.csv')

rede["falhou"] = rede["status_conexao"] != "ok"

print(rede.describe())
print(rede)

plt.bar(rede.status_conexao, rede.latencia_ms, log=True)
plt.title("Interferência da rede na latência")
plt.ylabel("Latência (ms)")
plt.xlabel("Falhas de Rede")

plt.grid(True)
plt.savefig("Falhas_de_rede_vs_latencia.png")