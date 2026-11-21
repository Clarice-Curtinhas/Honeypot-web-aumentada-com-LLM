import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

rede = pd.read_csv('./logs/redes.csv')
requisicao = pd.read_csv('./logs/requisicao.csv')

plt.plot(rede.latencia_ms, rede.cpu_pct)
plt.plot(rede.latencia_ms, rede.ram_mb)
plt.plot(rede.latencia_ms, rede.qnt_threads)
plt.title("Interferência da latência no consumo de cpu")
plt.xlabel("Latência (ms)")
plt.ylabel("Uso de CPU (%)")

plt.grid(True)
plt.savefig("grafico.png")