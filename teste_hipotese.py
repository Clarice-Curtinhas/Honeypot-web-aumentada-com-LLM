import matplotlib.pyplot as plt
import pandas as pd

rede_sem_perda = pd.read_csv("./LLM_Honeypot/logs/redes.csv")
rede_taxa_perda_5 = pd.read_csv("./LLM_Honeypot/logs/redes_perda_5.csv")
rede_taxa_perda_10 = pd.read_csv("./LLM_Honeypot/logs/redes_perda_10.csv")

rede = [rede_sem_perda, rede_taxa_perda_5, rede_taxa_perda_10]
nome = ["Sem perda", "5% de perda", "10% de perda"]

latencia_media = []
uso_cpu = []
uso_ram = []

for taxa in rede:
  if "status_conexao" in taxa.columns:
    taxa = taxa[taxa["status_conexao"] == "ok"]
  latencia_media.append(taxa["latencia_ms"].mean())
  uso_cpu.append(taxa["cpu_pct"].mean())
  uso_ram.append(taxa["ram_mb"].mean())

# Perda vs. Latência
plt.figure(figsize=(8, 5))
plt.plot(nome, latencia_media, marker="o", linewidth=2)
plt.title("Como a taxa de perda de pacotes afeta a latência das respostas")
plt.xlabel("Taxa de perda (%)")
plt.ylabel("Latência média (ms)")
plt.grid(True, linestyle="--", alpha=0.5)
plt.savefig("Taxa_de_perda_vs_latencia.png", dpi=300, bbox_inches="tight")
plt.close()

# Perda vs. CPU
plt.figure(figsize=(8, 5))
plt.plot(nome, uso_cpu, marker="o", linewidth=2)
plt.title("Como a taxa de perda de pacotes afeta o uso de CPU")
plt.xlabel("Taxa de perda (%)")
plt.ylabel("Uso de CPU (%)")
plt.grid(True, linestyle="--", alpha=0.5)
plt.savefig("Taxa_de_perda_vs_cpu.png", dpi=300, bbox_inches="tight")
plt.close()

# Perda vs. RAM
plt.figure(figsize=(8, 5))
plt.plot(nome, uso_ram, marker="o", linewidth=2)
plt.title("Como a taxa de perda de pacotes afeta o uso da RAM")
plt.xlabel("Taxa de perda (%)")
plt.ylabel("Uso de RAM (MB)")
plt.grid(True, linestyle="--", alpha=0.5)
plt.savefig("Taxa_de_perda_vs_ram.png", dpi=300, bbox_inches="tight")
plt.close()