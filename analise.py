import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.dates as mdates

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
plt.close()


#=============================================
# Requisições ao longo do tempo

def escolher_intervalo(duracao: pd.Timedelta) -> tuple[str, str]:
    """Escolhe o tamanho do intervalo de agrupamento conforme a duração da captura,
    para o gráfico ter uma quantidade razoável de barras (nem 3, nem 3000)."""
    if duracao <= pd.Timedelta(minutes=10):
        return "10s", "10 segundos"
    if duracao <= pd.Timedelta(hours=1):
        return "1min", "1 minuto"
    if duracao <= pd.Timedelta(hours=6):
        return "5min", "5 minutos"
    if duracao <= pd.Timedelta(days=2):
        return "1h", "1 hora"
    return "1D", "1 dia"


def categorizar_rota(row) -> str:
    """Agrupa as requisições pelo tipo de isca acessada."""
    if row["path"] == "/api/perguntar":
        return "API da LLM (POST)"
    if str(row["path"]).startswith("/wp-"):
        return "Páginas WordPress falsas"
    if row["path"] == "/":
        return "Página inicial"
    return "Outras"


def grafico_requisicoes_no_tempo(df: pd.DataFrame, arquivo: str = "Requisicoes_ao_longo_do_tempo.png") -> None:
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp"])
    if df.empty:
        print("Sem requisições com timestamp válido para o gráfico temporal.")
        return

    df["categoria"] = df.apply(categorizar_rota, axis=1)

    freq, rotulo_freq = escolher_intervalo(df["timestamp"].max() - df["timestamp"].min())

    # Conta quantas requisições de cada categoria caíram em cada intervalo de tempo
    contagem = (
        df.set_index("timestamp")
          .groupby("categoria")
          .resample(freq)
          .size()
          .unstack(level=0, fill_value=0)
          .fillna(0)
    )
    # Garante que intervalos sem nenhuma requisição também apareçam (com zero)
    contagem = contagem.reindex(
        pd.date_range(contagem.index.min(), contagem.index.max(), freq=freq), fill_value=0
    )

    cores = {
        "Página inicial": "#4C72B0",
        "Páginas WordPress falsas": "#DD8452",
        "API da LLM (POST)": "#55A868",
        "Outras": "#8C8C8C",
    }

    fig, (ax_barras, ax_acum) = plt.subplots(
        2, 1, figsize=(12, 7), sharex=True, gridspec_kw={"height_ratios": [3, 1.3]}
    )

    # Gráfico 1: barras empilhadas por categoria em cada intervalo
    largura = pd.Timedelta(freq) * 0.9
    base = pd.Series(0, index=contagem.index)
    for categoria in contagem.columns:
        ax_barras.bar(
            contagem.index, contagem[categoria], width=largura, bottom=base,
            label=categoria, color=cores.get(categoria), align="edge",
        )
        base = base + contagem[categoria]

    ax_barras.set_title(f"Requisições ao honeypot ao longo do tempo (intervalos de {rotulo_freq})")
    ax_barras.set_ylabel("Nº de requisições")
    ax_barras.legend(loc="upper left")
    ax_barras.grid(True, axis="y", alpha=0.3)

    # Gráfico 2: total acumulado de requisições
    acumulado = contagem.sum(axis=1).cumsum()
    ax_acum.step(acumulado.index, acumulado.values, where="post", color="#333333")
    ax_acum.set_ylabel("Acumulado")
    ax_acum.set_xlabel("Horário")
    ax_acum.grid(True, alpha=0.3)

    # Mostra só a hora no eixo X quando tudo acontece no mesmo dia
    if df["timestamp"].dt.date.nunique() == 1:
        ax_acum.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
    fig.autofmt_xdate()
    fig.tight_layout()
    fig.savefig(arquivo, dpi=150)
    plt.close(fig)

    # Resumo no terminal
    total_por_intervalo = contagem.sum(axis=1)
    print(f"\n=== Requisições ao longo do tempo (intervalo: {rotulo_freq}) ===")
    print(f"Período: {df['timestamp'].min()}  ->  {df['timestamp'].max()}")
    print(f"Total de requisições: {len(df)}")
    print(f"Pico: {int(total_por_intervalo.max())} requisições em {total_por_intervalo.idxmax()}")
    print(df["categoria"].value_counts().to_string())
    print(f"Gráfico salvo em {arquivo}")


grafico_requisicoes_no_tempo(requisicao)