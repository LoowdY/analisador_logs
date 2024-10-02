import tkinter as tk
from tkinter import filedialog, ttk, messagebox, scrolledtext
import re
from datetime import datetime
import json
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import seaborn as sns
from pandastable import Table, TableModel


class AnalisadorLogsDashboard:
    def __init__(self, janela_principal):
        self.janela_principal = janela_principal
        janela_principal.title("Analisador de Logs - Dashboard")
        janela_principal.geometry("1200x800")

        self.dados_log = None
        self.criar_widgets()

    def criar_widgets(self):
        self.notebook = ttk.Notebook(self.janela_principal)
        self.notebook.pack(expand=True, fill="both")

        self.tab_entrada = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_entrada, text="Entrada de Dados")
        self.criar_aba_entrada()

        self.tab_visao_geral = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_visao_geral, text="Visão Geral")
        self.criar_aba_visao_geral()

        self.tab_seguranca = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_seguranca, text="Análise de Segurança")
        self.criar_aba_seguranca()

        self.tab_desempenho = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_desempenho, text="Análise de Desempenho")
        self.criar_aba_desempenho()

        self.tab_exploracao = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_exploracao, text="Exploração de Dados")
        self.criar_aba_exploracao()

    def criar_aba_entrada(self):
        frame = ttk.Frame(self.tab_entrada, padding="10")
        frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.tab_entrada.columnconfigure(0, weight=1)
        self.tab_entrada.rowconfigure(0, weight=1)

        self.texto_logs = scrolledtext.ScrolledText(frame, wrap=tk.WORD, width=90, height=20)
        self.texto_logs.grid(row=0, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S))

        ttk.Button(frame, text="Carregar Arquivo", command=self.carregar_arquivo).grid(row=1, column=0, pady=10)
        ttk.Button(frame, text="Analisar Logs", command=self.analisar_logs).grid(row=1, column=1, pady=10)
        ttk.Button(frame, text="Limpar", command=self.limpar_logs).grid(row=1, column=2, pady=10)

        ttk.Label(frame, text="Formato:").grid(row=2, column=0, sticky=tk.E)
        self.formato_var = tk.StringVar(value="auto")
        formatos = ["auto", "syslog", "sysmon", "json", "csv"]
        self.combo_formato = ttk.Combobox(frame, textvariable=self.formato_var, values=formatos)
        self.combo_formato.grid(row=2, column=1, sticky=tk.W)

        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(0, weight=1)

    def criar_aba_visao_geral(self):
        frame = ttk.Frame(self.tab_visao_geral, padding="10")
        frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.tab_visao_geral.columnconfigure(0, weight=1)
        self.tab_visao_geral.rowconfigure(0, weight=1)

        self.fig_visao_geral, (self.ax1, self.ax2) = plt.subplots(1, 2, figsize=(10, 4))
        self.canvas_visao_geral = FigureCanvasTkAgg(self.fig_visao_geral, master=frame)
        self.canvas_visao_geral.draw()
        self.canvas_visao_geral.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=1)

        self.texto_resumo = scrolledtext.ScrolledText(frame, wrap=tk.WORD, width=90, height=10)
        self.texto_resumo.pack(side=tk.BOTTOM, fill=tk.X, expand=0)

    def criar_aba_seguranca(self):
        frame = ttk.Frame(self.tab_seguranca, padding="10")
        frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.tab_seguranca.columnconfigure(0, weight=1)
        self.tab_seguranca.rowconfigure(0, weight=1)

        self.fig_seguranca, (self.ax_seg1, self.ax_seg2) = plt.subplots(2, 1, figsize=(10, 8))
        self.canvas_seguranca = FigureCanvasTkAgg(self.fig_seguranca, master=frame)
        self.canvas_seguranca.draw()
        self.canvas_seguranca.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=1)

    def criar_aba_desempenho(self):
        frame = ttk.Frame(self.tab_desempenho, padding="10")
        frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.tab_desempenho.columnconfigure(0, weight=1)
        self.tab_desempenho.rowconfigure(0, weight=1)

        self.fig_desempenho, (self.ax_des1, self.ax_des2) = plt.subplots(2, 1, figsize=(10, 8))
        self.canvas_desempenho = FigureCanvasTkAgg(self.fig_desempenho, master=frame)
        self.canvas_desempenho.draw()
        self.canvas_desempenho.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=1)

    def criar_aba_exploracao(self):
        frame = ttk.Frame(self.tab_exploracao, padding="10")
        frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.tab_exploracao.columnconfigure(0, weight=1)
        self.tab_exploracao.rowconfigure(0, weight=1)

        self.frame_tabela = ttk.Frame(frame)
        self.frame_tabela.pack(side=tk.TOP, fill=tk.BOTH, expand=1)

        frame_filtro = ttk.Frame(frame)
        frame_filtro.pack(side=tk.BOTTOM, fill=tk.X)
        ttk.Label(frame_filtro, text="Filtro:").pack(side=tk.LEFT)
        self.entrada_filtro = ttk.Entry(frame_filtro, width=50)
        self.entrada_filtro.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        ttk.Button(frame_filtro, text="Aplicar Filtro", command=self.aplicar_filtro).pack(side=tk.RIGHT)

    def carregar_arquivo(self):
        arquivo = filedialog.askopenfilename(filetypes=[("Arquivos de Log", "*.log"), ("Arquivos de Texto", "*.txt"),
                                                        ("Arquivos JSON", "*.json"), ("Arquivos CSV", "*.csv"),
                                                        ("Todos os Arquivos", "*.*")])
        if arquivo:
            try:
                with open(arquivo, 'r', encoding='utf-8') as f:
                    conteudo = f.read()
                self.texto_logs.delete('1.0', tk.END)
                self.texto_logs.insert(tk.END, conteudo)
                messagebox.showinfo("Sucesso", f"Arquivo carregado: {arquivo}")
            except Exception as e:
                messagebox.showerror("Erro", f"Não foi possível abrir o arquivo: {str(e)}")

    def analisar_logs(self):
        conteudo = self.texto_logs.get('1.0', tk.END)
        formato = self.formato_var.get()

        if formato == "auto":
            formato = self.detectar_formato(conteudo)

        try:
            if formato == "syslog":
                self.dados_log = self.analisar_syslog(conteudo)
            elif formato == "sysmon":
                self.dados_log = self.analisar_sysmon(conteudo)
            elif formato == "json":
                self.dados_log = self.analisar_json(conteudo)
            elif formato == "csv":
                self.dados_log = self.analisar_csv(conteudo)
            else:
                raise ValueError("Formato não suportado")

            self.atualizar_dashboard()
        except Exception as e:
            messagebox.showerror("Erro na Análise", f"Não foi possível analisar os logs: {str(e)}")

    def detectar_formato(self, conteudo):
        if conteudo.strip().startswith('{'):
            return "json"
        elif ',' in conteudo.split('\n')[0]:
            return "csv"
        elif re.match(r'\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}', conteudo):
            return "syslog"
        else:
            return "sysmon"

    def analisar_syslog(self, conteudo):
        padrao = r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\w+):\s+(.*)'
        correspondencias = re.findall(padrao, conteudo)
        df = pd.DataFrame(correspondencias, columns=['timestamp', 'host', 'processo', 'mensagem'])
        df['timestamp'] = pd.to_datetime(df['timestamp'], format='%b %d %H:%M:%S', errors='coerce')
        return df

    def analisar_sysmon(self, conteudo):
        linhas = [linha.split(',') for linha in conteudo.split('\n') if linha.strip()]
        df = pd.DataFrame(linhas[1:], columns=linhas[0])
        if 'TimeCreated' in df.columns:
            df['TimeCreated'] = pd.to_datetime(df['TimeCreated'], errors='coerce')
        return df

    def analisar_json(self, conteudo):
        df = pd.DataFrame(json.loads(conteudo))
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        return df

    def analisar_csv(self, conteudo):
        df = pd.read_csv(pd.compat.StringIO(conteudo))
        colunas_tempo = df.columns[df.columns.str.contains('time', case=False)]
        if not colunas_tempo.empty:
            df[colunas_tempo[0]] = pd.to_datetime(df[colunas_tempo[0]], errors='coerce')
        return df

    def atualizar_dashboard(self):
        if self.dados_log is None or self.dados_log.empty:
            messagebox.showwarning("Aviso", "Nenhum dado válido para análise.")
            return

        self.atualizar_visao_geral()
        self.atualizar_seguranca()
        self.atualizar_desempenho()
        self.atualizar_exploracao()

    def atualizar_visao_geral(self):
        self.ax1.clear()
        self.ax2.clear()

        if 'processo' in self.dados_log.columns:
            self.dados_log['processo'].value_counts().plot(kind='bar', ax=self.ax1)
            self.ax1.set_title('Eventos por Processo')
            self.ax1.set_xlabel('Processo')
            self.ax1.set_ylabel('Contagem')
        elif 'EventID' in self.dados_log.columns:
            self.dados_log['EventID'].value_counts().plot(kind='bar', ax=self.ax1)
            self.ax1.set_title('Eventos por ID')
            self.ax1.set_xlabel('Event ID')
            self.ax1.set_ylabel('Contagem')

        coluna_tempo = next((col for col in ['timestamp', 'TimeCreated'] if col in self.dados_log.columns), None)
        if coluna_tempo:
            self.dados_log[coluna_tempo].dt.hour.value_counts().sort_index().plot(kind='line', ax=self.ax2)
            self.ax2.set_title('Eventos ao Longo do Tempo')
            self.ax2.set_xlabel('Hora do Dia')
            self.ax2.set_ylabel('Contagem de Eventos')

        self.fig_visao_geral.tight_layout()
        self.canvas_visao_geral.draw()

        resumo = f"Total de entradas: {len(self.dados_log)}\n"
        for coluna in self.dados_log.columns:
            if self.dados_log[coluna].dtype == 'object':
                resumo += f"{coluna} únicos: {self.dados_log[coluna].nunique()}\n"
            elif pd.api.types.is_numeric_dtype(self.dados_log[coluna]):
                resumo += f"{coluna} - Média: {self.dados_log[coluna].mean():.2f}, Máx: {self.dados_log[coluna].max()}\n"

        if coluna_tempo:
            resumo += f"\nPeríodo dos logs:\n"
            resumo += f"Início: {self.dados_log[coluna_tempo].min()}\n"
            resumo += f"Fim: {self.dados_log[coluna_tempo].max()}\n"
            resumo += f"Duração: {self.dados_log[coluna_tempo].max() - self.dados_log[coluna_tempo].min()}\n"

        self.texto_resumo.delete('1.0', tk.END)
        self.texto_resumo.insert(tk.END, resumo)

    def atualizar_seguranca(self):
        self.ax_seg1.clear()
        self.ax_seg2.clear()

        palavras_chave_seguranca = ['failed', 'unauthorized', 'error', 'warning', 'critical']
        coluna_mensagem = next((col for col in ['mensagem', 'Message'] if col in self.dados_log.columns), None)

        if coluna_mensagem:
            eventos_seguranca = self.dados_log[self.dados_log[coluna_mensagem].str.contains('|'.join(palavras_chave_seguranca), case=False, na=False)]

            contagem_eventos = eventos_seguranca[coluna_mensagem].value_counts()
            contagem_eventos[:10].plot(kind='bar', ax=self.ax_seg1)
            self.ax_seg1.set_title('Top 10 Eventos de Segurança')
            self.ax_seg1.set_xlabel('Tipo de Evento')
            self.ax_seg1.set_ylabel('Contagem')
            self.ax_seg1.tick_params(axis='x', rotation=45)

            coluna_tempo = next((col for col in ['timestamp', 'TimeCreated'] if col in self.dados_log.columns), None)
            if coluna_tempo:
                eventos_seguranca[coluna_tempo].dt.hour.value_counts().sort_index().plot(kind='line', ax=self.ax_seg2)
                self.ax_seg2.set_title('Eventos de Segurança ao Longo do Tempo')
                self.ax_seg2.set_xlabel('Hora do Dia')
                self.ax_seg2.set_ylabel('Contagem de Eventos')

        self.fig_seguranca.tight_layout()
        self.canvas_seguranca.draw()

        def atualizar_desempenho(self):
            self.ax_des1.clear()
            self.ax_des2.clear()

            palavras_chave_desempenho = ['slow', 'timeout', 'latency', 'performance']
            coluna_mensagem = next((col for col in ['mensagem', 'Message'] if col in self.dados_log.columns), None)

            if coluna_mensagem:
                eventos_desempenho = self.dados_log[
                    self.dados_log[coluna_mensagem].str.contains('|'.join(palavras_chave_desempenho), case=False,
                                                                 na=False)]

                contagem_eventos = eventos_desempenho[coluna_mensagem].value_counts()
                contagem_eventos[:10].plot(kind='bar', ax=self.ax_des1)
                self.ax_des1.set_title('Top 10 Eventos de Desempenho')
                self.ax_des1.set_xlabel('Tipo de Evento')
                self.ax_des1.set_ylabel('Contagem')
                self.ax_des1.tick_params(axis='x', rotation=45)

                coluna_tempo = next((col for col in ['timestamp', 'TimeCreated'] if col in self.dados_log.columns),
                                    None)
                if coluna_tempo:
                    eventos_desempenho[coluna_tempo].dt.hour.value_counts().sort_index().plot(kind='line',
                                                                                              ax=self.ax_des2)
                    self.ax_des2.set_title('Eventos de Desempenho ao Longo do Tempo')
                    self.ax_des2.set_xlabel('Hora do Dia')
                    self.ax_des2.set_ylabel('Contagem de Eventos')

            self.fig_desempenho.tight_layout()
            self.canvas_desempenho.draw()

    def atualizar_exploracao(self):
            if hasattr(self, 'tabela'):
                self.tabela.destroy()
            self.tabela = Table(self.frame_tabela, dataframe=self.dados_log, showtoolbar=True, showstatusbar=True)
            self.tabela.show()

    def aplicar_filtro(self):
            filtro = self.entrada_filtro.get()
            try:
                dados_filtrados = self.dados_log.query(filtro)
                self.tabela.model.df = dados_filtrados
                self.tabela.redraw()
                messagebox.showinfo("Filtro Aplicado", f"Exibindo {len(dados_filtrados)} entradas após o filtro.")
            except Exception as e:
                messagebox.showerror("Erro no Filtro", f"Não foi possível aplicar o filtro: {str(e)}")

    def limpar_logs(self):
            self.texto_logs.delete('1.0', tk.END)
            self.dados_log = None
            self.texto_resumo.delete('1.0', tk.END)

            # Limpar gráficos
            for ax in [self.ax1, self.ax2, self.ax_seg1, self.ax_seg2, self.ax_des1, self.ax_des2]:
                ax.clear()

            self.canvas_visao_geral.draw()
            self.canvas_seguranca.draw()
            self.canvas_desempenho.draw()

            if hasattr(self, 'tabela'):
                self.tabela.model.df = pd.DataFrame()
                self.tabela.redraw()

            messagebox.showinfo("Limpeza", "Todos os dados e gráficos foram limpos.")

    def exportar_relatorio(self):
            if self.dados_log is None or self.dados_log.empty:
                messagebox.showwarning("Aviso", "Não há dados para exportar.")
                return

            arquivo = filedialog.asksaveasfilename(defaultextension=".csv",
                                                   filetypes=[("CSV files", "*.csv"), ("Todos os arquivos", "*.*")])
            if arquivo:
                try:
                    self.dados_log.to_csv(arquivo, index=False)
                    messagebox.showinfo("Sucesso", f"Dados exportados para {arquivo}")
                except Exception as e:
                    messagebox.showerror("Erro na Exportação", f"Não foi possível exportar os dados: {str(e)}")

    # Inicialização da aplicação
if __name__ == "__main__":
    root = tk.Tk()
    app = AnalisadorLogsDashboard(root)
    root.mainloop()
