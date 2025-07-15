# Etapa 1: Build (instala dependências)
FROM python:3.11-slim AS builder

WORKDIR /app

# Instala uv (gerenciador de ambiente Python moderno)
RUN pip install --upgrade pip && pip install uv

# Copia arquivos de dependências
COPY pyproject.toml .
COPY aerich.ini .

# Instala dependências do projeto no sistema (sem dev)
RUN uv pip install --system .

# Etapa 2: Imagem final
FROM python:3.11-slim

WORKDIR /app

# Instala uv também na imagem final
RUN pip install --upgrade pip && pip install uv

# Copia o app e dependências já instaladas
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin/uv /usr/local/bin/uv
COPY . .

# (Recomendado: defina variáveis de ambiente no deploy, não copie .env.prod)

# Expõe a porta padrão do FastAPI
EXPOSE 8000

# Comando padrão para rodar o app
CMD ["uv", "run", "uvicorn", "core.main:app", "--host", "0.0.0.0", "--port", "8000"] 