# Uso

## Instalação

```bash
uv pip install --system .
```

## Configuração de ambiente

- Defina a variável `ENV` para `dev`, `prod` ou `test`.
- Edite `.env.dev`, `.env.prod` ou `.env.test` conforme necessário.

## Rodar servidor

```bash
uv run uvicorn core.main:app --reload
```

## Rodar testes

```bash
ENV=test PYTHONPATH=. uv run pytest
```

## CLI administrativo

Veja a seção [CLI](cli.md) para comandos como criação de superusuário, migrações e init-db. 