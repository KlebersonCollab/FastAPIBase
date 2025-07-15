# CLI Administrativo

O CLI (`fast_admin.py`) oferece comandos para administração do projeto:

## Criar superusuário
```bash
uv run python fast_admin.py createsuperuser
```

## Rodar migrações
```bash
uv run python fast_admin.py migrate
```

## Inicializar banco
```bash
uv run python fast_admin.py init-db
```

Você pode expandir o CLI para outros comandos administrativos conforme necessário. 