# FastAPI Core – Documentação Completa

## Índice

- [Visão Geral](#visão-geral)
- [Estrutura do Projeto](#estrutura-do-projeto)
- [Configuração Inicial](#configuração-inicial)
- [Ambientes e Variáveis](#ambientes-e-variáveis)
- [Comandos Essenciais](#comandos-essenciais)
- [CLI Administrativo (fast_admin.py)](#cli-administrativo-fast_adminpy)
- [Autenticação e Autorização (RBAC)](#autenticação-e-autorização-rbac)
- [Refresh Tokens](#refresh-tokens)
- [Gestão de Usuários, Roles e Permissões](#gestão-de-usuários-roles-e-permissões)
- [Criação de Novos Apps/Módulos](#criação-de-novos-appsmódulos)
- [Migrações de Banco de Dados (Aerich)](#migrações-de-banco-de-dados-aerich)
- [Exemplo de Fluxo Completo](#exemplo-de-fluxo-completo)
- [CI/CD e Qualidade](#cicd-e-qualidade)
- [Dicas de Manutenção e Boas Práticas](#dicas-de-manutenção-e-boas-práticas)
- [Segurança](#segurança)

---

## Visão Geral

Este projeto é um boilerplate FastAPI inspirado no Django, com:
- Estrutura modular para apps plugáveis
- Autenticação JWT com Refresh Tokens e rotação segura
- RBAC (roles + permissions)
- Migrações automáticas com Aerich
- CLI administrativo moderno (`fast_admin.py`)
- **Configuração por ambiente**: `.env.dev`, `.env.prod`, `.env.test`
- **CI/CD**: Pipeline GitHub Actions para lint, testes e build Docker
- **Arquitetura modular**: cada domínio (ex: auth, users) possui suas próprias camadas (routers, services, repositories, models, schemas, etc.)
- **Logging estruturado**: eventos críticos logados em JSON

---

## Estrutura do Projeto

```
.
├── core/
│   ├── main.py                # Inicialização do FastAPI
│   ├── config.py              # Configuração de lifespan e middlewares
│   ├── routers.py             # Inclusão centralizada dos routers dos módulos
│   ├── settings.py            # Configurações (Pydantic, multi-ambiente)
│   ├── auth/                  # Módulo de autenticação e RBAC
│   │   ├── routers.py         # Rotas/endpoints do módulo
│   │   ├── services.py        # Lógica de negócio do módulo
│   │   ├── repositories.py    # Acesso a dados do módulo
│   │   ├── models.py
│   │   ├── schemas.py
│   │   ├── permissions.py
│   ├── users/                 # Módulo de usuários
│   │   ├── routers.py
│   │   ├── services.py
│   │   ├── repositories.py
│   │   ├── models.py
│   │   ├── schemas.py
│   ├── security/              # Utilitários de segurança
│   │   └── security.py
├── migrations/                # Migrações do Aerich
├── pyproject.toml             # Dependências e config do Aerich
├── aerich.ini                 # Configuração do Aerich
├── fast_admin.py              # CLI administrativo (criação de superusuário, migrações, etc)
├── .env.dev/.env.prod/.env.test # Configs por ambiente
├── .github/workflows/ci.yml   # Pipeline CI/CD
└── README.md                  # (você está aqui!)
```

---

## Configuração Inicial

1. **Instale as dependências:**
   ```bash
   uv pip install --system .
   ```

2. **Configure o ambiente:**
   - Defina a variável `ENV` para `dev`, `prod` ou `test`.
   - O settings carrega automaticamente `.env.dev`, `.env.prod` ou `.env.test`.
   - Exemplo para desenvolvimento:
     ```bash
     export ENV=dev
     cp .env.dev .env.dev  # Edite conforme necessário
     ```

3. **Configure o banco de dados:**
   - Por padrão, usa SQLite (`sqlite://db.sqlite3`).
   - Para usar Postgres, edite `.env.prod` e defina `DATABASE_URL`.

---

## Ambientes e Variáveis

- `.env.dev` – Desenvolvimento
- `.env.prod` – Produção
- `.env.test` – Testes automatizados

Exemplo de `.env.dev`:
```
SECRET_KEY=dev-secret-key
DATABASE_URL=sqlite://db.sqlite3
REDIS_URL=redis://localhost:6379/0
API_KEYS=["dev-api-key"]
```

---

## Comandos Essenciais

### Instalar dependências
```bash
uv pip install --system .
```

### Rodar o servidor
```bash
uv run uvicorn core.main:app --reload
```

### Rodar Testes
```bash
ENV=test PYTHONPATH=. uv run pytest
```

---

## CLI Administrativo (`fast_admin.py`)

O CLI oferece comandos para administração do projeto:

- **Criar superusuário:**
  ```bash
  uv run python fast_admin.py createsuperuser
  ```
- **Rodar migrações:**
  ```bash
  uv run python fast_admin.py migrate
  ```
- **Inicializar banco:**
  ```bash
  uv run python fast_admin.py init-db
  ```

Você pode expandir o CLI facilmente para outros comandos administrativos.

---

## Autenticação e Autorização (RBAC)

- **Login:**  `POST /auth/token` (OAuth2, retorna JWT e Refresh Token)
- **Proteção de rotas:**  Use o decorator `Depends(check_permissions([Permissions.X]))` para exigir permissões.
- **Roles:**  Usuários podem ter múltiplas roles, cada role tem permissões.
- **Permissões disponíveis:**  Veja em `core/auth/permissions.py`.
- **Alteração de senha:**  `POST /users/me/change-password`
- **Recuperação de senha:**  `POST /auth/request-password-reset` e `POST /auth/reset-password`
- **Atualização de perfil:**  `PATCH /users/me` (restrito a campos não sensíveis)

---

## Refresh Tokens

- **Obtenção:** Ao fazer login em `POST /auth/token`, você receberá um `refresh_token` junto com o `access_token`.
- **Uso:** Utilize o `refresh_token` para obter um novo `access_token` sem precisar fazer login novamente.
  `POST /auth/refresh` (envie o `refresh_token` no corpo da requisição).
- **Rotação e revogação:** Tokens são rotacionados a cada uso e revogados imediatamente, com blacklist persistente em Redis.

---

## Gestão de Usuários, Roles e Permissões

### Usuários
- CRUD completo em `/users/` (exceto campos sensíveis)
- Alteração de senha e perfil via endpoints próprios

### Roles
- Criar role: `POST /auth/roles/`
- Listar roles: `GET /auth/roles/`
- Atualizar role: `PUT /auth/roles/{role_id}`
- Deletar role: `DELETE /auth/roles/{role_id}`

### Permissões
- Definidas em `core/auth/permissions.py`.

### Atribuir/Revogar Roles de Usuários
- Atribuir role: `POST /auth/users/{user_id}/roles/{role_id}`
- Revogar role: `DELETE /auth/users/{user_id}/roles/{role_id}`

---

## Criação de Novos Apps/Módulos

1. Crie um diretório dentro de `core/` (ex: `blog/`).
2. Adicione arquivos `models.py`, `routers.py`, `schemas.py`, `services.py`, `repositories.py` conforme necessário.
3. Importe e inclua o router no `core/routers.py`.
4. Adicione os models no `TORTOISE_ORM` em `main.py`.

> **Dica:** Mantenha a separação entre routers, services e repositories para garantir testabilidade e organização.

---

## Migrações de Banco de Dados (Aerich)

- **Configuração:**  Veja `aerich.ini` e `pyproject.toml`.
- **Comandos:**
  ```bash
  uv run python fast_admin.py migrate
  uv run python fast_admin.py init-db
  ```
- **Exemplo de migração:**  Veja arquivos em `migrations/`.

---

## Exemplo de Fluxo Completo

1. **Clone o projeto e instale dependências**
2. **Configure o ambiente e banco**
3. **Crie superusuário**
4. **Rode o servidor**
5. **Acesse `/docs` para testar a API**
6. **Crie apps, roles, atribua permissões e usuários conforme necessário**

---

## CI/CD e Qualidade

- **Pipeline GitHub Actions**: Lint (Black, Ruff), testes automatizados, build Docker.
- **Ambiente de testes isolado**: `.env.test` criado dinamicamente no CI.
- **Comandos do workflow:**
  - Lint: `uv run black --check .` e `uv run ruff check .`
  - Testes: `ENV=test PYTHONPATH=. uv run pytest`
  - Build Docker: `docker build -t fastapibase:ci .`
- **Deploy:** Pronto para integração com Docker Hub ou outro registry (ajuste o workflow conforme sua infra).

---

## Dicas de Manutenção e Boas Práticas

- Use sempre ambientes separados para dev, prod e test.
- Rode lint e testes localmente antes de subir código.
- Use o CLI para tarefas administrativas e migrações.
- Proteja endpoints sensíveis com permissões.
- Documente e versiona suas APIs.
- Use logging estruturado para auditoria e troubleshooting.
- Teste sempre em ambiente de desenvolvimento antes de ir para produção.

---

## Segurança

- **Rotação e revogação de refresh tokens:**
  - Tokens de refresh são rotacionados a cada uso e revogados imediatamente.
  - Blacklist persistente em Redis impede reuso de tokens revogados.
- **Logging estruturado:**
  - Todos os eventos críticos de autenticação e revogação são logados em JSON com structlog.
- **Testes automatizados de segurança:**
  - Testes para brute force, privilege escalation e ausência de CSRF.
- **Proteções adicionais:**
  - CORS restritivo, TrustedHostMiddleware, GZipMiddleware, Rate Limiting, Headers de segurança, autenticação JWT.
- **Ambiente seguro:**
  - Use HTTPS em produção, configure variáveis sensíveis apenas em `.env.prod`.

---

**Este README cobre toda a estrutura, comandos, RBAC, migrações, CLI, ambientes, CI/CD, segurança e melhores práticas do seu projeto FastAPI!**
Se quiser exemplos de payloads, fluxos de autenticação ou integração com frontend, posso complementar ainda mais.