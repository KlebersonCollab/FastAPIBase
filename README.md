# FastAPI Core – Documentação Completa

## Índice

- [Visão Geral](#visão-geral)
- [Estrutura do Projeto](#estrutura-do-projeto)
- [Configuração Inicial](#configuração-inicial)
- [Comandos Essenciais](#comandos-essenciais)
- [Autenticação e Autorização (RBAC)](#autenticação-e-autorização-rbac)
- [Refresh Tokens](#refresh-tokens)
- [Gestão de Usuários, Roles e Permissões](#gestão-de-usuários-roles-e-permissões)
- [Criação de Novos Apps/Módulos](#criação-de-novos-appsmódulos)
- [Migrações de Banco de Dados (Aerich)](#migrações-de-banco-de-dados-aerich)
- [Criação de Superusuário](#criação-de-superusuário)
- [Exemplo de Fluxo Completo](#exemplo-de-fluxo-completo)
- [Dicas de Manutenção e Boas Práticas](#dicas-de-manutenção-e-boas-práticas)

---

## Visão Geral

Este projeto é um boilerplate FastAPI inspirado no Django, com:
- Estrutura modular para apps plugáveis
- Autenticação JWT com Refresh Tokens
- RBAC (roles + permissions)
- Migrações automáticas com Aerich
- CLI para administração (criação de apps, migrações, etc.)
- **Arquitetura modular**: cada domínio (ex: auth, users, blog) possui suas próprias camadas (routers, services, repositories, models, schemas, etc.)
- **Configuração centralizada**: middlewares, lifespan e routers organizados em arquivos próprios

---

## Estrutura do Projeto

```
.
├── core/
│   ├── main.py                # Inicialização do FastAPI (enxuto)
│   ├── config.py              # Configuração de lifespan e middlewares
│   ├── routers.py             # Inclusão centralizada dos routers dos módulos
│   ├── settings.py            # Configurações (Pydantic)
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
│   └── models/
├── pyproject.toml             # Dependências e config do Aerich
├── aerich.ini                 # Configuração do Aerich
├── fast_admin.py              # Script para criar superusuário
└── README.md                  # (você está aqui!)
```

---

## Configuração Inicial

1. **Instale as dependências:**
   ```bash
   uv pip install -e .[dev]
   ```

2. **Configure o banco de dados:**
   - Por padrão, usa SQLite (`sqlite://db.sqlite3`).  
     Para usar Postgres, edite `core/settings.py` e defina `DATABASE_URL`.

3. **Configure variáveis de ambiente:**
   - Crie um arquivo `.env` na raiz do projeto e defina a `SECRET_KEY`:
     ```
     SECRET_KEY="sua-chave-secreta-aqui"
     ```
   - Alternativamente, defina a variável de ambiente diretamente no seu shell.

---



## Comandos Essenciais

### Instalar Dependencias usando UV
```bash
uv pip install -e .[dev]
```

### Rodar o servidor

```bash
uv run uvicorn core.main:app --reload
```

### Rodar Testes

```bash
task test
```

### Criar superusuário

```bash
uv run python fast_admin.py
```
Siga o prompt para criar usuário e senha.

### Migrações (Aerich)

```bash
uv run aerich init -t core.main.TORTOISE_ORM
uv run aerich init-db
# Migração com commit:
uv run aerich migrate --name add_refresh_token_model
# Após alterar models:
uv run aerich migrate
uv run aerich upgrade
```

### Criar novo app/módulo

1. Crie um diretório dentro de `core/` (ex: `blog/`).
2. Adicione arquivos `models.py`, `api.py`, `schemas.py` conforme necessário.
3. Importe e inclua o router no `core/main.py`:
   ```python
   from core.blog.api import router as blog_router
   app.include_router(blog_router, prefix="/blog", tags=["blog"])
   ```
4. Adicione os models no `TORTOISE_ORM` em `main.py`.

---

## Autenticação e Autorização (RBAC)

- **Login:**  
  `POST /auth/token` (OAuth2, retorna JWT e Refresh Token)
- **Proteção de rotas:**  
  Use o decorator `Depends(check_permissions([Permissions.X]))` para exigir permissões.
- **Roles:**  
  Usuários podem ter múltiplas roles, cada role tem permissões.
- **Permissões disponíveis:**  
  Veja em `core/auth/permissions.py`.

---

## Refresh Tokens

- **Obtenção:** Ao fazer login em `POST /auth/token`, você receberá um `refresh_token` junto com o `access_token`.
- **Uso:** Utilize o `refresh_token` para obter um novo `access_token` sem precisar fazer login novamente.
  `POST /auth/refresh` (envie o `refresh_token` no corpo da requisição).

---

## Gestão de Usuários, Roles e Permissões

### Usuários

- CRUD completo em `/users/`
- Exemplo de criação:
  ```json
  POST /users/
  {
    "username": "novo_user",
    "password": "senha"
  }
  ```
  *Nota: `is_active` e `is_superuser` não podem ser definidos diretamente na criação de usuário. Use o script `fast_admin.py` para superusuários e a gestão de roles para permissões.* 

### Roles

- Criar role: `POST /auth/roles/`
- Listar roles: `GET /auth/roles/`
- Adicionar permissões: `PUT /auth/roles/{role_id}` (atualize o campo `permissions`)
- Remover permissão: `PUT /auth/roles/{role_id}` (atualize o campo `permissions`)
- Deletar role: `DELETE /auth/roles/{role_id}`

### Permissões

- As permissões são definidas no código em `core/auth/permissions.py`.

### Atribuir/Revogar Roles de Usuários

- Atribuir role: `POST /auth/users/{user_id}/roles/{role_id}`
- Revogar role: `DELETE /auth/users/{user_id}/roles/{role_id}`

---

## Criação de Novos Apps/Módulos

Para criar um novo módulo seguindo o padrão da arquitetura:

1. **Crie um diretório dentro de `core/`** (ex: `blog/`).
2. **Adicione os arquivos base:**
   - `routers.py` – Defina as rotas/endpoints do módulo.
   - `services.py` – Implemente a lógica de negócio do módulo.
   - `repositories.py` – Centralize o acesso a dados do módulo.
   - `models.py` – Defina os modelos ORM.
   - `schemas.py` – Defina os schemas Pydantic.
   - (Opcional) `permissions.py` – Permissões específicas do módulo.
3. **Inclua o router no `core/routers.py`:**
   ```python
   from core.blog.routers import router as blog_router
   def include_routers(app):
       app.include_router(blog_router, prefix="/blog", tags=["blog"])
       # ... outros routers
   ```
4. **Adicione os models no `TORTOISE_ORM` em `main.py` (ou em config separado):**
   ```python
   TORTOISE_ORM = {
       "connections": {"default": settings.DATABASE_URL},
       "apps": {
           "models": {
               "models": [
                   "core.users.models",
                   "core.auth.models",
                   "core.blog.models",  # novo módulo
                   "aerich.models"
               ],
               "default_connection": "default",
           },
       },
   }
   ```
5. **Implemente os endpoints, services e repositories seguindo o padrão dos módulos existentes.**

> **Dica:** Sempre mantenha a separação entre routers (rotas), services (lógica de negócio) e repositories (acesso a dados) para garantir testabilidade e organização.

---

## Migrações de Banco de Dados (Aerich)

- **Configuração:**  
  Veja `aerich.ini` e `pyproject.toml`.
- **Comandos:**
  ```bash
  uv run aerich init -t core.main.TORTOISE_ORM
  uv run aerich init-db
  uv run aerich migrate
  uv run aerich upgrade
  ```
- **Exemplo de migração:**  
  Veja arquivos em `migrations/models/`.

---

## Criação de Superusuário

Execute:
```bash
uv run python fast_admin.py
```
- Siga o prompt para criar usuário e senha.
- O usuário criado será superusuário e terá todas as permissões.

---

## Exemplo de Fluxo Completo

1. **Clone o projeto e instale dependências**
2. **Configure o banco e rode migrações**
3. **Crie superusuário**
4. **Rode o servidor**
5. **Acesse `/docs` para testar a API**
6. **Crie apps, roles, atribua permissões e usuários conforme necessário**

---

## Dicas de Manutenção e Boas Práticas

- Sempre use migrações para alterar o banco (não use `generate_schemas=True` em produção).
- Use roles para agrupar permissões e facilitar a gestão.
- Proteja endpoints sensíveis com `Depends(check_permissions([...]))`.
- Documente e versiona suas APIs.
- Use `.env` para configs sensíveis.
- Teste sempre em ambiente de desenvolvimento antes de ir para produção.

---

## Segurança

Esta aplicação segue boas práticas de segurança para APIs modernas:

- **CORS Restritivo:** Apenas origens confiáveis podem acessar a API. Configure as origens permitidas em `core/main.py`.
- **TrustedHostMiddleware:** Bloqueia requisições de hosts não autorizados, prevenindo ataques de Host Header.
- **GZipMiddleware:** Compactação automática das respostas para melhorar performance e dificultar ataques de análise de tráfego.
- **Rate Limiting:** Limita o número de requisições por IP em endpoints sensíveis, prevenindo brute force e abuso.
- **Headers de Segurança:**
  - `X-Frame-Options: DENY` (protege contra clickjacking)
  - `X-Content-Type-Options: nosniff` (protege contra MIME sniffing)
  - `Referrer-Policy: same-origin` (protege dados de referência)
  - `X-XSS-Protection: 1; mode=block` (protege contra XSS)
  - `Strict-Transport-Security` (obriga uso de HTTPS)
  - `Content-Security-Policy: default-src 'self'` (mitiga XSS e injeção de conteúdo)
- **HTTPSRedirectMiddleware (opcional):** Redireciona todo o tráfego para HTTPS em produção.
- **Autenticação JWT:** Endpoints protegidos exigem token JWT válido.

### Autenticação baseada em sessão (SessionMiddleware)

Caso deseje autenticação baseada em sessão (cookies), siga os passos:

1. **Ative o SessionMiddleware:**
   ```python
   from starlette.middleware.sessions import SessionMiddleware
   app.add_middleware(SessionMiddleware, secret_key=settings.SECRET_KEY)
   ```
2. **No login:**
   - Após autenticar o usuário, armazene o ID do usuário na sessão:
     ```python
     request.session['user_id'] = user.id
     ```
   - O cookie de sessão será enviado automaticamente ao cliente.
3. **Em endpoints protegidos:**
   - Recupere o usuário da sessão:
     ```python
     user_id = request.session.get('user_id')
     ```
   - Valide a sessão e permissões normalmente.
4. **CSRF Protection:**
   - Para endpoints que alteram dados (POST, PUT, DELETE), implemente proteção CSRF:
     - Gere um token CSRF e envie ao frontend.
     - Exija o token em cada requisição de alteração.
     - Valide o token no backend.
   - Bibliotecas recomendadas: [starlette-wtf](https://github.com/yezz123/starlette-wtf), [itsdangerous](https://itsdangerous.palletsprojects.com/).

> **Atenção:** Cookies de sessão devem ser `HttpOnly`, `Secure` e com `SameSite=strict` em produção.

---

Para mais detalhes, consulte os comentários em `core/main.py` e ajuste as configurações conforme o ambiente (dev/prod).

**Este README cobre toda a estrutura, comandos, RBAC, migrações, criação de apps e melhores práticas do seu projeto FastAPI!**
Se quiser exemplos de payloads, fluxos de autenticação ou integração com frontend, posso complementar ainda mais.