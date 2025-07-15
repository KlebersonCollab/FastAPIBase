# API Reference

Consulte `/docs` para a documentação automática gerada pelo FastAPI (Swagger UI).

Principais endpoints:

- `POST /auth/token` — login
- `POST /auth/refresh` — refresh token
- `POST /users/me/change-password` — alterar senha
- `POST /auth/request-password-reset` — solicitar reset de senha
- `POST /auth/reset-password` — redefinir senha
- `PATCH /users/me` — atualizar perfil
- `POST /auth/roles/` — criar role
- `GET /auth/roles/` — listar roles
- `POST /auth/users/{user_id}/roles/{role_id}` — atribuir role
- `DELETE /auth/users/{user_id}/roles/{role_id}` — revogar role
- ...

Para exemplos detalhados de payloads, veja as seções de autenticação e RBAC. 