# Autenticação & RBAC

## Login

- Endpoint: `POST /auth/token`
- Retorna: `access_token`, `refresh_token`

## Refresh Token

- Endpoint: `POST /auth/refresh`
- Envie o `refresh_token` no corpo da requisição.
- Tokens são rotacionados e revogados a cada uso.

## RBAC

- Proteja rotas com `Depends(check_permissions([...]))`
- Usuários podem ter múltiplas roles, cada role tem permissões.
- Permissões disponíveis: veja `core/auth/permissions.py`

## Alteração de senha

- Endpoint: `POST /users/me/change-password`
- Payload:
```json
{
  "current_password": "senha_atual",
  "new_password": "nova_senha"
}
```

## Recuperação de senha

- Endpoint: `POST /auth/request-password-reset` (solicita token)
- Endpoint: `POST /auth/reset-password` (usa token para redefinir)

## Atualização de perfil

- Endpoint: `PATCH /users/me`
- Apenas campos não sensíveis podem ser alterados. 