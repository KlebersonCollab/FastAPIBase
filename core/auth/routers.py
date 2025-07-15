import os
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from core.auth.schemas import Token, RoleIn, RoleOut, RoleUpdate, RefreshTokenIn
from core.security.security import create_access_token, verify_password, get_current_user, check_permissions, create_refresh_token, verify_refresh_token
from core.users.models import User
from core.auth.models import Role, RefreshToken
from core.auth.permissions import Permissions
from datetime import timedelta
from typing import List
from fastapi_limiter.depends import RateLimiter
from core.auth.services import (
    login_user, refresh_user_token, create_role_service, list_roles_service, get_role_service, update_role_service, delete_role_service, assign_role_to_user_service, revoke_role_from_user_service
)
from core.auth.repositories import revoke_refresh_token, add_token_to_blacklist
import structlog
from core.users.schemas import PasswordResetRequestIn, PasswordResetIn
import secrets
import redis.asyncio as redis
from core.settings import settings
from core.users.models import User
from core.security.security import get_password_hash

router = APIRouter()

rate_limit = [] if os.getenv("TESTING") == "1" else [Depends(RateLimiter(times=5, seconds=60))]

logger = structlog.get_logger()

@router.post("/token", response_model=Token, dependencies=rate_limit)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    return await login_user(form_data.username, form_data.password)

@router.post("/refresh", response_model=Token, dependencies=rate_limit)
async def refresh_access_token(body: RefreshTokenIn):
    return await refresh_user_token(body.refresh_token)

@router.post("/logout")
async def logout(body: RefreshTokenIn):
    await revoke_refresh_token(body.refresh_token)
    refresh_token_obj = await RefreshToken.get_or_none(token=body.refresh_token)
    if refresh_token_obj:
        await add_token_to_blacklist(body.refresh_token, refresh_token_obj.expires_at)
        logger.info("Refresh token revogado e adicionado à blacklist", token=body.refresh_token, user_id=refresh_token_obj.user_id)
    else:
        logger.warning("Tentativa de revogar refresh token inexistente", token=body.refresh_token)
    return {"message": "Refresh token revoked"}

@router.post("/roles/", response_model=RoleOut, status_code=status.HTTP_201_CREATED, dependencies=[Depends(check_permissions([Permissions.MANAGE_ROLES]))] + rate_limit)
async def create_role(role: RoleIn):
    role_obj = await create_role_service(role)
    return await RoleOut.from_tortoise_orm(role_obj)

@router.get("/roles/", response_model=List[RoleOut], dependencies=[Depends(check_permissions([Permissions.MANAGE_ROLES]))])
async def read_roles():
    return await list_roles_service()

@router.get("/roles/{role_id}", response_model=RoleOut, dependencies=[Depends(check_permissions([Permissions.MANAGE_ROLES]))])
async def read_role(role_id: int):
    role = await get_role_service(role_id)
    return await RoleOut.from_tortoise_orm(role)

@router.put("/roles/{role_id}", response_model=RoleOut, dependencies=[Depends(check_permissions([Permissions.MANAGE_ROLES]))] + rate_limit)
async def update_role(role_id: int, role: RoleUpdate):
    role_obj = await update_role_service(role_id, role)
    return await RoleOut.from_tortoise_orm(role_obj)

@router.delete("/roles/{role_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(check_permissions([Permissions.MANAGE_ROLES]))] + rate_limit)
async def delete_role(role_id: int):
    await delete_role_service(role_id)
    return

@router.post("/users/{user_id}/roles/{role_id}", status_code=status.HTTP_200_OK, dependencies=[Depends(check_permissions([Permissions.MANAGE_ROLES]))] + rate_limit)
async def assign_role_to_user(user_id: int, role_id: int):
    return await assign_role_to_user_service(user_id, role_id)

@router.delete("/users/{user_id}/roles/{role_id}", status_code=status.HTTP_200_OK, dependencies=[Depends(check_permissions([Permissions.MANAGE_ROLES]))] + rate_limit)
async def revoke_role_from_user(user_id: int, role_id: int):
    return await revoke_role_from_user_service(user_id, role_id)

@router.post("/request-password-reset")
async def request_password_reset(data: PasswordResetRequestIn):
    user = await User.get_or_none(username=data.username)
    if not user:
        return {"message": "Se o usuário existir, um e-mail será enviado"}
    token = secrets.token_urlsafe(32)
    r = redis.from_url(settings.REDIS_URL, encoding="utf-8", decode_responses=True)
    await r.set(f"reset:{token}", user.id, ex=900)  # 15 minutos
    logger.info("Token de reset de senha gerado", token=token, user_id=user.id)
    # Em produção, enviar e-mail. Aqui, apenas loga.
    return {"message": "Se o usuário existir, um e-mail será enviado"}

@router.post("/reset-password")
async def reset_password(data: PasswordResetIn):
    r = redis.from_url(settings.REDIS_URL, encoding="utf-8", decode_responses=True)
    user_id = await r.get(f"reset:{data.token}")
    if not user_id:
        raise HTTPException(status_code=400, detail="Token inválido ou expirado")
    user = await User.get_or_none(id=user_id)
    if not user:
        raise HTTPException(status_code=400, detail="Usuário não encontrado")
    user.password = get_password_hash(data.new_password)
    await user.save()
    await r.delete(f"reset:{data.token}")
    logger.info("Senha redefinida via token de reset", user_id=user.id)
    return {"message": "Senha redefinida com sucesso"}