import structlog
from core.users.models import User
from core.auth.models import Role, RefreshToken
from core.security.security import (
    create_access_token,
    verify_password,
    create_refresh_token,
    verify_refresh_token,
)
from core.auth.schemas import RoleIn, RoleUpdate
from datetime import timedelta
from fastapi import HTTPException, status
from core.auth.repositories import (
    create_role as repo_create_role,
    get_role_by_id as repo_get_role_by_id,
    list_roles as repo_list_roles,
    update_role as repo_update_role,
    delete_role as repo_delete_role,
    revoke_refresh_token,
    is_refresh_token_valid,
    add_token_to_blacklist,
    is_token_blacklisted,
)

logger = structlog.get_logger()


# Serviço de autenticação
async def login_user(username: str, password: str):
    user = await User.get_or_none(username=username).prefetch_related("roles")
    if not user or not verify_password(password, user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=30)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    refresh_token = await create_refresh_token(user)
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "refresh_token": refresh_token,
    }


async def refresh_user_token(refresh_token: str):
    if await is_token_blacklisted(refresh_token):
        logger.warning(
            "Tentativa de uso de refresh token na blacklist", token=refresh_token
        )
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
    if not await is_refresh_token_valid(refresh_token):
        logger.warning("Refresh token inválido ou expirado", token=refresh_token)
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
    # Revoga o token antigo (rotação)
    await revoke_refresh_token(refresh_token)
    # Adiciona à blacklist
    refresh_token_obj = await RefreshToken.get(token=refresh_token)
    await add_token_to_blacklist(refresh_token, refresh_token_obj.expires_at)
    logger.info(
        "Refresh token rotacionado e revogado",
        token=refresh_token,
        user_id=refresh_token_obj.user_id,
    )
    user = await verify_refresh_token(refresh_token)
    access_token_expires = timedelta(minutes=30)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    new_refresh_token = await create_refresh_token(user)
    logger.info("Novo refresh token emitido", user_id=user.id)
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "refresh_token": new_refresh_token,
    }


# Serviços de Role
async def create_role_service(role: RoleIn, executor_id=None):
    role_obj = await repo_create_role(role.model_dump(exclude_unset=True))
    logger.info(
        "role_created", executor_id=executor_id, role_id=role_obj.id, name=role_obj.name
    )
    return role_obj


async def list_roles_service():
    return await repo_list_roles()


async def get_role_service(role_id: int):
    role = await repo_get_role_by_id(role_id)
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Role not found"
        )
    return role


async def update_role_service(role_id: int, role: RoleUpdate, executor_id=None):
    role_obj = await repo_get_role_by_id(role_id)
    if not role_obj:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Role not found"
        )
    updated = await repo_update_role(role_obj, role.model_dump(exclude_unset=True))
    logger.info(
        "role_updated",
        executor_id=executor_id,
        role_id=role_id,
        update_data=role.model_dump(exclude_unset=True),
    )
    return updated


async def delete_role_service(role_id: int, executor_id=None):
    role = await repo_get_role_by_id(role_id)
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Role not found"
        )
    await repo_delete_role(role)
    logger.info("role_deleted", executor_id=executor_id, role_id=role_id)


async def assign_role_to_user_service(user_id: int, role_id: int, executor_id=None):
    user = await User.get_or_none(id=user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )
    role = await Role.get_or_none(id=role_id)
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Role not found"
        )
    await user.roles.add(role)
    logger.info(
        "role_assigned_to_user",
        executor_id=executor_id,
        user_id=user_id,
        role_id=role_id,
    )
    return {"message": "Role assigned successfully"}


async def revoke_role_from_user_service(user_id: int, role_id: int, executor_id=None):
    user = await User.get_or_none(id=user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )
    role = await Role.get_or_none(id=role_id)
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Role not found"
        )
    await user.roles.remove(role)
    logger.info(
        "role_revoked_from_user",
        executor_id=executor_id,
        user_id=user_id,
        role_id=role_id,
    )
    return {"message": "Role revoked successfully"}
