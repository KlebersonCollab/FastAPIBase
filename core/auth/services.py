from core.users.models import User
from core.auth.models import Role, RefreshToken
from core.security.security import create_access_token, verify_password, create_refresh_token, verify_refresh_token
from core.auth.schemas import RoleIn, RoleUpdate
from datetime import timedelta
from fastapi import HTTPException, status
from core.auth.repositories import (
    create_role as repo_create_role,
    get_role_by_id as repo_get_role_by_id,
    list_roles as repo_list_roles,
    update_role as repo_update_role,
    delete_role as repo_delete_role
)

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
    return {"access_token": access_token, "token_type": "bearer", "refresh_token": refresh_token}

async def refresh_user_token(refresh_token: str):
    user = await verify_refresh_token(refresh_token)
    access_token_expires = timedelta(minutes=30)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# Serviços de Role
async def create_role_service(role: RoleIn):
    return await repo_create_role(role.model_dump())

async def list_roles_service():
    return await repo_list_roles()

async def get_role_service(role_id: int):
    role = await repo_get_role_by_id(role_id)
    if not role:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")
    return role

async def update_role_service(role_id: int, role: RoleUpdate):
    role_obj = await repo_get_role_by_id(role_id)
    if not role_obj:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")
    return await repo_update_role(role_obj, role.model_dump(exclude_unset=True))

async def delete_role_service(role_id: int):
    role = await repo_get_role_by_id(role_id)
    if not role:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")
    await repo_delete_role(role)

async def assign_role_to_user_service(user_id: int, role_id: int):
    user = await User.get_or_none(id=user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    role = await Role.get_or_none(id=role_id)
    if not role:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")
    await user.roles.add(role)
    return {"message": "Role assigned successfully"}

async def revoke_role_from_user_service(user_id: int, role_id: int):
    user = await User.get_or_none(id=user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    role = await Role.get_or_none(id=role_id)
    if not role:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")
    await user.roles.remove(role)
    return {"message": "Role revoked successfully"} 