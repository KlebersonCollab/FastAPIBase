import os
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from core.auth.schemas import Token, RoleIn, RoleOut, RoleUpdate
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

router = APIRouter()

rate_limit = [] if os.getenv("TESTING") == "1" else [Depends(RateLimiter(times=5, seconds=60))]

@router.post("/token", response_model=Token, dependencies=rate_limit)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    return await login_user(form_data.username, form_data.password)

@router.post("/refresh", response_model=Token, dependencies=rate_limit)
async def refresh_access_token(refresh_token: str):
    return await refresh_user_token(refresh_token)

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