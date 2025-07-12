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

router = APIRouter()

rate_limit = [] if os.getenv("TESTING") == "1" else [Depends(RateLimiter(times=5, seconds=60))]

@router.post("/token", response_model=Token, dependencies=rate_limit)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await User.get_or_none(username=form_data.username).prefetch_related("roles")
    if not user or not verify_password(form_data.password, user.password):
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

@router.post("/refresh", response_model=Token, dependencies=rate_limit)
async def refresh_access_token(refresh_token: str):
    user = await verify_refresh_token(refresh_token)
    access_token_expires = timedelta(minutes=30)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/roles/", response_model=RoleOut, status_code=status.HTTP_201_CREATED, dependencies=[Depends(check_permissions([Permissions.MANAGE_ROLES]))] + rate_limit)
async def create_role(role: RoleIn):
    role_obj = await Role.create(**role.model_dump())
    return await RoleOut.from_tortoise_orm(role_obj)

@router.get("/roles/", response_model=List[RoleOut], dependencies=[Depends(check_permissions([Permissions.MANAGE_ROLES]))])
async def read_roles():
    return await Role.all()

@router.get("/roles/{role_id}", response_model=RoleOut, dependencies=[Depends(check_permissions([Permissions.MANAGE_ROLES]))])
async def read_role(role_id: int):
    role = await Role.get_or_none(id=role_id)
    if not role:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")
    return await RoleOut.from_tortoise_orm(role)

@router.put("/roles/{role_id}", response_model=RoleOut, dependencies=[Depends(check_permissions([Permissions.MANAGE_ROLES]))] + rate_limit)
async def update_role(role_id: int, role: RoleUpdate):
    role_obj = await Role.get_or_none(id=role_id)
    if not role_obj:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")
    update_data = role.model_dump(exclude_unset=True)
    await role_obj.update_from_dict(update_data).save()
    return await RoleOut.from_tortoise_orm(role_obj)

@router.delete("/roles/{role_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(check_permissions([Permissions.MANAGE_ROLES]))] + rate_limit)
async def delete_role(role_id: int):
    role = await Role.get_or_none(id=role_id)
    if not role:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")
    await role.delete()
    return

@router.post("/users/{user_id}/roles/{role_id}", status_code=status.HTTP_200_OK, dependencies=[Depends(check_permissions([Permissions.MANAGE_ROLES]))] + rate_limit)
async def assign_role_to_user(user_id: int, role_id: int):
    user = await User.get_or_none(id=user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    role = await Role.get_or_none(id=role_id)
    if not role:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")
    await user.roles.add(role)
    return {"message": "Role assigned successfully"}

@router.delete("/users/{user_id}/roles/{role_id}", status_code=status.HTTP_200_OK, dependencies=[Depends(check_permissions([Permissions.MANAGE_ROLES]))] + rate_limit)
async def revoke_role_from_user(user_id: int, role_id: int):
    user = await User.get_or_none(id=user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    role = await Role.get_or_none(id=role_id)
    if not role:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Role not found")
    await user.roles.remove(role)
    return {"message": "Role revoked successfully"}