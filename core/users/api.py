import os
from fastapi import APIRouter, Depends, HTTPException, status
from typing import List
from core.users.models import User
from core.users.schemas import UserCreate, UserOut, UserUpdate, UserRoleOut
from core.security.security import get_password_hash, get_current_user, check_permissions
from core.auth.permissions import Permissions
from fastapi_limiter.depends import RateLimiter

router = APIRouter()

rate_limit = [] if os.getenv("TESTING") == "1" else [Depends(RateLimiter(times=5, seconds=60))]

@router.post("/users/", response_model=UserOut, status_code=status.HTTP_201_CREATED, dependencies=[Depends(check_permissions([Permissions.CREATE_USERS]))] + rate_limit)
async def create_user(user: UserCreate):
    user_data = user.model_dump(exclude_unset=True)
    user_obj = await User.create(**user_data)
    await user_obj.fetch_related("roles")
    return UserOut(
        id=user_obj.id,
        username=user_obj.username,
        is_active=user_obj.is_active,
        is_superuser=user_obj.is_superuser,
        roles=[UserRoleOut(id=role.id, name=role.name) for role in user_obj.roles]
    )

@router.get("/users/me", response_model=UserOut)
async def read_users_me(current_user: User = Depends(get_current_user)):
    await current_user.fetch_related("roles")
    return UserOut(
        id=current_user.id,
        username=current_user.username,
        is_active=current_user.is_active,
        is_superuser=current_user.is_superuser,
        roles=[UserRoleOut(id=role.id, name=role.name) for role in current_user.roles]
    )

@router.get("/users/", response_model=List[UserOut], dependencies=[Depends(check_permissions([Permissions.READ_USERS]))])
async def read_users():
    return await User.all().prefetch_related("roles")

@router.get("/users/{user_id}", response_model=UserOut, dependencies=[Depends(check_permissions([Permissions.READ_USERS]))])
async def read_user(user_id: int):
    user = await User.get_or_none(id=user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    await user.fetch_related("roles")
    return UserOut(
        id=user.id,
        username=user.username,
        is_active=user.is_active,
        is_superuser=user.is_superuser,
        roles=[UserRoleOut(id=role.id, name=role.name) for role in user.roles]
    )

@router.put("/users/{user_id}", response_model=UserOut, dependencies=[Depends(check_permissions([Permissions.UPDATE_USERS]))] + rate_limit)
async def update_user(user_id: int, user: UserUpdate):
    user_obj = await User.get_or_none(id=user_id)
    if not user_obj:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    update_data = user.model_dump(exclude_unset=True)
    if "password" in update_data:
        update_data["password"] = get_password_hash(update_data["password"])
    await user_obj.update_from_dict(update_data).save()
    return await UserOut.from_tortoise_orm(user_obj)

@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(check_permissions([Permissions.DELETE_USERS]))] + rate_limit)
async def delete_user(user_id: int):
    user = await User.get_or_none(id=user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    await user.delete()
    return
