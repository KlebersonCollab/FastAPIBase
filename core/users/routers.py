import os
from fastapi import APIRouter, Depends, HTTPException, status
from typing import List
from core.users.models import User
from core.users.schemas import (
    UserCreate,
    UserOut,
    UserUpdate,
    UserRoleOut,
    ChangePasswordIn,
    UserSelfUpdate,
)
from core.security.security import (
    get_password_hash,
    get_current_user,
    check_permissions,
    verify_password,
)
from core.auth.permissions import Permissions
from fastapi_limiter.depends import RateLimiter
from core.users.services import (
    create_user_service,
    get_current_user_service,
    list_users_service,
    get_user_service,
    update_user_service,
    delete_user_service,
)

router = APIRouter()

rate_limit = (
    [] if os.getenv("TESTING") == "1" else [Depends(RateLimiter(times=5, seconds=60))]
)


@router.post(
    "/users/",
    response_model=UserOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(check_permissions([Permissions.CREATE_USERS]))] + rate_limit,
)
async def create_user(user: UserCreate):
    return await create_user_service(user)


@router.get("/users/me", response_model=UserOut)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return await get_current_user_service(current_user)


@router.post("/users/me/change-password", status_code=200)
async def change_password(
    data: ChangePasswordIn, current_user: User = Depends(get_current_user)
):
    if not verify_password(data.current_password, current_user.password):
        raise HTTPException(status_code=400, detail="Senha atual incorreta")
    current_user.password = get_password_hash(data.new_password)
    await current_user.save()
    return {"message": "Senha alterada com sucesso"}


@router.patch("/users/me", response_model=UserOut)
async def update_own_profile(
    data: UserSelfUpdate, current_user: User = Depends(get_current_user)
):
    update_data = data.model_dump(exclude_unset=True)
    # Bloquear campos sensíveis
    for field in ["is_superuser", "is_active", "roles", "password"]:
        update_data.pop(field, None)
    for key, value in update_data.items():
        setattr(current_user, key, value)
    await current_user.save()
    return await get_current_user_service(current_user)


@router.get(
    "/users/",
    response_model=List[UserOut],
    dependencies=[Depends(check_permissions([Permissions.READ_USERS]))],
)
async def read_users():
    return await list_users_service()


@router.get(
    "/users/{user_id}",
    response_model=UserOut,
    dependencies=[Depends(check_permissions([Permissions.READ_USERS]))],
)
async def read_user(user_id: int):
    return await get_user_service(user_id)


@router.put(
    "/users/{user_id}",
    response_model=UserOut,
    dependencies=[Depends(check_permissions([Permissions.UPDATE_USERS]))] + rate_limit,
)
async def update_user(user_id: int, user: UserUpdate):
    return await update_user_service(user_id, user)


@router.delete(
    "/users/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(check_permissions([Permissions.DELETE_USERS]))] + rate_limit,
)
async def delete_user(user_id: int):
    await delete_user_service(user_id)
    return
