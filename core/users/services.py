import structlog

logger = structlog.get_logger()
from core.users.repositories import (
    create_user as repo_create_user,
    get_user_by_id as repo_get_user_by_id,
    get_user_by_username as repo_get_user_by_username,
    list_users as repo_list_users,
    update_user as repo_update_user,
    delete_user as repo_delete_user,
)
from core.users.schemas import UserCreate, UserUpdate, UserOut, UserRoleOut
from core.security.security import get_password_hash
from fastapi import HTTPException, status


async def create_user_service(user: UserCreate, executor_id=None):
    user_data = user.model_dump(exclude_unset=True)
    user_data["password"] = get_password_hash(user_data["password"])
    user_obj = await repo_create_user(user_data)
    await user_obj.fetch_related("roles")
    logger.info(
        "user_created",
        executor_id=executor_id,
        user_id=user_obj.id,
        username=user_obj.username,
    )
    return UserOut(
        id=user_obj.id,
        username=user_obj.username,
        is_active=user_obj.is_active,
        is_superuser=user_obj.is_superuser,
        roles=[UserRoleOut(id=role.id, name=role.name) for role in user_obj.roles],
    )


async def get_current_user_service(user_obj):
    await user_obj.fetch_related("roles")
    return UserOut(
        id=user_obj.id,
        username=user_obj.username,
        is_active=user_obj.is_active,
        is_superuser=user_obj.is_superuser,
        roles=[UserRoleOut(id=role.id, name=role.name) for role in user_obj.roles],
    )


async def list_users_service():
    users = await repo_list_users()
    return [
        UserOut(
            id=user.id,
            username=user.username,
            is_active=user.is_active,
            is_superuser=user.is_superuser,
            roles=[UserRoleOut(id=role.id, name=role.name) for role in user.roles],
        )
        for user in users
    ]


async def get_user_service(user_id: int):
    user = await repo_get_user_by_id(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )
    await user.fetch_related("roles")
    return UserOut(
        id=user.id,
        username=user.username,
        is_active=user.is_active,
        is_superuser=user.is_superuser,
        roles=[UserRoleOut(id=role.id, name=role.name) for role in user.roles],
    )


async def update_user_service(user_id: int, user: UserUpdate, executor_id=None):
    user_obj = await repo_get_user_by_id(user_id)
    if not user_obj:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )
    update_data = user.model_dump(exclude_unset=True)
    if "password" in update_data:
        update_data["password"] = get_password_hash(update_data["password"])
    await repo_update_user(user_obj, update_data)
    logger.info(
        "user_updated",
        executor_id=executor_id,
        user_id=user_id,
        update_data=update_data,
    )
    return await UserOut.from_tortoise_orm(user_obj)


async def delete_user_service(user_id: int, executor_id=None):
    user = await repo_get_user_by_id(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )
    await repo_delete_user(user)
    logger.info("user_deleted", executor_id=executor_id, user_id=user_id)
