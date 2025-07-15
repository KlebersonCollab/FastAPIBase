from core.users.models import User
from typing import Optional, List


async def create_user(data: dict) -> User:
    return await User.create(**data)


async def get_user_by_id(user_id: int) -> Optional[User]:
    return await User.get_or_none(id=user_id)


async def get_user_by_username(username: str) -> Optional[User]:
    return await User.get_or_none(username=username)


async def list_users() -> List[User]:
    return await User.all().prefetch_related("roles")


async def update_user(user: User, data: dict) -> User:
    await user.update_from_dict(data).save()
    return user


async def delete_user(user: User):
    await user.delete()
