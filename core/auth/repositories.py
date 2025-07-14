from core.auth.models import Role
from typing import Optional, List

async def create_role(data: dict) -> Role:
    return await Role.create(**data)

async def get_role_by_id(role_id: int) -> Optional[Role]:
    return await Role.get_or_none(id=role_id)

async def list_roles() -> List[Role]:
    return await Role.all()

async def update_role(role: Role, data: dict) -> Role:
    await role.update_from_dict(data).save()
    return role

async def delete_role(role: Role):
    await role.delete() 