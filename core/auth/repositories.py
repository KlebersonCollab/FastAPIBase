from core.auth.models import Role
from typing import Optional, List
from core.auth.models import RefreshToken
from datetime import datetime, timezone
import redis.asyncio as redis
from core.settings import settings

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

async def revoke_refresh_token(token: str):
    refresh_token = await RefreshToken.get_or_none(token=token)
    if refresh_token:
        refresh_token.is_revoked = True
        await refresh_token.save()

async def is_refresh_token_valid(token: str):
    refresh_token = await RefreshToken.get_or_none(token=token)
    now = datetime.now(timezone.utc)
    return refresh_token and not refresh_token.is_revoked and refresh_token.expires_at > now 

# Blacklist de Refresh Tokens
async def add_token_to_blacklist(token: str, expires_at):
    r = redis.from_url(settings.REDIS_URL, encoding="utf-8", decode_responses=True)
    ttl = int((expires_at - datetime.now(timezone.utc)).total_seconds())
    await r.set(f"blacklist:{token}", "1", ex=ttl)

async def is_token_blacklisted(token: str) -> bool:
    r = redis.from_url(settings.REDIS_URL, encoding="utf-8", decode_responses=True)
    return await r.exists(f"blacklist:{token}") 