from pydantic import BaseModel
from typing import List, Optional
from tortoise.contrib.pydantic import pydantic_model_creator
from core.auth.models import Role
from core.auth.permissions import Permissions

class Token(BaseModel):
    access_token: str
    token_type: str
    refresh_token: Optional[str] = None

class TokenData(BaseModel):
    username: str | None = None

class RefreshTokenIn(BaseModel):
    refresh_token: str

RoleOut = pydantic_model_creator(Role, name="RoleOut")

class RoleIn(BaseModel):
    name: str
    permissions: List[Permissions] = []

class RoleUpdate(BaseModel):
    name: Optional[str] = None
    permissions: Optional[List[Permissions]] = None
