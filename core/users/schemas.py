from pydantic import BaseModel
from typing import List, Optional


class UserRoleOut(BaseModel):
    id: int
    name: str


class UserOut(BaseModel):
    id: int
    username: str
    is_active: bool
    is_superuser: bool
    roles: List[UserRoleOut] = []


class UserCreate(BaseModel):
    username: str
    password: str


class UserIn(BaseModel):
    username: str
    password: str
    is_active: Optional[bool] = True
    is_superuser: Optional[bool] = False


class UserUpdate(BaseModel):
    username: Optional[str] = None
    password: Optional[str] = None
    is_active: Optional[bool] = None
    is_superuser: Optional[bool] = None


class UserSelfUpdate(BaseModel):
    username: Optional[str] = None
    # Adicione outros campos permitidos, ex: email: Optional[str] = None


class ChangePasswordIn(BaseModel):
    current_password: str
    new_password: str


class PasswordResetRequestIn(BaseModel):
    username: str


class PasswordResetIn(BaseModel):
    token: str
    new_password: str
