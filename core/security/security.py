from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, APIKeyHeader
from typing import List
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from core.settings import settings
from core.users.models import User
from core.auth.models import RefreshToken
from core.auth.permissions import Permissions
import secrets

SECRET_KEY = settings.SECRET_KEY
ALGORITHM = settings.ALGORITHM
ACCESS_TOKEN_EXPIRE_MINUTES = settings.ACCESS_TOKEN_EXPIRE_MINUTES
REFRESH_TOKEN_EXPIRE_DAYS = 7

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")
api_key_header = APIKeyHeader(name="X-API-KEY")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def create_refresh_token(user: User):
    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    refresh_token_obj = await RefreshToken.create(user=user, token=token, expires_at=expires_at)
    return refresh_token_obj.token

async def verify_refresh_token(token: str):
    refresh_token_obj = await RefreshToken.get_or_none(token=token).prefetch_related("user")
    if not refresh_token_obj or refresh_token_obj.expires_at < datetime.utcnow():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token")
    return refresh_token_obj.user

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = await User.get(username=username).prefetch_related("roles")
    if user is None:
        raise credentials_exception
    return user

def check_permissions(required_permissions: List[Permissions]):
    async def permission_checker(current_user: User = Depends(get_current_user)):
        if current_user.is_superuser:
            return
        
        user_permissions = set()
        for role in current_user.roles:
            user_permissions.update(role.permissions)

        if not all(p.value in user_permissions for p in required_permissions):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permissions")
    return permission_checker

async def get_api_key(api_key: str = Depends(api_key_header)):
    if api_key not in settings.API_KEYS:
        raise HTTPException(status_code=403, detail="Invalid API Key")
    return api_key
