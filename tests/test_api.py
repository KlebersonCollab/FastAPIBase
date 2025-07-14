import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from tortoise import Tortoise
from core.main import app, TORTOISE_ORM
from core.users.models import User
from core.auth.models import Role
from core.security.security import get_password_hash
from fastapi_limiter import FastAPILimiter
import redis.asyncio as redis
import os
os.environ["TESTING"] = "1"

@pytest_asyncio.fixture
async def client():
    await Tortoise.init(config=TORTOISE_ORM, modules={"models": ["core.users.models", "core.auth.models"]})
    await Tortoise.generate_schemas()
    # Inicializa o FastAPILimiter com Redis em memória para testes
    r = await redis.from_url("redis://localhost:6379/0", encoding="utf-8", decode_responses=True)
    await FastAPILimiter.init(r)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    await Tortoise._drop_databases()

@pytest_asyncio.fixture
async def test_user(client: AsyncClient):
    hashed_password = get_password_hash("testpassword")
    user = await User.create(username="testuser", password=hashed_password)
    return user

@pytest_asyncio.fixture
async def superuser(client: AsyncClient):
    hashed_password = get_password_hash("superpassword")
    user = await User.create(username="superuser", password=hashed_password, is_superuser=True)
    return user

@pytest_asyncio.fixture
async def superuser_token(superuser: User, client: AsyncClient):
    response = await client.post("/auth/token", data={"username": superuser.username, "password": "superpassword"})
    assert response.status_code == 200, f"Erro ao obter token do superusuário: {response.text}"
    data = response.json()
    assert "access_token" in data, f"Resposta inesperada ao obter token: {data}"
    return data["access_token"]

@pytest_asyncio.fixture
async def create_user_permission(client: AsyncClient):
    role = await Role.create(name="create_user_role", permissions=["create_users"])
    return role

@pytest.mark.asyncio
async def test_create_user(client: AsyncClient, superuser_token: str):
    response = await client.post(
        "/users/",
        json={
            "username": "newuser",
            "password": "newpassword",
        },
        headers={
            "Authorization": f"Bearer {superuser_token}"
        }
    )
    assert response.status_code == 201
    assert response.json()["username"] == "newuser"

@pytest.mark.asyncio
async def test_login_for_access_token(client: AsyncClient, test_user: User):
    response = await client.post(
        "/auth/token",
        data={
            "username": test_user.username,
            "password": "testpassword",
        },
    )
    assert response.status_code == 200
    assert "access_token" in response.json()
    assert "refresh_token" in response.json()

@pytest.mark.asyncio
async def test_read_users_me(client: AsyncClient, test_user: User):
    response = await client.post(
        "/auth/token",
        data={
            "username": test_user.username,
            "password": "testpassword",
        },
    )
    token = response.json()["access_token"]
    response = await client.get(
        "/users/me",
        headers={
            "Authorization": f"Bearer {token}"
        },
    )
    assert response.status_code == 200
    assert response.json()["username"] == test_user.username

@pytest.mark.asyncio
async def test_read_users_as_superuser(client: AsyncClient, superuser_token: str):
    response = await client.get(
        "/users/",
        headers={
            "Authorization": f"Bearer {superuser_token}"
        },
    )
    assert response.status_code == 200
    assert isinstance(response.json(), list)

@pytest.mark.asyncio
async def test_create_role(client: AsyncClient, superuser_token: str):
    response = await client.post(
        "/auth/roles/",
        json={
            "name": "test_role",
            "permissions": ["read_users"]
        },
        headers={
            "Authorization": f"Bearer {superuser_token}"
        },
    )
    assert response.status_code == 201
    assert response.json()["name"] == "test_role"

@pytest.mark.asyncio
async def test_assign_role_to_user(client: AsyncClient, superuser_token: str, test_user: User, create_user_permission: Role):
    response = await client.post(
        f"/auth/users/{test_user.id}/roles/{create_user_permission.id}",
        headers={
            "Authorization": f"Bearer {superuser_token}"
        },
    )
    assert response.status_code == 200
    assert response.json()["message"] == "Role assigned successfully"

    # Verify role is assigned
    response = await client.get(
        f"/users/{test_user.id}",
        headers={
            "Authorization": f"Bearer {superuser_token}"
        },
    )
    assert response.status_code == 200
    assert "roles" in response.json()
    assert len(response.json()["roles"]) > 0
    assert response.json()["roles"][0]["name"] == "create_user_role"
