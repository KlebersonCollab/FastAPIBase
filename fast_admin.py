import asyncio
import typer
import os
from tortoise import Tortoise
from core.users.models import User
from core.auth.models import Role
from core.security.security import get_password_hash
from core.settings import settings
from core.auth.permissions import Permissions


def run_async(func):
    def wrapper(*args, **kwargs):
        return asyncio.run(func(*args, **kwargs))

    return wrapper


app = typer.Typer()


@app.command()
def createsuperuser():
    """Cria um superusuário interativamente."""
    asyncio.run(_createsuperuser())


async def _createsuperuser():
    await Tortoise.init(
        db_url=settings.DATABASE_URL,
        modules={"models": ["core.users.models", "core.auth.models"]},
    )
    username = input("Enter username: ")
    password = input("Enter password: ")
    hashed_password = get_password_hash(password)
    superuser_role, _ = await Role.get_or_create(
        name="superuser", defaults={"permissions": [p.value for p in Permissions]}
    )
    user = await User.create(
        username=username, password=hashed_password, is_superuser=True, is_active=True
    )
    await user.roles.add(superuser_role)
    print(f"Superuser {username} created successfully.")


@app.command()
def migrate():
    """Roda migrações do banco de dados usando aerich."""
    os.system("uv run aerich migrate && uv run aerich upgrade")


@app.command()
def init_db():
    """Inicializa o banco de dados (cria tabelas)."""
    os.system("uv run aerich init-db")


if __name__ == "__main__":
    app()
