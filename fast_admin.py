import asyncio
from tortoise import Tortoise
from core.users.models import User
from core.auth.models import Role
from core.security.security import get_password_hash
from core.settings import settings
from core.auth.permissions import Permissions

async def create_superuser():
    await Tortoise.init(
        db_url=settings.DATABASE_URL,
        modules={"models": ["core.users.models", "core.auth.models"]}
    )
    username = input("Enter username: ")
    password = input("Enter password: ")
    hashed_password = get_password_hash(password)
    
    superuser_role, _ = await Role.get_or_create(name="superuser", defaults={"permissions": [p.value for p in Permissions]})

    user = await User.create(
        username=username, 
        password=hashed_password, 
        is_superuser=True, 
        is_active=True
    )
    await user.roles.add(superuser_role)
    print(f"Superuser {username} created successfully.")

if __name__ == "__main__":
    asyncio.run(create_superuser())