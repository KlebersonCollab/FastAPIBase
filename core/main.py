from fastapi import FastAPI
from core.config import lifespan, configure_middlewares
from core.routers import include_routers
from core.settings import settings
from tortoise.contrib.fastapi import register_tortoise
import structlog

app = FastAPI(title=settings.PROJECT_NAME, lifespan=lifespan)

configure_middlewares(app)
include_routers(app)

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ]
)

TORTOISE_ORM = {
    "connections": {"default": settings.DATABASE_URL},
    "apps": {
        "models": {
            "models": ["core.users.models", "core.auth.models", "aerich.models"],
            "default_connection": "default",
        },
    },
}

register_tortoise(
    app,
    config=TORTOISE_ORM,
    generate_schemas=True,
    add_exception_handlers=True,
)
