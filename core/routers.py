from core.auth.routers import router as auth_router
from core.users.routers import router as users_router

def include_routers(app):
    app.include_router(auth_router, prefix="/auth", tags=["auth"])
    app.include_router(users_router, tags=["users"])
    # Adicione outros routers aqui conforme necessário 