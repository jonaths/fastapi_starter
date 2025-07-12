# src/main.py

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from tortoise import Tortoise

from src.config import DATABASE_URL, APP_ENV, logger
from src.controllers.user_controller import router as user_router

# 1) Crea la app
app = FastAPI(
    title="My FastAPI App",
    version="0.1.0",
    description="API con FastAPI y Tortoise ORM",
    openapi_url="/openapi.json",
    docs_url="/docs" if APP_ENV == "development" else None,
)

# 2) CORS (igual que antes)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# 3) ORM por petición (igual que antes)
@app.middleware("http")
async def orm_per_request(request: Request, call_next):
    if not Tortoise.apps:
        logger.info("⏳ Inicializando ORM…")
        await Tortoise.init(
            db_url=DATABASE_URL,
            modules={"models": ["src.models"]},
        )
        if APP_ENV == "development":
            await Tortoise.generate_schemas()
        logger.info("✅ ORM listo")

    response = await call_next(request)

    logger.info("Cerrando conexiones ORM…")
    await Tortoise.close_connections()
    Tortoise.apps = {}
    logger.info("ORM cerrado")
    return response


# 4) Monta el router (incluye /login, /protected, etc.)
app.include_router(user_router, prefix="/users", tags=["users"])


# 5) Endpoints globales
@app.get("/")
async def root():
    return {"message": "¡Hola, mundo!!!!!"}


@app.get("/ping")
async def ping():
    return {"message": "pong"}
