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

# Nota: esto es demostrativo, no debiera usarse en producción porque se le indica al navegador
# que puede recibir peticiones de cualquier lugar, lo cuál no es muy seguro.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # permite cualquier origen (incluido file:// y null)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# 2) Middleware para inicializar Tortoise en el mismo loop que atiende la petición
@app.middleware("http")
async def orm_per_request(request: Request, call_next):
    """
    Middleware HTTP para inicializar y cerrar Tortoise ORM en cada petición.

    Debido a que en entornos serverless como Vercel el proceso o el bucle
    de eventos puede no persistir entre invocaciones, y los eventos de
    startup de FastAPI pueden no ejecutarse, este middleware garantiza:

    1. **Inicialización**: Si `Tortoise.apps` está vacío:
       - Conecta a la base de datos con `Tortoise.init()`.
       - En desarrollo (`APP_ENV == "development"`), genera esquemas con
         `Tortoise.generate_schemas()`.
    2. **Procesamiento**: Llama al siguiente handler con `await call_next(request)`.
    3. **Tear Down**:
       - Cierra conexiones con `Tortoise.close_connections()`.
       - Reinicia `Tortoise.apps = {}` para forzar nueva inicialización
         en la siguiente petición.
    """

    # 1) Inicializa en el mismo loop si no está
    if not Tortoise.apps:
        logger.info("⏳ Inicializando ORM…")
        await Tortoise.init(
            db_url=DATABASE_URL,
            modules={"models": ["src.models"]},
        )
        if APP_ENV == "development":
            await Tortoise.generate_schemas()
        logger.info("✅ ORM listo")

    # 2) Ejecuta la ruta
    response = await call_next(request)

    # 3) Cierra conexiones para que no queden en un estado intermedio
    logger.info("Cerrando conexiones ORM…")
    await Tortoise.close_connections()

    # 4) Limpia el estado para que en la siguiente petición la inicialice de nuevo
    Tortoise.apps = {}
    logger.info("ORM cerrado")
    return response


# 3) Monta el router de usuarios
app.include_router(user_router, prefix="/users", tags=["users"])


# 4) Endpoints globales
@app.get("/")
async def root():
    return {"message": "¡Hola, mundo!!!!!"}


@app.get("/ping")
async def ping():
    return {"message": "pong"}
