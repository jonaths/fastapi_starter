from pydantic import BaseModel
from fastapi_jwt_auth import AuthJWT
from fastapi_jwt_auth.exceptions import AuthJWTException
from fastapi import HTTPException
from fastapi.responses import JSONResponse

# 1) Configuración de JWT (aquí pones tu propia clave;
#    idealmente la lees de una var de entorno o .env)
class JWTSettings(BaseModel):
    authjwt_secret_key: str = "CAMBIA_ESTA_CLAVE_POR_ALGO_SECRETO"

@AuthJWT.load_config
def get_jwt_config():
    return JWTSettings()

# 2) Handler global para errores de JWT
def jwt_exception_handler(request, exc: AuthJWTException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.message}
    )
