from datetime import datetime, timedelta

from fastapi import APIRouter, HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr

from src.config import JWT_SECRET_KEY
from src.services.user_service import UserService
from src.config import logger

router = APIRouter(
    tags=["users"],
    responses={404: {"description": "Not found"}},
)

# --------------------
#  Configuración JWT
# --------------------
SECRET_KEY = JWT_SECRET_KEY  # Clave secreta usada para firmar los tokens (NUNCA PONER EN EL CÓDIGO)
ALGORITHM = "HS256"  # Algoritmo de firma HMAC-SHA256
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # Duración en minutos del token

# Este objeto indica a FastAPI que use el flujo OAuth2 “password” apuntando a /users/login
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/users/login")


# --------------------
#  DTOs (Data Transfer Objects)
# --------------------

class UserInDto(BaseModel):
    """
    DTO de entrada para usuarios:
      - name: nombre completo
      - email: correo válido
    FastAPI usará esto para validar y documentar el body de create_user y list_users.
    """
    name: str
    email: EmailStr  # valida automáticamente formato de email


class TokenDto(BaseModel):
    """
    DTO de salida para login:
      - access_token: el JWT que usarás luego
      - token_type: por defecto "bearer"
    """
    access_token: str
    token_type: str = "bearer"


# --------------------
#  Endpoints CRUD
# --------------------

@router.get(
    "/",
    summary="Listar usuarios",
    response_model=list[UserInDto],  # documenta que devuelve lista de UserIn
    status_code=status.HTTP_200_OK
)
async def list_users():
    try:
        return await UserService.get_all()
    except Exception as e:
        logger.exception(e)
        raise HTTPException(500, "Error al listar usuarios")


@router.post(
    "/",
    summary="Crear usuario",
    response_model=UserInDto,  # documenta que devuelve un UserIn
    status_code=status.HTTP_201_CREATED,
    responses={400: {"description": "Email ya registrado"}}
)
async def create_user(payload: UserInDto):
    try:
        # payload ya está validado contra el esquema UserIn
        return await UserService.create(name=payload.name, email=payload.email)
    except Exception:
        logger.exception("Error creando usuario")
        raise HTTPException(400, "No se pudo crear el usuario")


# --------------------
#  Login → emite JWT
# --------------------

@router.post(
    "/login",
    summary="Obtener token JWT",
    response_model=TokenDto,  # documenta la forma {access_token, token_type}
    status_code=status.HTTP_200_OK
)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    1) form_data.username es el email
    2) Verifica que exista en la BD
    3) Crea un JWT con:
         - sub: el email (subject)
         - exp: fecha de expiración
    4) Devuelve el token para que el cliente lo use después
    """
    user = await UserService.get_by_email(form_data.username)
    if not user:
        # 401 con header WWW-Authenticate para indicar que falta credenciales válidas
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            detail="Usuario o contraseña incorrectos",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # TODO: habiendo recuperado el usuario, validar que la contraseña coincide con la contraseña almacenada.
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {"sub": user.email, "exp": expire}  # payload del JWT
    token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": token}


# --------------------
#  Dependencia de seguridad
# --------------------

async def get_current_user(token: str = Depends(oauth2_scheme)):
    """
    1) Extrae el JWT del header Authorization: Bearer <token>
    2) Decodifica y valida firma/expiración
    3) Saca el campo 'sub' (email) y busca el usuario en BD
    4) Si todo OK, devuelve la entidad User; si no, lanza 401
    """
    credentials_exc = HTTPException(
        status.HTTP_401_UNAUTHORIZED,
        detail="No se pudo validar las credenciales",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if not email:
            raise credentials_exc
    except JWTError:
        raise credentials_exc

    user = await UserService.get_by_email(email)
    if not user:
        raise credentials_exc
    return user


# --------------------
#  Endpoint protegido
# --------------------

@router.get(
    "/protected",
    summary="Endpoint protegido",
    status_code=status.HTTP_200_OK
)
async def protected(current_user=Depends(get_current_user)):
    """
    Sólo accesible si envías el JWT:
      Authorization: Bearer <access_token>

    current_user es la entidad devuelta por get_current_user().
    """
    return {"message": f"¡Hola, {current_user.email}! Accediste a un endpoint protegido."}
