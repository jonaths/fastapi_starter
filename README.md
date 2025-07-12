# FastAPI App Starter

Proyecto base para una API construida con FastAPI, Tortoise ORM y Poetry.  
Incluye:

- Estructura modular (src/)
- FastAPI como servidor ASGI
- Tortoise ORM para conexión asíncrona a base de datos (SQLite/Postgres)
- Validación de datos con Pydantic
- Gestión de variables de entorno con Python-Decouple
- Esqueleto de tests con pytest

---

## Requisitos previos

1. **Git** (para clonar el repositorio).  
   2  **Poetry** (gestor de dependencias y entorno virtual).
    - Si no está instalado, instalar siguiendo [la guía oficial](https://python-poetry.org/docs/#installation).

Opcionales (si usarás Postgres en lugar de SQLite):

- Un servidor de **PostgreSQL** en marcha (local o remoto).
- El comando `psql` en tu PATH (para validar conexión, backups, etc.).

---

## Configurar el proyecto

1. **Clonar** este repositorio a tu máquina local:

   ```bash
   git clone https://github.com/jonaths/fastapi_starter

2. Instalar dependencias con Poetry y crea un entorno virtual:

   ```bash
   poetry install

3. Configurar variables de entorno

   ```bash
   cp .env.example .env

4. Editar .env según sea necesario. Por ejemplo.
   ```
   # Entorno de ejecución: development o production
   APP_ENV=development
   
   # Puerto en el que correrá la aplicación (solo si corres local)
   PORT=8000
   
   # URL de conexión a la base de datos
   # Ejemplo para SQLite local:
   DATABASE_URL=sqlite://db.sqlite3
   
   # Ejemplo para Postgres (reemplaza los datos con tus credenciales):
   # DATABASE_URL=postgres://usuario:contraseña@localhost:5432/nombre_db
   ```

   Notas:

    - En desarrollo, basta con SQLite (sqlite://db.sqlite3).
    - En producción apuntar a Postgres mediante DATABASE_URL.

## Levantar la aplicación en local

1. Levantar el servidor Uvicorn

   ```bash
   poetry run uvicorn src.main:app --reload
   ```

    - --reload activa recarga automática cuando detecta cambios en el código.
    - Por defecto, corre en http://127.0.0.1:8000 (o el puerto que definas en .env).

2. Verificar en el navegador o con curl

    - Abre tu navegador en http://127.0.0.1:8000/docs para acceder a la documentación interactiva Swagger UI.
    - Para probar rápidamente el endpoint raíz:
       ```bash
       curl http://127.0.0.1:8000/
       # Debe devolver: {"message":"¡Hola, mundo!"}

3. Probar algunos endpoints de ejemplo:
    - Listar usuarios (GET)
   ```bash
   curl http://127.0.0.1:8000/users/
   ```

4. Uso de autenticación demostrativa

   La autenticacion incluída está basada en JWT y únicamente valida el correo electrónico para generar el JWT.
   Se incluye un endpoint protegido y otro endpoint para autenticar.

   Se puede crear un usuario con este comando (o usando la interfase web de FastAPI)

   ```
   curl -X POST http://127.0.0.1:8000/users/ -H "Content-Type: application/json" -d '{"name":"Juan","email":"juan@ejemplo.com"}'
   ```

   Para autenticar a un usuario
   ```
   curl -X POST http://127.0.0.1:8000/users/login -F "username=juan100@ejemplo.com" -F "password=foo"
   ```

   Para acceder a un endpoint protegido
   ```
   curl http://127.0.0.1:8000/users/protected \
   -H "Authorization: Bearer <JWT>"
   ```

## Deployment en Vercel

### Preliminares

1. Se debe asegurar que el plugin para exportar esté declarado en `pyproject.toml`:

   ```toml
   [tool.poetry.requires-plugins]
   poetry-plugin-export = ">=1.8"
   ```

2. Se debe verificar que `src/api/index.py` expone la aplicación de FastAPI:

   ```python
   import os
   import sys

   HERE = os.path.dirname(__file__)
   SRC_ROOT = os.path.dirname(HERE)
   sys.path.append(SRC_ROOT)

   from main import app
   ```

3. Se debe tener instalado [Vercel CLI](https://www.npmjs.com/package/vercel) y haber iniciado sesión:

   ```bash
   vercel login
   ```

4. Se debe confirmar que `vercel.json` existe en la raíz y contiene la configuración adecuada:

   ```json
   {
     "version": 2,
     "builds": [
       {
         "src": "src/api/index.py",
         "use": "@vercel/python",
         "config": { "runtime": "python3.12" }
       }
     ],
     "routes": [
       { "src": "/(.*)", "dest": "src/api/index.py" }
     ]
   }
   ```

### Despliegue

1. Se debe exportar las dependencias a `requirements.txt`:

   ```bash
   poetry export --without-hashes -f requirements.txt > requirements.txt
   ```

2. Se debe vincular el directorio al proyecto de Vercel:

   ```bash
   vercel link
   ```
    - Cuando pregunte si se quiere enlazar a un proyecto existente, se debe elegir **No**.

3. Se puede ejecutar el despliegue inicial y luego publicar en producción:

   ```bash
   vercel
   vercel --prod
   ```

### Comprobación

- Se puede visitar la URL de producción para verificar que la API esté disponible:

  ```
  https://<tu-proyecto>.vercel.app/docs
  ```

#### Base de datos Postgres en Vercel

1. Asegurarse que hay una linea con   ```"asyncpg (>=0.30.0,<0.31.0)"  ``` en pyproject.toml. Si no la hay instalar la
   dependencia y actualizar requirements.txt con el comando 1.

2. En el dashboard de Vercel crear una base de datos en Storage -> Create New -> Neon Serverless Postgres y recuperar la
   variable de ambiente DATABASE_URL

**Uso de la base de datos con la aplicacion local**

3.1. Cambiar la variable de ambiente correspondiente para usar Postgres en lugar de SQLite (quitar el query string de
SSL)

3.2. Levantar la aplicación

   ```bash
     poetry run uvicorn src.main:app --reload
   ```

3.3. Visitar ```https://<tu-proyecto>.vercel.app/docs``` para interactuar con la aplicación.

   ```
      DATABASE_URL=postgres://neondb_owner:xxx@ep-plain-bush-xxx-pooler.us-east-1.aws.neon.tech/neondb
   ```

**Uso de la base de datos con la aplicación en línea**

4.1. Verificar en el dashboard de Vercel Settings -> Environment Variables que la variable DATABASE_URL
esté seteada exactamente igual que en el archivo .env local.

4.2. Hacer un nuevo deployment usando los comandos de Vercel.