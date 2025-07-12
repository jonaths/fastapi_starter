import logging
import sys

from decouple import config

APP_ENV = config("APP_ENV", default="production")
PORT = config("PORT", cast=int, default=8000)
DATABASE_URL = config("DATABASE_URL_VERCEL", default="sqlite://db.sqlite3")


JWT_SECRET_KEY = config("JWT_SECRET_KEY", "CAMBIA_POR_ALGO_SUPER_SECRETO")

# ---------------------------------------------------
# 2. Nivel de logging según entorno
# ---------------------------------------------------
# En desarrollo mostramos DEBUG; en prod INFO o superior
LOG_LEVEL = logging.DEBUG if APP_ENV == "development" else logging.INFO

# ---------------------------------------------------
# 3. Formato y configuración básica de logging
# ---------------------------------------------------
LOG_FORMAT = "%(asctime)s %(levelname)-8s [%(name)s] %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Enviar logs a stdout (útil en entornos serverless como Vercel)
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(logging.Formatter(fmt=LOG_FORMAT, datefmt=DATE_FORMAT))

# Logger raíz
logger = logging.getLogger()
logger.setLevel(LOG_LEVEL)

# Evitar duplicar handlers si este módulo se importa varias veces
if not logger.handlers:
    logger.addHandler(handler)