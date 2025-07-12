"""
src/services/user_service.py

Capa de servicio para operaciones relacionadas con el modelo User.

Este módulo define:
- UserService: clase con métodos estáticos que abstraen la lógica de negocio
  para recuperar y crear usuarios.
- Uso de Tortoise ORM para interactuar con la base de datos de manera asíncrona.
"""

from typing import List, Optional
from src.models import User


class UserService:
    """
    UserService

    Proporciona métodos de alto nivel para interactuar con la entidad User.
    Separa la lógica de negocio de los controladores (API) y el acceso directo al ORM.
    """

    @staticmethod
    def get_age_group(age: int) -> str:
        if 0 < age < 18:
            age_group = "underage"
        elif 18 <= age < 64:
            age_group = "adult"
        elif age >= 64:
            age_group = "senior"
        else:
            raise ValueError("Edad invalida")
        return age_group

    @staticmethod
    async def get_all() -> List[User]:
        """
        Recupera todos los usuarios registrados en la base de datos.

        Returns:
            List[User]: Lista de instancias User cargadas desde la base de datos.

        Ejemplo:
            >>> users = await UserService.get_all()
            >>> for u in users:
            ...     print(u.id, u.name, u.email)
        """
        return await User.all()

    @staticmethod
    async def create(name: str, email: str) -> Optional[User]:
        """
        Crea un nuevo usuario con los datos proporcionados.

        Args:
            name (str): Nombre completo del usuario. Debe ser una cadena no vacía.
            email (str): Correo electrónico único. Se validó previamente con Pydantic.

        Returns:
            Optional[User]: Instancia User recién creada si la operación fue exitosa.
                            None si ocurrió un error o violación de unicidad.

        Comportamiento:
        1. Llama a User.create() del ORM para insertar el registro.
        2. Si el correo ya existe, Tortoise lanzará una excepción de integridad.
           Es recomendable capturarla en un nivel superior (controlador) para
           devolver un HTTP 400 con detalle de duplicado.

        Ejemplo:
            >>> new_user = await UserService.create("Ana Pérez", "ana@ejemplo.com")
            >>> if new_user:
            ...     print(new_user.id)
            ... else:
            ...     print("Error al crear usuario")
        """
        return await User.create(name=name, email=email)

    @staticmethod
    async def get_by_email(email: str):
        from src.models import User
        return await User.filter(email=email).first()
