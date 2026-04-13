from fastapi import HTTPException, status, Depends
from functools import wraps
from dependencies import get_current_user

class PermissionChecker:
    def __init__(self, allowed_roles: list[str]):
        self.allowed_roles = allowed_roles

    def __call__(self, func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # получаем current_user из kwargs
            current_user = kwargs.get("current_user")
            
            if not current_user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required"
                )
            
            # админ имеет доступ ко всему
            if "admin" in current_user.roles:
                return await func(*args, **kwargs)
            
            # проверяем есть ли у пользователя хотя бы одна разрешённая роль
            if not any(role in current_user.roles for role in self.allowed_roles):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Insufficient permissions"
                )
            
            return await func(*args, **kwargs)
        return wrapper