import datetime
from jose import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext

from db import get_user

import os
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "mysecretkey")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
ALGORITHM = "HS256"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

# извлекаем токен из заголовка и указываем где пользователь получает токен
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def create_jwt_token(data):
    to_encode = data.copy() # копируем данные, чтобы не изменить исходный словарь
    
    # задаём и добавляем время когда токен потухнет
    expire = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    # кодируем токен с использованием секретного ключа и алгоритма
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user_from_token(token: str = Depends(oauth2_scheme)):
    
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        # декодируем токен с помощью секретного ключа
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        # roles = payload.get("roles")
        if username is None:
            raise credentials_exception
    except jwt.JWTError:
        raise credentials_exception
    
    
    # ищем пользователя в БД
    user = get_user(username)
    if user is None:
        raise credentials_exception
    return user

def authenticate_user(username, password):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user
