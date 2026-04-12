import secrets
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from passlib.context import CryptContext
from models import User, UserInDB

app = FastAPI()
security = HTTPBasic()

# настройка хеширования паролей 
pwd_context = CryptContext(schemes=["bcrypt"])

fake_users_db = {}

def auth_user(credentials: HTTPBasicCredentials = Depends(security)):
    username = credentials.username
    password = credentials.password
    
    # ищем пользователя в бд
    user = fake_users_db.get(username)
    
    # защита от тайминг-атак. если пользователя нет в бд, всё равно делаем проверку пароля
    if user is None:
        secrets.compare_digest(password, "")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    
    # проверяем пароль
    if not pwd_context.verify(password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    
    return user

@app.post("/register", status_code=status.HTTP_201_CREATED)
def register(user: User):
    # проверяем, есть ли пользоватеть в бд с таким ником
    if user.username in fake_users_db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )
    
    # хешируем пароль
    hashed_password = pwd_context.hash(user.password)
    
    # создаем объект для хранения в бд
    user_in_db = UserInDB(
        username=user.username,
        hashed_password=hashed_password
    )
    
    # сохраняем в бд
    fake_users_db[user.username] = user_in_db
    
    return {"message": "User registered successfully"}

@app.get("/login")
def login(user: UserInDB = Depends(auth_user)):
    return {"message": f"Welcome, {user.username}!"}