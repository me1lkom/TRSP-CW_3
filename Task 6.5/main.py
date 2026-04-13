from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from security import (
    create_jwt_token,
    get_current_user_from_token,
    authenticate_user,
    get_password_hash
)
from models import User, Token, UserInDB
from db import get_user, create_user, user_exists

app = FastAPI()

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.post("/register", status_code=status.HTTP_201_CREATED)
@limiter.limit("1/minute")  # ограничение на 1 запрос в минуту
def register(request: Request, user: User):

    if user_exists(user.username):
        raise HTTPException(
            status_code=status.HTTP_409_BAD_REQUEST,
            detail="Username already registered"
        )
    
    hashed_password = get_password_hash(user.password)
    
    user_in_db = UserInDB(
        username=user.username,
        hashed_password=hashed_password
    )
    create_user(user_in_db)
    
    return {"message": f"User {user.username} created"}



@app.post("/login", response_model=Token)
@limiter.limit("5/minute")  # ограничение на 5 запросов в минуту
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):

    # проверяем существует ли пользователь
    user_from_db = get_user(form_data.username)
    if not user_from_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # проверяем учётные данные
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # генерируем токен с username
    token = create_jwt_token({"sub": user.username})
    
    return {"access_token": token, "token_type": "bearer"}

@app.get("/protected_resource")
async def protected_resource(current_user=Depends(get_current_user_from_token)):

    return {
        "message": "You have access to the protected resource!",
        "user": {
            "username": current_user.username
        }
    }

@app.get("/")
async def root():
    return {"message": "Welcome to JWT Auth API with Rate Limiting"}