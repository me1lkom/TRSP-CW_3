from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

from security import (
    create_jwt_token,
    authenticate_user,
    get_password_hash
)
from models import User, Token, UserInDB
from db import get_user, create_user, user_exists
from dependencies import get_current_user
from rbac import PermissionChecker

app = FastAPI(title="RBAC API")

@app.post("/register", status_code=status.HTTP_201_CREATED)
def register(user: User):
    if user_exists(user.username):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User already exists"
        )
    
    hashed_password = get_password_hash(user.password)
    
    user_in_db = UserInDB(
        username=user.username,
        hashed_password=hashed_password,
        roles=user.roles
    )
    create_user(user_in_db)
    
    return {"message": "New user created"}

@app.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user_from_db = get_user(form_data.username)
    if not user_from_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization failed",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # в токен кладем username и роли
    token = create_jwt_token({
        "sub": user.username,
        "roles": user.roles
    })
    
    return {"access_token": token, "token_type": "bearer"}

@app.get("/protected_resource")
@PermissionChecker(["admin"])
async def protected_resource(current_user=Depends(get_current_user)):
    return {"message": f"Admin access granted for {current_user.username}"}

@app.get("/user")
@PermissionChecker(["user"])
async def user_info(current_user=Depends(get_current_user)):
    return {"message": f"User access granted for {current_user.username}"}

@app.get("/about_me")
async def about_me(current_user=Depends(get_current_user)):
    return {
        "username": current_user.username,
        "roles": current_user.roles
    }

@app.get("/")
async def root():
    return {"message": "Welcome to RBAC API"}