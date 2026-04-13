from fastapi import Depends, HTTPException, status
from security import get_current_user_from_token
from db import get_user
from models import User

def get_current_user(current_user_from_db: str = Depends(get_current_user_from_token)) -> User:
    user = User(
        username = current_user_from_db.username,
        password = "",
        roles=current_user_from_db.roles 
    )
    return user