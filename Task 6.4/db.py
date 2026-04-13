from models import UserInDB
from typing import Optional

USERS_DB: dict[str, UserInDB] = {}

def get_user(username: str) -> Optional[UserInDB]:
    return USERS_DB.get(username)

def create_user(user: UserInDB) -> None:
    USERS_DB[user.username] = user

def user_exists(username: str) -> bool:
    return username in USERS_DB