from models import UserInDB

USERS_DB = {}

def get_user(username):
    return USERS_DB.get(username)

def create_user(user):
    USERS_DB[user.username] = user

def user_exists(username):
    return username in USERS_DB