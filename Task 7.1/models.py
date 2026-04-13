from pydantic import BaseModel

# добавляем список ролей
class User(BaseModel):
    username: str
    roles: list[str]
    password: str
    

class UserInDB(BaseModel):
    username: str
    roles: list[str]
    hashed_password: str

class Token(BaseModel):
    access_token: str
    token_type: str