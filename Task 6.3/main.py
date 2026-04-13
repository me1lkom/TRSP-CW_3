import secrets
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from passlib.context import CryptContext
from models import User, UserInDB
from config import MODE, DOCS_USER, DOCS_PASSWORD

# отключаем стандартную документацию, чтобы создать её самим с защитой
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

security = HTTPBasic()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

fake_users_db = {}

# защита документации
docs_security = HTTPBasic()

def auth_docs(credentials: HTTPBasicCredentials = Depends(docs_security)):
    username = credentials.username
    password = credentials.password
    
    username_valid = secrets.compare_digest(username, DOCS_USER)
    password_valid = secrets.compare_digest(password, DOCS_PASSWORD)
    
    if not (username_valid and password_valid):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return username

# создаём эндпоинты документации, зависимые от режима. в режиме PROD их просто не будет существовать
if MODE == "DEV":
    from fastapi.openapi.docs import get_swagger_ui_html
    from fastapi.openapi.utils import get_openapi
    
    @app.get("/docs", include_in_schema=False)
    async def get_swagger_documentation(username: str = Depends(auth_docs)):
        return get_swagger_ui_html(openapi_url="/openapi.json", title="API Docs")
    
    @app.get("/openapi.json", include_in_schema=False)
    async def get_openapi_json(username: str = Depends(auth_docs)):
        return get_openapi(title="My API", version="1.0", routes=app.routes)
    



# аутентификация пользователя 
def auth_user(credentials: HTTPBasicCredentials = Depends(security)):
    username = credentials.username
    password = credentials.password
    
    user = fake_users_db.get(username)
    
    if user is None:
        secrets.compare_digest(password, "")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    
    if not pwd_context.verify(password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    
    return user

@app.post("/register", status_code=status.HTTP_201_CREATED)
def register(user: User):
    if user.username in fake_users_db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )
    
    hashed_password = pwd_context.hash(user.password[:72])
    
    user_in_db = UserInDB(
        username=user.username,
        hashed_password=hashed_password
    )
    
    fake_users_db[user.username] = user_in_db
    
    return {"message": "User registered successfully"}

@app.get("/login")
def login(user: UserInDB = Depends(auth_user)):
    return {"message": f"Welcome, {user.username}!"}