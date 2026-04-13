from fastapi import FastAPI, status, HTTPException
from fastapi.security import HTTPBasic
from models import User

from database import get_db_connection, create_db

app = FastAPI()
security = HTTPBasic()



@app.post("/register", status_code=status.HTTP_201_CREATED)
def register(user: User):
    create_db()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT id FROM users WHERE username = ?", (user.username,))
    existing_user = cursor.fetchone()
    
    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (user.username, user.password))
    conn.commit()
    conn.close()
    
    return {"message": "User registered successfully!"}