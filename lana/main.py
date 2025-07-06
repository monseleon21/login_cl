from fastapi import FastAPI, HTTPException
from schemas import UserCreate, UserOut
from auth import hash_password
from database import fake_users_db
from schemas import UserLogin, Token
from auth import verify_password, create_access_token, ACCESS_TOKEN_EXPIRE_MINUTES
from datetime import timedelta



app = FastAPI()

@app.post("/register", response_model=UserOut)
def register(user: UserCreate):
    if user.username in fake_users_db:
        raise HTTPException(status_code=400, detail="Usuario ya existe")
    
    hashed_password = hash_password(user.password)
    fake_users_db[user.username] = {"username": user.username, "password": hashed_password}
    return {"username": user.username}


@app.post("/login", response_model=Token)
def login(user: UserLogin):
    db_user = fake_users_db.get(user.username)
    
    if not db_user:
        raise HTTPException(status_code=400, detail="Usuario no encontrado")
    
    if not verify_password(user.password, db_user["password"]):
        raise HTTPException(status_code=400, detail="Contraseña incorrecta")

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, 
        expires_delta=access_token_expires
    )

    return {"access_token": access_token, "token_type": "bearer"}

