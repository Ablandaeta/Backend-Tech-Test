from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from pwdlib import PasswordHash
from typing import List

from db.database import SessionLocal, User
import schemas

password_hash = PasswordHash.recommended()

app = FastAPI(title="FastAPI Backend Service")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return password_hash.verify(plain_password, hashed_password)
def hash_password(plain_password: str) -> str:
    return password_hash.hash(plain_password)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.get("/")
def read_root():
    return {"Hello": "World"}

@app.post('/v1/users/', response_model=schemas.UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    hashed_password = hash_password(user.password)
    
    db_user = User(name=user.username, 
                   email=user.email, 
                   hashed_password=hashed_password)
    try:
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")
    return db_user

@app.get('/v1/users/', response_model=List[schemas.UserResponse])
def list_users(db: Session = Depends(get_db)):
    users = db.query(User).all()
    return users