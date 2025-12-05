import sys
import os
import bcrypt #change for pwdlib as recommended in the fastapi docs

from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from typing import List

from db.database import SessionLocal, User
from . import schemas

app = FastAPI(title="FastAPI Backend Service")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.post('/v1/users/', response_model=schemas.UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    hashed_password = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt())
    
    db_user = User(name=user.username, 
                   email=user.email, 
                   hashed_password=hashed_password.decode('utf-8'))
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