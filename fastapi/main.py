import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from typing import List, Annotated

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from pwdlib import PasswordHash

from db.database import SessionLocal, User
import schemas

password_hash = PasswordHash.recommended()

app = FastAPI(title="FastAPI Backend Service")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return password_hash.verify(plain_password, hashed_password)
def hash_password(plain_password: str) -> str:
    return password_hash.hash(plain_password)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="v1/token")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Root endpoint Hello World
@app.get("/")
def read_root():
    return {"Hello": "World"}

# 'singin' endpoint
@app.post('/v1/users/', response_model=schemas.UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    hashed_password = hash_password(user.password)
    
    db_user = User(username=user.username, 
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

# 'Login' endpoint
@app.post('/v1/token/')
def login(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()], 
    db: Session = Depends(get_db)
):
    # 1. Treat the 'username' from the form_data as the user's email
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"})
    # set up token creation logic here
    return {"access_token": f'{user.username}.token', "token_type": "bearer"}

# List users/'elements of the table' endpoint
@app.get('/v1/users/', response_model=List[schemas.UserResponse])
def list_users(db: Session = Depends(get_db)):
    users = db.query(User).all()
    return users

# GET user/'element' by ID endpoint
@app.get('/v1/users/{user_id}', response_model=schemas.UserResponse)
def get_user(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user

# protected route example
@app.get('/v1/protected/')
def protected_route(token: Annotated[str, Depends(oauth2_scheme)]):
    return {"message": "This is a protected route", "token": token}