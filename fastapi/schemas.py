from typing import List
from pydantic import BaseModel, EmailStr


class UserCreate(BaseModel):
    email: EmailStr
    username: str
    password: str # This will be HASHED before saving to the DB

class UserResponse(BaseModel):
    id: int
    email: EmailStr
    username: str    
    
    class Config:
        from_attributes = True    

class UserList(BaseModel):
    users: List[UserResponse]