import os
from sqlalchemy import create_engine, Column, Integer, String, Boolean
from sqlalchemy.orm import sessionmaker, declarative_base

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SQLALCHEMY_DATABASE_URL = f"sqlite:///{BASE_DIR}/database.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    username = Column(String, index=True)    
    hashed_password = Column(String(255), nullable=False)
    disabled = Column(Boolean, default=False)

    def __repr__(self):
        return f"User(id={self.id}, email='{self.email}', username='{self.username}')"
    
def create_db_tables():
    Base.metadata.create_all(bind=engine)    
    