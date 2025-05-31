from sqlalchemy import create_engine, Column, String, Boolean, Text, JSON, Integer
from sqlalchemy.ext.declarative import declarative_base
from pydantic import BaseModel, EmailStr
from typing import Optional, List

from src.data.config import *

Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(Text, primary_key=True)
    name = Column(String(50))
    email = Column(String(40))
    password = Column(Text)
    tag = Column(String(30))
    roles = Column(JSON, default=list)
    in_system = Column(Boolean, default=True, nullable=False)


class Student(Base):
    __tablename__ = "students"
    id = Column(Text, primary_key=True)
    name = Column(String(50))
    group = Column(String(50))
    direction = Column(String(50))
    stack = Column(String(50))
    applications_count = Column(Integer)
    status = Column(String(50))
    score = Column(Integer)
    current_score = Column(Integer)


class UserCreate(BaseModel):
    email: EmailStr
    password: str
    name: str
    tag: str
    roles: List[str]


class UserUpdate(BaseModel):
    name: Optional[str] = None
    tag: Optional[str] = None
    email: Optional[EmailStr] = None
    roles: Optional[List[str]] = None


class StudentUpdate(BaseModel):
    name: Optional[str] = None
    group: Optional[str] = None
    direction: Optional[str] = None
    stack: Optional[str] = None
    applications_count: Optional[int] = None
    status: Optional[str] = None
    score: Optional[int] = None
    current_score: Optional[int] = None


class UserLogin(BaseModel):
    email: str
    password: str


engine = create_engine(DATABASE_URL)

Base.metadata.create_all(bind=engine)
