from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Text, List
from sqlalchemy.sql import func
from sqlalchemy.ext.declarative import declarative_base
from pydantic import BaseModel
from typing import Optional

from config import *

Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(Text, primary_key=True)
    token = Column(Text)
    name = Column(String(50))
    email = Column(String(40))
    password = Column(Text)
    tag = Column(String(30))
    roles = Column(String(50))
    in_system = Column(Boolean, default=True, nullable=False)


class UserCreate(BaseModel):
    email: str
    password: str
    name: str
    tag: str
    roles: str


class UserLogin(BaseModel):
    email: str
    password: str


engine = create_engine(DATABASE_URL)

Base.metadata.create_all(bind=engine)
