from fastapi import FastAPI, Depends, HTTPException, Header
from sqlalchemy.orm import Session, sessionmaker
from fastapi.middleware.cors import CORSMiddleware
from passlib.context import CryptContext
import uuid
import uvicorn
import secrets
from models import *

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_current_user(authorization: str = Header(None), db: Session = Depends(get_db)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Токен отсутствует или некорректен")
    token = authorization.split("Bearer ")[-1]
    user = db.query(User).filter(User.token == token).first()
    if not user:
        raise HTTPException(status_code=401, detail="Некорректный токен")
    if not user.in_system:
        raise HTTPException(status_code=403, detail="Пользователь не в системе")
    return user


@app.post("/register/")
async def register(user: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(status_code=400, detail="Пользователь с такой почтой уже зарегистрирован")

    user_id = str(uuid.uuid4())
    db_user = User(
        token=secrets.token_hex(32),
        id=user_id,
        email=user.email,
        password=hash_password(user.password),
        name=user.name,
        tag=user.tag,
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    return {"msg": "Пользователь успешно создан", "token": db_user.token}


@app.post("/login/")
async def login(user: UserLogin, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.email == user.email).first()
    if not existing_user or not verify_password(user.password, existing_user.password):
        raise HTTPException(status_code=400, detail="Неверные учетные данные")

    existing_user.token = secrets.token_hex(32)
    existing_user.in_system = True
    db.commit()
    db.refresh(existing_user)

    return {"msg": "Успешный вход", "token": existing_user.token}


@app.post("/logout/")
async def logout(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    user.in_system = False
    db.commit()
    return {"msg": "Успешный выход"}


@app.get("/token/")
async def token(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    user_db = db.query(User).filter(User.token == user.token).first()
    if not user_db:
        raise HTTPException(status_code=401, detail="Некорректный токен")
    if not user_db.in_system:
        raise HTTPException(status_code=403, detail="Пользователь не в системе")
    return {"status_code": 200, "user_id": user_db.id}


@app.get("/profile/")
async def profile(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    user_db = db.query(User).filter(User.token == user.token).first()
    if not user_db:
        raise HTTPException(status_code=401, detail="Некорректный токен")
    if not user_db.in_system:
        raise HTTPException(status_code=403, detail="Пользователь не в системе")
    return_data = {
        "email": user.email,
        "id": user.id,
        "tag": user.tag,
        "name": user.name,
    }
    return return_data



if __name__ == "__main__":
    uvicorn.run(app, host=API_HOST, port=API_PORT)
