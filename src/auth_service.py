"""Auth service using FastAPI"""

import uuid
from datetime import datetime
from typing import Optional

import jwt
import uvicorn
from fastapi import FastAPI, Depends, HTTPException, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from passlib.context import CryptContext
from sqlalchemy import or_, and_, func
from sqlalchemy.orm import Session

from src.data.models import (
    User, UserCreate, UserLogin, UserUpdate,
    Student, StudentUpdate, engine
)

from src.data.config import SECRET_KEY, ALGORITHM, API_HOST, API_PORT_AUTH_SERVICE

PWD_CONTEXT = CryptContext(schemes=["bcrypt"], deprecated="auto")
SESSION_LOCAL = Session(bind=engine, autoflush=False, autocommit=False)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def custom_openapi():
    """Function to generate custom swagger."""
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="Auth service API",
        version="1.0.0",
        description="API для авторизации и управления пользователями",
        routes=app.routes,
    )
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT"
        }
    }
    for path in openapi_schema["paths"].values():
        for operation in path.values():
            operation.setdefault("security", []).append({"BearerAuth": []})
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi


def get_db():
    """Dependency for DB session."""
    db = SESSION_LOCAL
    try:
        yield db
    finally:
        db.close()


def hash_password(password: str) -> str:
    """Hash the given password."""
    return PWD_CONTEXT.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return PWD_CONTEXT.verify(plain_password, hashed_password)


def create_access_token(data: dict) -> str:
    """Create a JWT token."""
    to_encode = data.copy()
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token_to_decode: str) -> Optional[str]:
    """Decode a JWT token."""
    try:
        payload = jwt.decode(token_to_decode, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("user_id")
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(status_code=401, detail="Token expired") from exc
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc


def get_current_user(
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db)
) -> User:
    """Dependency to get current authenticated user."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid token")

    access_token = authorization.split("Bearer ")[-1]
    user_id = decode_token(access_token)
    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    if not user.in_system:
        raise HTTPException(status_code=403, detail="Unauthorised")

    return user


def calculate_course_from_group(
    group_number: str,
    current_year: Optional[int] = None
) -> Optional[int]:
    """Calculate course from group number."""
    if not group_number or len(group_number) < 4:
        return None

    try:
        admission_year = int(group_number[2:4])
        current_year = current_year or datetime.now().year
        course = (current_year % 100) - admission_year
        return course if 1 <= course <= 6 else None
    except (ValueError, TypeError):
        return None


@app.post("/register/")
async def register(user_data: UserCreate, db: Session = Depends(get_db)):
    """Register a new user."""
    if db.query(User).filter(User.email == user_data.email).first():
        raise HTTPException(status_code=400, detail="User with this email already exists")

    user_id = str(uuid.uuid4())
    hashed_pw = hash_password(user_data.password)

    db_user = User(
        id=user_id,
        email=user_data.email,
        password=hashed_pw,
        name=user_data.name,
        tag=user_data.tag,
        roles=user_data.roles,
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    if 'student' in user_data.roles:
        db_student = Student(id=user_id, name=user_data.name)
        db.add(db_student)
        db.commit()
        db.refresh(db_student)

    access_token = create_access_token({"user_id": db_user.id, "roles": db_user.roles})
    return {"msg": "User created", "token": access_token}


@app.post("/login/")
async def login(user_data: UserLogin, db: Session = Depends(get_db)):
    """User login endpoint."""
    user = db.query(User).filter(User.email == user_data.email).first()

    if not user or not verify_password(user_data.password, user.password):
        raise HTTPException(status_code=400, detail="Invalid data")

    user.token = create_access_token({"user_id": user.id})
    user.in_system = True
    db.commit()
    db.refresh(user)

    return {"msg": "Success", "token": user.token}


@app.post("/logout/")
async def logout(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Log out user."""
    user.in_system = False
    db.commit()
    return {"msg": "Success"}


@app.get("/token/")
async def token(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Get token status."""
    user_db = db.query(User).filter(User.id == user.id).first()
    if not user_db.in_system:
        raise HTTPException(status_code=403, detail="Unauthorised")
    return {"status_code": 200, "user_id": user_db.id}


@app.get("/profile/")
async def profile(user: User = Depends(get_current_user)):
    """Get user profile."""
    return {
        "email": user.email,
        "id": user.id,
        "tag": user.tag,
        "name": user.name,
        "roles": user.roles
    }


@app.put("/profile/")
async def update_profile(
    updated_data: UserUpdate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update user profile."""
    user_db = db.query(User).filter(User.id == user.id).first()
    if not user_db or not user_db.in_system:
        raise HTTPException(status_code=403, detail="Unauthorised")

    if updated_data.name is not None:
        user_db.name = updated_data.name
    if updated_data.tag is not None:
        user_db.tag = updated_data.tag
    if updated_data.email is not None:
        existing_user = db.query(User).filter(
            User.email == updated_data.email, User.id != user.id
        ).first()
        if existing_user:
            raise HTTPException(status_code=400, detail="Email already registered")
        user_db.email = updated_data.email

    if updated_data.roles is not None:
        prev_roles = set(user_db.roles or [])
        new_roles = set(updated_data.roles)
        user_db.roles = updated_data.roles

        if 'student' in prev_roles and 'student' not in new_roles:
            student_db = db.query(Student).filter(Student.id == user.id).first()
            if student_db:
                db.delete(student_db)
        elif 'student' not in prev_roles and 'student' in new_roles:
            existing = db.query(Student).filter(Student.id == user.id).first()
            if not existing:
                db.add(Student(id=user.id, name=user_db.name))

    db.commit()
    db.refresh(user_db)

    return {
        "msg": "Profile updated",
        "user": {
            "email": user_db.email,
            "id": user_db.id,
            "tag": user_db.tag,
            "name": user_db.name,
            "roles": user_db.roles
        }
    }


@app.put("/students_update/{student_id}")
async def update_students_profile(
    updated_data: StudentUpdate,
    student_id: str,
    db: Session = Depends(get_db)
):
    """Update student profile by ID."""
    student_db = db.query(Student).filter(Student.id == student_id).first()
    if not student_db:
        raise HTTPException(status_code=404, detail="Student not found")

    for field, value in updated_data.dict(exclude_unset=True).items():
        setattr(student_db, field, value)

    db.commit()
    db.refresh(student_db)

    return {"msg": "Profile updated!", "student": student_db}


@app.get("/students/")
async def get_students(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    course: Optional[str] = Query(None),
    name: Optional[str] = None,
    group: Optional[str] = Query(None),
    skip: int = 0,
    limit: int = 10
):
    """Retrieve students with optional filters."""
    query = db.query(Student)

    if name:
        query = query.filter(Student.name.ilike(f"%{name}%"))

    if group:
        group_ids = [int(g.strip()) for g in group.split(",") if g.strip().isdigit()]
        if group_ids:
            query = query.filter(Student.group.in_(group_ids))

    if course:
        course_ids = [int(c.strip()) for c in course.split(",") if c.strip().isdigit()]
        year_now = datetime.now().year % 100
        if course_ids:
            course_filters = [
                and_(
                    func.substr(Student.group, 3, 2) == f"{year_now - c:02d}",
                    func.length(Student.group) >= 4
                )
                for c in course_ids
            ]
            query = query.filter(or_(*course_filters))

    total = query.count()
    students = query.offset(skip).limit(limit).all()

    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "data": students,
        "curr_user_id": user.id
    }


if __name__ == "__main__":
    uvicorn.run(app, host=API_HOST, port=API_PORT_AUTH_SERVICE)
