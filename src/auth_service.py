from fastapi import FastAPI, Depends, HTTPException, Header, Query
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy import or_, and_, func, extract
from fastapi.middleware.cors import CORSMiddleware
from passlib.context import CryptContext
import uuid
import uvicorn
import jwt
from src.data.models import *
from datetime import datetime

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


def create_access_token(data: dict):
    to_encode = data.copy()
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token_to_decode: str):
    try:
        payload = jwt.decode(token_to_decode, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("user_id")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")


def get_current_user(authorization: str = Header(None), db: Session = Depends(get_db)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid token")
    token_from_request = authorization.split("Bearer ")[-1]
    decoded_token = decode_token(token_from_request)
    user = db.query(User).filter(decoded_token == User.id).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    if not user.in_system:
        raise HTTPException(status_code=403, detail="Unauthorised")
    return user


def calculate_course_from_group(group_number: str, current_year: int = None) -> int:
    """
    Вычисляет курс на основе номера группы.
    Группа: 972202 → 3-4 цифры (22) - год поступления
    Текущий год: 2025 → курс = 25 - 22 = 3
    """
    if not group_number or len(group_number) < 4:
        return None

    try:
        admission_year = int(group_number[2:4])
        current_year = current_year or datetime.now().year
        current_short_year = current_year % 100
        course = current_short_year - admission_year

        # Проверяем, что курс получился разумным (от 1 до 6 обычно)
        return course if 1 <= course <= 6 else None
    except (ValueError, TypeError):
        return None


@app.post("/register/")
async def register(user: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(user.email == User.email).first():
        raise HTTPException(status_code=400, detail="User with this email already exists")

    user_id = str(uuid.uuid4())
    db_user = User(
        id=user_id,
        email=user.email,
        password=hash_password(user.password),
        name=user.name,
        tag=user.tag,
        roles=user.roles,
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    token_to_return = create_access_token(data={"user_id": db_user.id, "roles": db_user.roles})
    if 'student' in user.roles:
        db_student = Student(
            id=user_id,
            name=user.name,
        )
        db.add(db_student)
        db.commit()
        db.refresh(db_student)
    return {"msg": "User created", "token": token_to_return}


@app.post("/login/")
async def login(user: UserLogin, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.email == user.email).first()
    if not existing_user or not verify_password(user.password, existing_user.password):
        raise HTTPException(status_code=400, detail="Invalid data")

    existing_user.token = create_access_token(data={"user_id": existing_user.id})
    existing_user.in_system = True
    db.commit()
    db.refresh(existing_user)

    return {"msg": "Success", "token": existing_user.token}


@app.post("/logout/")
async def logout(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    user.in_system = False
    db.commit()
    return {"msg": "Success"}


@app.get("/token/")
async def token(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    user_db = db.query(User).filter(User.id == user.id).first()
    if not user_db.in_system:
        raise HTTPException(status_code=403, detail="Unauthorised")
    return {"status_code": 200, "user_id": user_db.id}


@app.get("/profile/")
async def profile(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    user_db = db.query(User).filter(User.id == user.id).first()
    if not user_db.in_system:
        raise HTTPException(status_code=403, detail="Unauthorised")
    return_data = {
        "email": user.email,
        "id": user.id,
        "tag": user.tag,
        "name": user.name,
        "roles": user.roles
    }
    return return_data


@app.put("/profile/")
async def update_profile(
    updated_data: UserUpdate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user_db = db.query(User).filter(User.id == user.id).first()

    if not user_db or not user_db.in_system:
        raise HTTPException(status_code=403, detail="Unauthorised")

    if updated_data.name is not None:
        user_db.name = updated_data.name

    if updated_data.tag is not None:
        user_db.tag = updated_data.tag

    if updated_data.roles is not None:
        user_db.roles = updated_data.roles

    if updated_data.email is not None:
        existing_user = db.query(User).filter(User.email == updated_data.email, User.id != user.id).first()
        if existing_user:
            raise HTTPException(status_code=400, detail="Email already registered")
        user_db.email = updated_data.email

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
    student_id,
    db: Session = Depends(get_db)
):
    student_db = db.query(Student).filter(Student.id == student_id).first()

    if not student_db:
        raise HTTPException(status_code=404, detail="Student not found")

    if updated_data.name is not None:
        student_db.name = updated_data.name

    if updated_data.group is not None:
        student_db.group = updated_data.group

    if updated_data.direction is not None:
        student_db.direction = updated_data.direction

    if updated_data.stack is not None:
        student_db.stack = updated_data.stack

    if updated_data.applications_count is not None:
        student_db.applications_count = updated_data.applications_count

    if updated_data.status is not None:
        student_db.status = updated_data.status

    if updated_data.score is not None:
        student_db.score = updated_data.score

    if updated_data.current_score is not None:
        student_db.current_score = updated_data.current_score

    db.commit()
    db.refresh(student_db)

    return {
        "msg": "Profile updated!",
        "student": {
            "id": student_db.id,
            "name": student_db.name,
            "group": student_db.group,
            "direction": student_db.direction,
            "stack": student_db.stack,
            "applications_count": student_db.applications_count,
            "status": student_db.status,
            "score": student_db.score,
            "current_score": student_db.current_score,
        }
    }


@app.get("/students/")
async def students(
        user: User = Depends(get_current_user),
        db: Session = Depends(get_db),
        course: Optional[str] = Query(None),
        name: Optional[str] = None,
        group: Optional[str] = Query(None),
        skip: int = 0,
        limit: int = 10
):
    query = db.query(Student)

    if name:
        query = query.filter(Student.name.ilike(f"%{name}%"))

    if group:
        groups_list = [int(group.strip()) for group in group.split(",") if group.strip().isdigit()]
        group_conditions = []
        for g in groups_list:
            group_conditions.append(
                and_(
                    Student.group == g,
                )
            )

        if group_conditions:
            query = query.filter(or_(*group_conditions))

    if course:
        courses_list = [int(course.strip()) for course in course.split(",") if course.strip().isdigit()]

        current_year = datetime.now().year
        course_conditions = []

        for c in courses_list:
            expected_admission_year = (current_year % 100) - int(c)
            course_conditions.append(
                and_(
                    func.substr(Student.group, 3, 2) == f"{expected_admission_year:02d}",
                    func.length(Student.group) >= 4
                )
            )

        if course_conditions:
            query = query.filter(or_(*course_conditions))

    total = query.count()

    students = query.offset(skip).limit(limit).all()

    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "data": students
    }


if __name__ == "__main__":
    uvicorn.run(app, host=API_HOST, port=API_PORT_AUTH_SERVICE)
