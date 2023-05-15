from datetime import timedelta, datetime, date
from typing_extensions import Annotated
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from fastapi import FastAPI, Depends, HTTPException, Form
from pydantic import BaseModel, EmailStr, validator
from sqlalchemy.orm import Session
from starlette import status
import models
from models import UserInput
from database import engine, SessionLocal
from passlib.context import CryptContext
from jose import jwt, JWTError

app = FastAPI()

origins = ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = '12nhd45et674r567tfg657yh8jdg75wcj32ki9865d656tf536kjl87tf654'
ALGORITHM = 'HS256'

models.Base.metadata.create_all(bind=engine)

bcrypt_context = CryptContext(schemes='bcrypt', deprecated='auto')
oauth2_bearer = OAuth2PasswordBearer(tokenUrl='token')


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def authenticate_user(username: str, password: str, db):
    user = db.query(UserInput).filter((UserInput.username == username) | (UserInput.email == username)).first()
    if not user:
        return False
    if not bcrypt_context.verify(password, user.password):
        return False
    return user


def create_access_token(username: str, user_id: int, expires_delta: timedelta):
    encode = {'sub': username, 'id': user_id}
    expires = datetime.utcnow() + expires_delta
    encode.update({'exp': expires})
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(token: Annotated[str, Depends(oauth2_bearer)]):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get('sub')
        user_id: int = payload.get('id')
        if username is None or user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail='Could not validate user.')
        return {'username': username, 'id': user_id}
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail='Could not validate user.')


db_dependency = Annotated[Session, Depends(get_db)]
user_dependency = Annotated[dict, Depends(get_current_user)]


class UserRequest(BaseModel):
    first_name: str = Form(...)
    last_name: str = Form(...)
    age: int = Form(..., ge=15)
    dob: date = Form(...)
    gender: str = Form(...)
    username: str = Form(..., min_length=4, max_length=20, regex="^[a-zA-Z0-9_-]+$")
    email: EmailStr = Form(...)
    password: str = Form(...)
    confirm_password: str = Form(...)

    @validator('username')
    def username_must_be_valid(cls, value):
        if not (4 <= len(value) <= 20):
            raise ValueError('Username must be between 4 and 20 characters long')
        if not value.isalnum():
            raise ValueError('Username must contain only alphanumeric characters')
        return value

    @validator('password')
    def password_must_be_strong(cls, value):
        if not (8 <= len(value) <= 50):
            raise ValueError('Password must be between 8 and 50 characters long')
        if not any(c.isupper() for c in value):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in value):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in value):
            raise ValueError('Password must contain at least one digit')
        return value


class Token(BaseModel):
    access_token: str
    token_type: str


class ChangePassword(BaseModel):
    username_or_email: str = Form(...)
    current_password: str = Form(...)
    new_password: str = Form(...)

    @validator('username_or_email')
    def username_or_email_must_be_valid(cls, value):
        if '@' in value:
            email = EmailStr(value)
            return email
        else:
            # value is a username
            if not (4 <= len(value) <= 20):
                raise ValueError('Username must be between 4 and 20 characters long')
            if not value.isalnum():
                raise ValueError('Username must contain only alphanumeric characters')
            return value

    @validator('new_password')
    def password_must_be_strong(cls, value):
        if not (8 <= len(value) <= 50):
            raise ValueError('Password must be between 8 and 50 characters long')
        if not any(c.isupper() for c in value):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in value):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in value):
            raise ValueError('Password must contain at least one digit')
        return value


@app.post("/register", status_code=status.HTTP_201_CREATED)
async def register_user(db: db_dependency,
                        user_request: UserRequest):
    if db.query(UserInput).filter(UserInput.username == user_request.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    if db.query(UserInput).filter(UserInput.email == user_request.email).first():
        raise HTTPException(status_code=400, detail="Email already exists")
    if user_request.password != user_request.confirm_password:
        raise HTTPException(status_code=400, detail="Password and confirm password should be same")
    user_data = UserInput(
        first_name=user_request.first_name,
        last_name=user_request.last_name,
        age=user_request.age,
        dob=user_request.dob,
        gender=user_request.gender,
        username=user_request.username,
        email=user_request.email,
        password=bcrypt_context.hash(user_request.password)
    )
    db.add(user_data)
    db.commit()
    db.refresh(user_data)
    return {"message": "User created successfully"}


@app.post("/login", response_model=Token)
async def login_user(form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
                     db: db_dependency):
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail='Could not validate user.')
    token = create_access_token(user.username, user.id, timedelta(minutes=20))
    return {'access_token': token, 'token_type': 'bearer', "message": "Login successful!"}


@app.put('/change_user_password')
async def change_user_password(change_password: ChangePassword, db: db_dependency):
    user = db.query(UserInput).filter((UserInput.email == change_password.username_or_email) |
                                      (UserInput.username == change_password.username_or_email)).first()
    if not user:
        raise HTTPException(status_code=404, detail='User not found')
    if not bcrypt_context.verify(change_password.current_password, user.password):
        raise HTTPException(status_code=400, detail='Incorrect password')
    new_password_hashed = bcrypt_context.hash(change_password.new_password)
    user.password = new_password_hashed
    db.commit()
    return {'message': 'Password changed successfully'}


@app.get("/get_all_users")
async def read_all(db: db_dependency):
    return db.query(UserInput).all()
