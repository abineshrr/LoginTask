from datetime import timedelta, datetime, date
from typing_extensions import Annotated
from uuid import uuid4
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from fastapi import FastAPI, Depends, HTTPException, Form
from pydantic import BaseModel, EmailStr, validator
from sqlalchemy.orm import Session
from starlette import status
import models
from models import UserInput, AccessToken, RefreshToken
from database import engine, SessionLocal
from passlib.context import CryptContext
from jose import jwt, JWTError

from Crypto.Util.Padding import unpad, pad
from Crypto.Cipher import AES
from cryptography.fernet import Fernet
import base64

app = FastAPI()

origins = ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

session = SessionLocal()

SECRET_KEY = '12nhd45et674r567tfg657yh8jdg75wcj32ki9865d656tf536kjl87tf654'
ALGORITHM = 'HS256'

models.Base.metadata.create_all(bind=engine)

bcrypt_context = CryptContext(schemes='bcrypt', deprecated='auto')
oauth2_bearer = OAuth2PasswordBearer(tokenUrl='/token')


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def encrypt_password(passwrd: str):
    encryption_key = '22eeab4fe24a3d7fb40874b3a40c8271'
    password = passwrd.encode()

    # Pad the password to make it a multiple of the block size
    padded_password = pad(password, AES.block_size)

    cipher = AES.new(encryption_key.encode(), AES.MODE_ECB)
    encrypted_password = cipher.encrypt(padded_password)
    encoded_password = base64.b64encode(encrypted_password).decode()
    return encoded_password

# def decrypt_data(encrypted_data: str):
#     encryption_key = "22eeab4fe24a3d7fb40874b3a40c8271"
#     encrypted_data = base64.b64decode(encrypted_data)
#     cipher = AES.new(encryption_key.encode(), AES.MODE_ECB)
#     decrypted_data = cipher.decrypt(encrypted_data)
#     decrypted_data = unpad(decrypted_data, AES.block_size).decode()
#     return decrypted_data

def decrypt_data(encrypted_data: str):
    encryption_key = base64.urlsafe_b64decode(b'Q4bOALstbrq0hdvukj5fdz8xR9V-J-w_yWuGYX8vCuU=')
    cipher_suite = Fernet(encryption_key)
    decrypted_data = cipher_suite.decrypt(encrypted_data.encode()).decode()
    return decrypted_data

def authenticate_user(username_or_email: str, password: str, db):
    user = db.query(UserInput).filter((UserInput.username == username_or_email) | (UserInput.email == username_or_email)).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail='Could not validate user.')
    if not bcrypt_context.verify(password, user.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail='Incorrect password.')
    return user


def create_tokens(username: str, user_id: int, expires_delta: timedelta, refresh_delta: timedelta):
    encode = {'sub': username, 'id': user_id}
    expires = datetime.utcnow() + expires_delta
    encode.update({'exp': expires})
    access_token = jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)

    refresh_expires = datetime.utcnow() + refresh_delta
    encode.update({'exp': refresh_expires})
    refresh_token = jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)

    return access_token, refresh_token


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
    reg_no: str = Form(...)
    age: int = Form(...)
    dob: date = Form(...)
    gender: str = Form(...)
    username: str = Form(..., min_length=4, max_length=20)
    email: EmailStr = Form(...)
    phonenumber: str = Form(...)
    password: str = Form(...)
    confirm_password: str = Form(...)

    @validator('password')
    def password_must_be_strong(cls, value):
        if not (8 <= len(value) <= 50):
            raise ValueError('Password must be between 8 and 50 characters long')
        return value

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str
    message: str

class LoginRequest(BaseModel):
    username_or_email: str
    password: str

class ChangePassword(BaseModel):
    username_or_email: str = Form(...)
    new_password: str = Form(...)
    confirm_password: str = Form(...)

    @validator('username_or_email')
    def username_or_email_must_be_valid(cls, value):
        if '@' in value:
            email = EmailStr(value)
            return email
        else:
            if not (4 <= len(value) <= 20):
                raise ValueError('Username must be between 4 and 20 characters long')
            return value

    @validator('new_password')
    def password_must_be_strong(cls, value):
        if not (8 <= len(value) <= 50):
            raise ValueError('Password must be between 8 and 50 characters long')
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
        reg_no=user_request.reg_no,
        age=user_request.age,
        dob=user_request.dob,
        gender=user_request.gender,
        username=user_request.username,
        email=user_request.email,
        phonenumber=user_request.phonenumber,
        password=bcrypt_context.hash(user_request.password)
    )
    db.add(user_data)
    db.commit()
    db.refresh(user_data)
    return {"message": "User created successfully"}


@app.post("/login", response_model=Token)
async def login_user(login_request: LoginRequest,
                     db: db_dependency):
    decryptedpassword = decrypt_data(login_request.password)
    decryptedusername = decrypt_data(login_request.username_or_email)
    user = authenticate_user(decryptedusername, decryptedpassword, db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail='Could not validate user.')
    access_token, refresh_token = create_tokens(user.username, user.id, timedelta(minutes=60), timedelta(days=7))

    access_token_id = str(uuid4())
    refresh_token_id = str(uuid4())
    accesstoken = AccessToken(
        id=access_token_id,
        token=access_token
    )
    db.add(accesstoken)
    db.commit()

    refreshtoken = RefreshToken(
        id=refresh_token_id,
        token=refresh_token,
        accesstoken_id=access_token_id
    )
    db.add(refreshtoken)
    db.commit()

    return {'access_token': access_token, 'refresh_token': refresh_token, 'token_type': 'bearer', 'message': 'Login successful!'}



@app.put('/change_user_password')
async def change_user_password(change_password: ChangePassword, db: db_dependency):
    user = db.query(UserInput).filter((UserInput.email == change_password.username_or_email) |
                                      (UserInput.username == change_password.username_or_email)).first()
    if not user:
        raise HTTPException(status_code=404, detail='User not found')
    if change_password.new_password != change_password.confirm_password:
        raise HTTPException(status_code=400, detail="New password and confirm password should be same")
    new_password_hashed = bcrypt_context.hash(change_password.new_password)
    user.password = new_password_hashed
    db.commit()
    return {'message': 'Password changed successfully'}


@app.get("/get_all_users")
async def read_all(user: user_dependency, db: db_dependency):
    if user is None:
        raise HTTPException(status_code=401, detail='Authentication failed.')
    return db.query(UserInput).all()

@app.get("/get_all_user")
async def read_all(db: db_dependency):
    return db.query(RefreshToken).all()


@app.delete('/delete_user/{user_id}')
async def delete_user(user_id:int, db:db_dependency):
    user = db.query(UserInput).filter(UserInput.id == user_id).first()
    db.delete(user)
    db.commit()
    return {'message': 'User deleted successfully'}


users = session.query(UserInput).all()
user_list = [{"id": user.id, "first name": user.first_name, "last name": user.last_name, "reg no": user.reg_no, "age": user.age, "dob": user.dob, "gender": user.gender, "username": user.username, "email": user.email, "phone number": user.phonenumber} for user in users]

@app.get("/users_list/")
def get_users(page: int, per_page: int):
    start_index = (page - 1) * per_page
    end_index = start_index + per_page
    return user_list[start_index:end_index]

@app.get('/encrpyt')
def ennrypt_password(password: str):
    encrypted_password = encrypt_password(password)
    return encrypted_password

@app.get('/decrpyt')
def deecrypt_password(password: str):
    decrypted_password = decrypt_data(password)
    return decrypted_password