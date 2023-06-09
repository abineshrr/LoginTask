from datetime import timedelta, datetime, date
from typing_extensions import Annotated

from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from fastapi import FastAPI, Depends, HTTPException, Form, Request, Response
from pydantic import BaseModel, EmailStr, validator
from sqlalchemy.orm import Session
from starlette import status
import models
from models import UserInput, Token
from database import engine, SessionLocal
from passlib.context import CryptContext
from jose import jwt, JWTError

from Crypto.Util.Padding import unpad, pad
from Crypto.Cipher import AES

from base64 import b64encode, b64decode
import binascii

app = FastAPI()

origins = ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

SECRET_KEY = '12nhd45et674r567tfg657yh8jdg75wcj32ki9865d656tf536kjl87tf654'
ALGORITHM = 'HS256'

models.Base.metadata.create_all(bind=engine)

bcrypt_context = CryptContext(schemes='bcrypt', deprecated='auto')
oauth2_bearer = OAuth2PasswordBearer(tokenUrl='/login')
# blacklisted_tokens = set()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

PASSWORD_SECRET_KEY = binascii.unhexlify("206c10c99d6246f784005331e384df6d13e2056b2d0037bef81de611efb62e03")

def decrypt_data(encrypted_password: str):
    try:
        cipher = AES.new(PASSWORD_SECRET_KEY, AES.MODE_ECB)
        decrypted_bytes = cipher.decrypt(b64decode(encrypted_password.encode('utf-8')))
        decrypted_password = unpad(decrypted_bytes, AES.block_size).decode('utf-8')
        return decrypted_password
    except binascii.Error:
        raise HTTPException(status_code=400, detail="Incorrect padding error.")

def hash_password(password: str):
    hashed_password = bcrypt_context.hash(password)
    return hashed_password

def encrypt_data(password: str):
    cipher = AES.new(PASSWORD_SECRET_KEY, AES.MODE_ECB)
    encrypted_bytes = cipher.encrypt(pad(password.encode('utf-8'), AES.block_size))
    encrypted_password = b64encode(encrypted_bytes).decode('utf-8')
    return encrypted_password

def authenticate_user(username_or_email: str, password: str, db: Session):
    user = db.query(UserInput).filter((UserInput.username == username_or_email) | (UserInput.email == username_or_email)).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='No user found.')
    
    if bcrypt_context.verify(password, user.password):
        return user  # Return the user object
    else:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid password.')


def create_access_token(username: str, user_id: int, expires_delta: timedelta):
    encode = {'sub': username, 'id': user_id}
    expires = datetime.utcnow() + expires_delta
    encode.update({'exp': expires})
    access_token = jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)
    return access_token

def create_refresh_token(username: str, user_id: int, refresh_delta: timedelta):
    encode = {'sub': username, 'id': user_id}
    refresh_expires = datetime.utcnow() + refresh_delta
    encode.update({'exp': refresh_expires})
    refresh_token = jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)

    return refresh_token, refresh_expires


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
    #confirm_password: str = Form(...)

    # @validator('password')
    # def password_must_be_strong(cls, value):
    #     if not (8 <= len(value) <= 50):
    #         raise ValueError('Password must be between 8 and 50 characters long')
    #     return value

class Tokn(BaseModel):
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
    #if user_request.password != user_request.confirm_password:
     #   raise HTTPException(status_code=400, detail="Password and confirm password should be same")
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
        #password=encrypt_data(decryptedpassword)
        password= hash_password(user_request.password)
        #password= bcrypt.hashpw(decryptedpassword.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    )
    db.add(user_data)
    db.commit()
    db.refresh(user_data)
    return {"message": "User created successfully"}

@app.post("/login")
async def login_user(login_request: LoginRequest, db: db_dependency, response: Response):
    #if not db.query(UserInput).filter(UserInput.username == login_request.username_or_email).first():
    #   raise HTTPException(status_code=400, detail="User doesn't exist")
    try:
        decryptedpassword = decrypt_data(login_request.password)
   
        user = authenticate_user(login_request.username_or_email, decryptedpassword, db)
   
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Could not validate user.')

        access_tokn = create_access_token(user.username, user.id, timedelta(minutes=60))
        refresh_tokn, refresh_expiry = create_refresh_token(user.username, user.id, timedelta(days=7))
        tokn = Token(access_token=access_tokn, refresh_token=refresh_tokn, refresh_token_expiration = refresh_expiry, user_id=user.id)
        db.add(tokn)
        db.commit()
   
        tokens = Tokn(
        access_token=access_tokn,
        refresh_token=refresh_tokn,
        token_type='bearer',
        message='Login successful!'
        )
   
        response.set_cookie(key="access_token", value=access_tokn, httponly=True)
        response.set_cookie(key="refresh_token", value=refresh_tokn, httponly=True)

        return tokens
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail='Could not validate user.')
    

@app.post('/token')
async def new_access_token(request: Request, response: Response, db: db_dependency):
    refresh_tokn = request.cookies.get("refresh_token")
    if not refresh_tokn:
        raise HTTPException(status_code=400, detail="Token doesn't exist.")
    token_db = db.query(Token).filter(Token.refresh_token == refresh_tokn).first()
    if not token_db:
        raise HTTPException(status_code=400, detail="Invalid token.")
    if token_db.refresh_token_expiration < datetime.utcnow():
        response.delete_cookie(key="access_token")
        response.delete_cookie(key="refresh_token")
        db.delete(token_db)
        db.commit()
        raise HTTPException(status_code=400, detail="Logged out due to token expiration")
    else:
        payload = jwt.decode(refresh_tokn, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get('sub')
        user_id: int = payload.get('id')
        generated_access_token = create_access_token(username, user_id, timedelta(minutes=60))
        response.set_cookie(key="access_token", value=generated_access_token, httponly=True)
        token_db.access_token = generated_access_token
        db.commit()
        return generated_access_token
    
    
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

# @app.get("/get_all_user")
# async def read_all(db: db_dependency):
#     return db.query(RefreshToken).all()


@app.delete('/delete_user/{user_id}')
async def delete_user(user_id:int, db:db_dependency):
    user = db.query(UserInput).filter(UserInput.id == user_id).first()
    db.delete(user)
    db.commit()
    return {'message': 'User deleted successfully'}

session = SessionLocal()
users = session.query(UserInput).all()
user_list = [{"id": user.id, "first name": user.first_name, "last name": user.last_name, "reg no": user.reg_no, "age": user.age, "dob": user.dob, "gender": user.gender, "username": user.username, "email": user.email, "phone number": user.phonenumber} for user in users]

@app.get("/users_list/")
def get_users(page: int, per_page: int):
    start_index = (page - 1) * per_page
    end_index = start_index + per_page
    return user_list[start_index:end_index]

@app.get("/decrypt-password")
def decryptt_password(encrypted_password: str):
    decrypted_password = decrypt_data(encrypted_password)
    return decrypted_password

@app.get("/encrypt-password")
def encryptt_password(password: str):
    encrypted_password = encrypt_data(password)
    return encrypted_password

@app.post("/logout")
def logout(request: Request, response: Response, db: db_dependency):
    refresh_tokn = request.cookies.get("refresh_token")
    token_db = db.query(Token).filter(Token.refresh_token == refresh_tokn).first()
    db.delete(token_db)
    db.commit()
    response.delete_cookie(key="access_token")
    response.delete_cookie(key="refresh_token")
    return {"message": "Logged out successfully"}

@app.post('/logout_all') 
def logout_all_devices(request: Request, response: Response, db: db_dependency):
    refresh_tokn = request.cookies.get("refresh_token")
    if not refresh_tokn:
        raise HTTPException(status_code=400, detail="Haven't logged in.")
    token_db = db.query(Token).filter(Token.refresh_token == refresh_tokn).first()
    user_id = token_db.user_id
    all_token_db = db.query(Token).filter(Token.user_id == user_id).all()
    for token in all_token_db:
        db.delete(token)

    db.commit()
    response.delete_cookie(key="access_token")
    response.delete_cookie(key="refresh_token")
    return {"message": "Logged out from all devices."}
