from database import Base
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Date
from sqlalchemy.orm import relationship

class UserInput(Base):
    __tablename__ = 'userinput'

    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String)
    last_name = Column(String)
    reg_no = Column(String, unique=True)
    age = Column(Integer)
    dob = Column(Date)
    gender = Column(String)
    username = Column(String, unique=True)
    email = Column(String, unique=True)
    phonenumber = Column(String)
    password = Column(String)

    tokens = relationship("Token", back_populates="user")
class Token(Base):
    __tablename__ = 'tokens'

    id = Column(Integer, primary_key=True, index=True)
    access_token = Column(String)
    refresh_token = Column(String)
    refresh_token_expiration = Column(DateTime)
    user_id = Column(Integer, ForeignKey('userinput.id'))

    user = relationship("UserInput", back_populates="tokens")
# class AccessToken(Base):
#     __tablename__ = "access_tokens"

#     id = Column(String, primary_key=True, index=True)
#     token = Column(String)



# class RefreshToken(Base):
#     __tablename__ = "refresh_tokens"

#     id = Column(String, primary_key=True, index=True)
#     token = Column(String)
#     accesstoken_id = Column(String, index=True)
