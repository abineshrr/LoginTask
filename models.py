from database import Base
from sqlalchemy import Column, Integer, String, Date

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
