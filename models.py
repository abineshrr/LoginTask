from database import Base
from sqlalchemy import Column, Integer, String, Date

class UserInput(Base):
    __tablename__ = 'userinput'

    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String)
    last_name = Column(String)
    age = Column(Integer)
    dob = Column(Date)
    gender = Column(String)
    username = Column(String)
    email = Column(String)
    password = Column(String)
