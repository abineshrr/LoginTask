from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

SQLALCHEMY_DATABASE_URL = 'postgres://studentlogin_user:Ek8NAisDA7g2Vcd6SY0DF1JoXnydvCHV@dpg-chh73qrhp8ualfnfrgag-a/studentlogin'

engine = create_engine(SQLALCHEMY_DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()