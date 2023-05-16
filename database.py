from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from psycopg2 import ssl

ssl_context = ssl.create_default_context()
engine = create_engine(
    "postgresql://postgres:abirr02@localhost/LoginDatabase",
    connect_args={"sslmode": "require", "ssl": ssl_context},
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()