from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

engine = create_engine(
    "postgresql://postgres:abirr02@localhost/LoginDatabase",
    client_encoding="latin1",
    sslmode="require",
    pool_size=20,
    max_overflow=50,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()