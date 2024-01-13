from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Float, create_engine, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.sql import func
import os
from dotenv import load_dotenv

load_dotenv('.env')

engine = create_engine(os.environ['DATABASE_URL'], future=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# Untuk mencatat user
class Users(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, index=True)
    uid = Column(String)
    firstname = Column(String)
    lastname = Column(String)
    address = Column(String)
    postalcode = Column(String)
    dob = Column(DateTime)
    is_admin = Column(Boolean)
    is_disabled = Column(Boolean)
    time_created = Column(DateTime(timezone=True), server_default=func.now())
    time_updated = Column(DateTime(timezone=True), onupdate=func.now())
    moderator_id = Column(Integer, ForeignKey('moderator.id'))
    moderator = relationship('Moderator')
    auth = relationship("Auth", uselist=False, backref="users")



class Auth(Base):
    __tablename__ = 'auth'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    access_token = Column(String)
    hashed_password = Column(String)
    type = Column(String)
    time_created = Column(DateTime(timezone=True), server_default=func.now())
    time_updated = Column(DateTime(timezone=True), onupdate=func.now())


# Untuk mencatat hit (scanned user)
class Hit(Base):
    __tablename__ = 'hit'
    id = Column(Integer, primary_key=True)
    name = Column(String)
    user_id = Column(Integer, ForeignKey('users.id'))
    user_scanner_id = Column(Integer)
    # user = relationship('Users')
    time_created = Column(DateTime(timezone=True), server_default=func.now())
    time_updated = Column(DateTime(timezone=True), onupdate=func.now())


# Untuk mencatat location, akan terisi keterangan jika user memiliki is_moderator=true
class Moderator(Base):
    __tablename__ = 'moderator'
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    description = Column(String)
    location = Column(String)
    time_created = Column(DateTime(timezone=True), server_default=func.now())
    time_updated = Column(DateTime(timezone=True), onupdate=func.now())
