# build a schema using pydantic
from pydantic import BaseModel


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str or None = None


class Users(BaseModel):
    id: int
    uid: str
    firstname: str
    lastname: str
    address: str
    postalcode: str
    dob: str
    is_admin: bool
    is_disabled: bool

    class Config:
        orm_mode = True


class Auth(BaseModel):
    id: int
    user_id: int
    access_token: str
    hashed_password: str
    type: str

    class Config:
        orm_mode = True


class Moderators(BaseModel):
    id: int
    name: str
    description: str
    location: str

    class Config:
        orm_mode = True


class Hit(BaseModel):
    id: int
    name: str
    user_id: int
    user_scanner_id: int

    class Config:
        orm_mode = True
