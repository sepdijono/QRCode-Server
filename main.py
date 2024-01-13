import os
from copy import deepcopy
from datetime import datetime, timedelta
from functools import wraps

import bcrypt
import jwt
import uvicorn
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, status, Request, APIRouter
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi_sqlalchemy import DBSessionMiddleware, db
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.sql.annotation import Annotated

from models import Auth as ModelAuth
from models import Hit as ModelHit
from models import Users as ModelUser
from schema import Hit as SchemaHit
from schema import Token
from schema import Users as SchemaUsers

load_dotenv('.env')

router = APIRouter(
    prefix='/auth',
    tags=['auth']
)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
req_info = Request

app = FastAPI()
# to avoid csrftokenError
app.add_middleware(DBSessionMiddleware, db_url=os.environ['DATABASE_URL'])


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credential_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                         detail="Could not validate credentials",
                                         headers={"WWW-Authenticate": "Bearer"})
    try:
        secret_key = os.environ['SECRET_KEY']
        algorithm = os.environ['ALGORITHM']
        payload = jwt.decode(token, secret_key, algorithms=[algorithm])
        username: str = payload.get("username")
        if username is None:
            raise credential_exception
    except JWTError:
        raise credential_exception

    user = db.session.query(ModelUser).filter_by(uid=username).first()
    if not user:
        raise credential_exception

    return user


# async def get_current_active_user(current_user: db.session. = Depends(get_current_user)):
#     if current_user.disabled:
#         raise HTTPException(status_code=400, detail="Inactive user")
#
#     return current_user


def auth_required(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        for kwarg in kwargs:
            if kwarg == 'info':
                print(kwarg)
                kw = kwargs['info']['headers'][0]
                access_token = kw[1].decode('utf-8')
                print(kw)
                auth_tokens = db.session.query(ModelAuth).all()
                auth_token = None
                for auth_token in auth_tokens:
                    if auth_token == access_token:
                        break

                if not auth_token:
                    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                        detail="Could not validate credentials",
                                        headers={"WWW-Authenticate": "Bearer"})
                current_user = await get_current_user(access_token)
                if not current_user:
                    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                        detail="Could not validate credentials",
                                        headers={"WWW-Authenticate": "Bearer"})
            else:
                print('None')
        return await func(*args, **kwargs)

    return wrapper


def admin_required(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        for kwarg in kwargs:
            if kwarg:
                kw = kwargs['info']['headers'][0]
                access_token = kw[1].decode('utf-8')
                auth_tokens = db.session.query(ModelAuth).all()
                for auth_token in auth_tokens:
                    if auth_token == access_token:
                        break

                if not auth_token:
                    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                        detail="Could not validate credentials",
                                        headers={"WWW-Authenticate": "Bearer"})
                current_user = await get_current_user(access_token)
                if not current_user:
                    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                        detail="Could not validate credentials",
                                        headers={"WWW-Authenticate": "Bearer"})
                if not current_user.is_admin:
                    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                        detail="You do not have sufficient permission",
                                        headers={"WWW-Authenticate": "Bearer"})

        return await func(*args, **kwargs)

    return wrapper


@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    async def generate_token(data: dict, expires_delta: timedelta or None = None):
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=15)

        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, os.environ['SECRET_KEY'],
                                 algorithm=os.environ['ALGORITHM'])
        return encoded_jwt

    current_user = db.session.query(ModelUser).filter_by(uid=form_data.username).first()

    if not current_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Incorrect username or password", headers={"WWW-Authenticate": "Bearer"})
    try:
        hash_utf8 = current_user.auth.hashed_password.encode('utf-8')
        pasw_utf8 = form_data.password.encode('utf-8')
        client_id_ok = form_data.client_id == os.environ['CLIENT_ID']
        client_secret_ok = form_data.client_secret = os.environ['CLIENT_SECRET']
        authenticated = bcrypt.checkpw(pasw_utf8, hash_utf8) and str(current_user.uid).strip() == form_data.username
        authenticated = authenticated and client_id_ok and client_secret_ok

        if not authenticated:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="Incorrect username or password", headers={"WWW-Authenticate": "Bearer"})
        access_token_expires = timedelta(minutes=float(os.environ['ACCESS_TOKEN_EXPIRE_MINUTES']))
        access_token = await generate_token(
            data={"username": current_user.uid, "password": form_data.password, "client_id": os.environ['CLIENT_ID'],
                  "client_secret": os.environ['CLIENT_SECRET']},
            expires_delta=access_token_expires)
        # Update access_token in table Auth
        db.session.query(ModelAuth).filter_by(user_id=current_user.id).update({'access_token': access_token})
        db.session.commit()
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Incorrect username or password", headers={"WWW-Authenticate": "Bearer"})

    return {"access_token": access_token, "token_type": "bearer"}


async def jwt_required(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, os.environ['SECRET_KEY'], algorithms=os.environ['ALGORITHM'])
        username: str = payload.get("username")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.session.query(ModelUser).filter_by(uid=username).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


# @app.get("/items/")
# async def read_items(token: Annotated[str, Depends(oauth2_scheme)]):
#     print(token)
#     return {"token": token}


@app.get("/")
async def home(info: Request):
    if not await get_current_user(info.headers.get('access_token').strip()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return {"access_token": info.headers.get('access_token')}


@app.post('/users/', response_model=SchemaUsers)
@admin_required
async def users(user: SchemaUsers):
    db_users = ModelUser(firstname=user.firstname, lastname=user.lastname,
                         address=user.address, postalcode=user.postalcode, dob=user.dob)
    db.session.add(db_users)
    db.session.commit()
    return db_users


@app.get('/users/')
@admin_required
async def users(info: Request):
    # inf = info.headers.get('access_token')
    global au
    users = db.session.query(ModelUser).all()
    active_users = []
    for user in users:
        if not user.is_disabled:
            au = {
                "uid": user.uid,
                "firstname": user.firstname,
                "lastname": user.lastname,
                "address": user.address,
                "postalcode": user.postalcode,
                "dob": user.dob,
                "is_admin": user.is_admin,
                "is_disabled": user.is_disabled,
                "moderator_id": user.moderator_id,
                "moderator": user.moderator
            }
        active_users.append(au)

    if not active_users:
        out = {"message": "not found"}
    else:
        out = {'count': len(active_users), 'data': active_users}
    return out


@app.get('/user/{id}')
@auth_required
async def user(id: int, info: Request):
    user = db.session.query(ModelUser).get(id)
    if not user:
        user = {"message": "not found"}
    au = {
        "uid": user.uid,
        "firstname": user.firstname,
        "lastname": user.lastname,
        "address": user.address,
        "postalcode": user.postalcode,
        "dob": user.dob,
        "is_admin": user.is_admin,
        "is_disabled": user.is_disabled,
        "moderator_id": user.moderator_id,
        "moderator": user.moderator
    }
    return au


@app.get('/uid/{muid}')
@auth_required
async def uid(muid: str, info: Request):
    user = db.session.query(ModelUser).filter_by(uid=muid).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Not found",
                            headers={"WWW-Authenticate": "Bearer"})
    au = {
        "uid": user.uid,
        "firstname": user.firstname,
        "lastname": user.lastname,
        "address": user.address,
        "postalcode": user.postalcode,
        "dob": user.dob,
        "is_admin": user.is_admin,
        "is_disabled": user.is_disabled,
        "moderator_id": user.moderator_id,
        "moderator": user.moderator
    }
    return au


@app.post('/user/scan/{id}/')
async def user_scan(info: Request, id: int):
    if not await get_current_user(info.headers.get('access_token').strip()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    scanner = await get_current_user(info.headers.get('access_token'))
    try:
        if not scanner.moderator:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail="You do not have sufficient permission",
                                headers={"WWW-Authenticate": "Bearer"})
        if not id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail="Bad request",
                                headers={"WWW-Authenticate": "Bearer"})
        user = db.session.query(ModelUser).get(id)
        if not user:
            return {"message": "not found"}
        au = {
            "id": user.id,
            "uid": user.uid,
            "firstname": user.firstname,
            "lastname": user.lastname,
            "address": user.address,
            "postalcode": user.postalcode,
            "dob": user.dob,
            "is_admin": user.is_admin,
            "is_disabled": user.is_disabled,
            "scanner": {
                "id": scanner.id,
                "uid": scanner.uid,
                "moderator": scanner.moderator
            }
        }
        return au
    except Exception as e:
        return {"message": e}


@app.post('/hit/', response_model=SchemaHit)
@auth_required
async def hit(hit: SchemaHit, info: Request):
    db_hit = ModelHit(name=hit.name)
    db.session.add(db_hit)
    db.session.commit()
    return db_hit


@app.get('/hit/')
@auth_required
async def hit(info: Request):
    hit = db.session.query(ModelHit).all()
    return hit


# To run locally
if __name__ == '__main__':
    uvicorn.run(app, host='0.0.0.0', port=8000)
