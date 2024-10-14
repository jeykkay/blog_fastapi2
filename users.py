from fastapi import APIRouter, Depends, HTTPException, status
from async_db import get_db
from sqlalchemy.future import select
from jose import jwt, JWTError
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timedelta
import models
import schemas


PWD_CONTEXT = CryptContext(schemes=["bcrypt"], deprecated="auto")
ALGORITHM = 'HS256'
SECRET_KEY = 'abcdefqwerty'
ACCESS_TOKEN_EXPIRE_MINUTES = 30
OAUTH2_SCHEME = OAuth2PasswordBearer(tokenUrl='users/login')

router = APIRouter(
    prefix='/users',
    tags=['Users']
)


async def get_user(db: AsyncSession, email):
    async with db:
        result = await db.execute(select(models.User).filter(models.User.email == email))
        return result.scalars().first()


#Проверка пароля
def verify_password(plain_password, hashed_password):
    return PWD_CONTEXT.verify(plain_password, hashed_password)


#Генерация токена
def create_access_token(data: dict, expires_delta: timedelta):
    data_to_process = data.copy()
    expire = datetime.utcnow() + expires_delta
    data_to_process.update({'exp': expire})
    encoded_jwt = jwt.encode(data_to_process, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def authenticate_user(db: AsyncSession, email: str, password: str):
    user = await get_user(db, email)
    if not user or not verify_password(password, user.password_hash):
        return False
    return user


@router.post('/register/', response_model=schemas.User)
async def register(user: schemas.UserCreate, db: AsyncSession = Depends(get_db)):
    db_user = await get_user(db, email=user.email)

    if db_user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail='User already exists!')
    hashed_password = PWD_CONTEXT.hash(user.password)
    db_user = models.User(email=user.email, password_hash=hashed_password)
    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)
    return db_user


@router.post('/login/', response_model=schemas.Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)):
    user = await authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Incorrect email or password',
            headers={'WWW-Authenticate': 'Bearer'}
        )
    token_expire = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={'sub': user.email}, expires_delta=token_expire
    )
    return {'access_token': access_token, 'token_type': 'bearer'}
