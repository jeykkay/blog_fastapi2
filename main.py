from fastapi import FastAPI
from fastapi.security import OAuth2PasswordBearer
import posts
import users


OAUTH2_SCHEME = OAuth2PasswordBearer('users/login/')


app = FastAPI()

app.include_router(posts.router)
app.include_router(users.router)


@app.get('/')
async def index():
    return {'message': 'Hello World'}
