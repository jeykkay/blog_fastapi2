from pydantic import BaseModel


class PostBase(BaseModel):
    title: str
    content: str

    class Config:
        from_attributes = True


class UserBase(BaseModel):
    email: str

    class Config:
        from_attributes = True


class UserCreate(UserBase):
    password: str


class User(UserBase):
    id: int


class Token(BaseModel):
    access_token: str
    token_type: str
