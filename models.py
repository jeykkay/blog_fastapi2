from sync_db import Base
from sqlalchemy import (Column, Integer,
                        String, TIMESTAMP,
                        text, ForeignKey)
from sqlalchemy.orm import relationship


class Post(Base):
    __tablename__ = 'posts'

    id = Column(Integer, primary_key=True, nullable=False)
    title = Column(String, nullable=False)
    content = Column(String, nullable=False)
    create_at = Column(TIMESTAMP(timezone=True), server_default=text('now()'))
    user_id = Column(Integer, ForeignKey('users.id'))

    user = relationship('User', back_populates='posts')


class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)

    posts = relationship('Post', back_populates='user')
