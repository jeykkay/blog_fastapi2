from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException, Depends, APIRouter

from async_db import get_db
from sqlalchemy.future import select
import models
import schemas
from typing import List


router = APIRouter(
    prefix='/posts',
    tags=['Posts']
)


@router.get('/', response_model=List[schemas.PostBase])
async def all_posts(db: AsyncSession = Depends(get_db)):
    async with db:
        result = await db.execute(select(models.Post))
        posts = result.scalars().all()
        return posts
