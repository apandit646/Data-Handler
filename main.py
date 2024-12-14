from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Annotated, Optional
import models
from database import engine, SessionLocal, get_db
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from datetime import datetime, timedelta

app = FastAPI()
models.Base.metadata.create_all(bind=engine)

# JWT Configurations
SECRET_KEY = "your_secret_key_here"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Dependency and Password Hashing
pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
db_dependency = Annotated[Session, Depends(get_db)]




# Models
class PostBase(BaseModel):
    title: str
    content: str
    user_id: int


class UserBase(BaseModel):
    username: str
    email: str
    password: str

    class Config:
        orm_mode = True


class Login(BaseModel):
    username: str
    password: str


class ShowUserBase(BaseModel):
    username: str
    email: str
    posts: List[PostBase] = []

    class Config:
        orm_mode = True


class ShowPostBase(BaseModel):
    title: str
    content: str
    creator: ShowUserBase

    class Config:
        orm_mode = True


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    email: Optional[str] = None


# Utility Functions
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"}
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        user = db.query(models.User).filter(models.User.email == email).first()
        if user is None:
            raise credentials_exception
        return user
    except JWTError: 
        raise credentials_exception


# Routes
@app.post("/users/", status_code=status.HTTP_201_CREATED, tags=["Users"])
async def create_user(user: UserBase, db: db_dependency):
    hashed_password = pwd_context.hash(user.password)
    db_user = models.User(username=user.username, email=user.email, password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


@app.post("/login", status_code=status.HTTP_200_OK, response_model=Token, tags=["Authentication"])
def login(db: db_dependency, form_data: OAuth2PasswordRequestForm = Depends()):
    user = db.query(models.User).filter(models.User.email == form_data.username).first()
    if not user or not pwd_context.verify(form_data.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"}
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.email}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}



@app.get("/users/id", response_model=ShowUserBase, tags=["Users"])
async def read_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if user.id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this user"
        )
    return user


@app.post("/posts/", status_code=status.HTTP_201_CREATED, tags=["Posts"])
async def create_post(
    post: PostBase,
    db: db_dependency,
    current_user: models.User = Depends(get_current_user)
):
    db_post = models.Post(**post.dict())
    db.add(db_post)
    db.commit()
    db.refresh(db_post)
    return db_post


@app.get("/posts/id", response_model=ShowPostBase, tags=["Posts"])
async def read_post(
    post_id: int,
    db: db_dependency,
    current_user: models.User = Depends(get_current_user)
):
    post = db.query(models.Post).filter(models.Post.id == post_id).first()
    if post is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Post not found")
    return post


@app.delete("/posts/id", status_code=status.HTTP_204_NO_CONTENT, tags=["Posts"])
async def delete_post(
    post_id: int,
    db: db_dependency,
    current_user: models.User = Depends(get_current_user)
):
    post = db.query(models.Post).filter(models.Post.id == post_id).first()
    if post is None or post.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Post not found or not authorized to delete"
        )
    db.delete(post)
    db.commit()


@app.put("/posts/id", tags=["Posts"])
async def update_post(
    post_id: int,
    post: PostBase,
    db: db_dependency,
    current_user: models.User = Depends(get_current_user)
):
    db_post=db.query(models.Post).filter(models.Post.id==post_id)
    if db_post is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Post not found")
    
    db_post.update(post)
    
    db.commit()
