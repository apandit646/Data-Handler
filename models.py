from database import Base
from sqlalchemy import Column, Integer, String,ForeignKey
from sqlalchemy.orm import relationship
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String)
    email = Column(String, unique=True)
    password = Column(String)
    
    # Relationship with Post
    posts = relationship("Post", back_populates="creator")

# Post model
class Post(Base):
    __tablename__ = "posts"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(100))
    content = Column(String(100))
    user_id = Column(Integer, ForeignKey('users.id'))  # ForeignKey to 'users.id'
    
    # Relationship with User
    creator = relationship("User", back_populates="posts")
