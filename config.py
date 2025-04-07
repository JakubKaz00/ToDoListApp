import os

class Config:
    SQLALCHEMY_DATABASE_URI = "postgresql://postgres:admin123@127.0.0.1:5470/todo-db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = os.urandom(24)
