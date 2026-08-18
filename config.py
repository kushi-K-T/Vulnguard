import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "vulnguard-academic-lab-secret-2026")
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{os.path.join(BASE_DIR, 'vulnguard.db')}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    TIMEOUT_SECONDS = 5
    ALLOWED_SCHEMES = {"http", "https"}
