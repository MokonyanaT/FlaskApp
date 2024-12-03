import os

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "secure-random-key")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URI", "sqlite:///insurance_app.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_COOKIE_SECURE = True  # Ensures cookies are only sent over HTTPS
    REMEMBER_COOKIE_SECURE = True
    WTF_CSRF_ENABLED = True
    WTF_CSRF_SECRET_KEY = os.environ.get("CSRF_SECRET_KEY", "csrf-secret-key")
    DEBUG = False  # Disable debug mode in production
    ENV = "production"  # Production environment
