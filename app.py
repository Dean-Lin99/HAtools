# app.py
from datetime import datetime, timedelta, timezone
from typing import Optional
import os, secrets, hashlib

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, ForeignKey, select, func
from sqlalchemy.orm import sessionmaker, declarative_base, Session, relationship
from passlib.hash import argon2
import jwt

# =========================
# 設定
# =========================
class Settings(BaseSettings):
    JWT_SECRET: str = Field(default_factory=lambda: secrets.token_urlsafe(64))
    JWT_ALG: str = "HS256"
    ACCESS_EXPIRE_MIN: int = 15       # Access Token 15 分鐘
    REFRESH_EXPIRE_DAYS: int = 30     # Refresh Token 30 天

settings = Settings()

# =========================
# 資料庫
# =========================
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./auth.sqlite3")
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(190), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), default=func.now())
    refresh_tokens = relationship("RefreshToken", back_populates="user", cascade="all,delete-orphan")

class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=False)
    jti = Column(String(64), index=True, nullable=False)
    token_hash = Column(String(64), nullable=False)           # 只存雜湊，避免庫洩漏拿到明文
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=func.now())
    user = relationship("User", back_populates="refresh_tokens")

Base.metadata.create_all(bind=engine)

# =========================
# Pydantic 模型
# =========================
class RegisterIn(BaseModel):
    username: str
    password: str

class LoginIn(BaseModel):
    username: str
    password: str

class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    refresh_token: Optional[str] = None

class RefreshIn(BaseModel):
    refresh_token: str

class MeOut(BaseModel):
    id: int
    username: str
    created_at: datetime

# =========================
# 工具
# =========================
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def hash_refresh_token(rt: str) -> str:
    return hashlib.sha256(rt.encode("utf-8")).hexdigest()

def create_access_token(*, user_id: int, username: str) -> tuple[str, int]:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=settings.ACCESS_EXPIRE_MIN)
    jti = secrets.token_hex(16)
    payload = {
        "sub": str(user_id),
        "usr": username,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "jti": jti,
        "typ": "access",
    }
    token = jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALG)
    return token, settings.ACCESS_EXPIRE_MIN * 60

def create_refresh_token(db: Session, *, user_id: int) -> str:
    raw = secrets.token_urlsafe(64)  # 高熵非 JWT 也可
    jti = secrets.token_hex(16)
    expires_at = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_EXPIRE_DAYS)
    rt = RefreshToken(
        user_id=user_id,
        jti=jti,
        token_hash=hash_refresh_token(raw),
        expires_at=expires_at,
        revoked=False
    )
    db.add(rt)
    db.commit()
    return raw  # 只回傳給客戶端一次

def rotate_refresh_token(db: Session, old_rt: RefreshToken) -> str:
    old_rt.revoked = True
    db.add(old_rt)
    db.commit()
    return create_refresh_token(db, user_id=old_rt.user_id)

def verify_refresh_token(db: Session, raw_token: str) -> RefreshToken:
    h = hash_refresh_token(raw_token)
    rt: RefreshToken | None = db.execute(
        select(RefreshToken).where(RefreshToken.token_hash == h)
    ).scalar_one_or_none()
    if not rt or rt.revoked:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
    if rt.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired")
    return rt

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)) -> User:
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALG])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Access token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid access token")
    if payload.get("typ") != "access":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")
    user_id = int(payload.get("sub", "0"))
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user

# =========================
# 應用
# =========================
app = FastAPI(title="Auth Server (Minimal but Solid)")

@app.post("/register", response_model=MeOut)
def register(data: RegisterIn, db: Session = Depends(get_db)):
    existed = db.execute(select(User).where(User.username == data.username)).scalar_one_or_none()
    if existed:
        raise HTTPException(status_code=400, detail="Username already exists")
    pwd_hash = argon2.hash(data.password)  # Argon2
    user = User(username=data.username, password_hash=pwd_hash)
    db.add(user)
    db.commit()
    db.refresh(user)
    return MeOut(id=user.id, username=user.username, created_at=user.created_at)

@app.post("/login", response_model=TokenOut)
def login(data: LoginIn, db: Session = Depends(get_db)):
    user: User | None = db.execute(select(User).where(User.username == data.username)).scalar_one_or_none()
    if not user or not argon2.verify(data.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    access, expires_in = create_access_token(user_id=user.id, username=user.username)
    refresh = create_refresh_token(db, user_id=user.id)
    return TokenOut(access_token=access, expires_in=expires_in, refresh_token=refresh)

@app.post("/refresh", response_model=TokenOut)
def refresh_token(data: RefreshIn, db: Session = Depends(get_db)):
    rt = verify_refresh_token(db, data.refresh_token)
    user = db.get(User, rt.user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    new_refresh = rotate_refresh_token(db, rt)       # 旋轉 refresh
    access, expires_in = create_access_token(user_id=user.id, username=user.username)
    return TokenOut(access_token=access, expires_in=expires_in, refresh_token=new_refresh)

@app.post("/logout")
def logout(data: RefreshIn, db: Session = Depends(get_db)):
    rt = verify_refresh_token(db, data.refresh_token)
    rt.revoked = True
    db.add(rt)
    db.commit()
    return {"detail": "Logged out"}

@app.get("/me", response_model=MeOut)
def me(user: User = Depends(get_current_user)):
    return MeOut(id=user.id, username=user.username, created_at=user.created_at)

@app.get("/healthz")
def healthz():
    return {"ok": True}
