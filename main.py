from fastapi import FastAPI, Depends, HTTPException, status, Request, Response, Cookie, Form
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from typing import Optional
from uuid import UUID
import logging
from database import SessionLocal, engine
from models import User, UserSession
from pydantic import EmailStr, BaseModel, Field
from schemas import UserCreate, UserPublic, Token, UserLogin
from security import (
    hash_password,
    verify_password,
    create_access_token,
    get_current_user_from_jwt,
    ALGORITHM, SECRET_KEY
)
from auth import create_user, create_db_session, delete_session, get_active_session, soft_delete_user, delete_all_sessions_for_user
from jose import JWTError, jwt

from models import Base
from rbac import seed_rbac_minimal, seed_users_minimal
from routes_admin import router as admin_router
from routes_resources import router as resources_router
from db_compat import ensure_user_role_column
Base.metadata.create_all(bind=engine)

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    db = SessionLocal()
    try:
        ensure_user_role_column(engine)
        seed_rbac_minimal(db)
        seed_users_minimal(db)
    finally:
        db.close()
    yield

app = FastAPI(
    title="Auth API with JWT + DB Sessions",
    description=(
        "Hybrid auth: JWT + DB sessions with RBAC\n\n"
        "Данные для проверки в Swagger (/docs):\n\n"
        "- admin: email admin@example.com / пароль AdminPass123\n"
        "- user: email user@example.com / пароль UserPass123\n\n"
        "После логина вставьте access_token в Authorize (HTTPBearer, без префикса).\n\n"
        "Проверка:\n"
        "- GET /resources/articles — доступно user и admin\n"
        "- POST /resources/articles — доступно только admin\n"
    ),
    version="1.0.0",
    lifespan=lifespan
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


app.include_router(admin_router)
app.include_router(resources_router)

@app.post("/register", description="Регистрация нового пользователя",summary="Регистрация", tags=["аутентификация"], response_model=UserPublic, status_code=status.HTTP_201_CREATED)
def register(user: UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.email == user.email, User.is_active == True).first()
    if existing_user:
        raise HTTPException(400, "Email already registered")
    if (user.password != user.retrypassword):
        raise HTTPException(400, "Пароли не совпадают")

    new_user = create_user(db, user)
    logger.info(f"New user registered: {new_user.email}")
    return new_user

@app.post("/login", summary="Аутентификация", tags=["аутентификация"], response_model=Token)
def login(
    response: Response,
    email: EmailStr = Form(...),
    password: str = Form(..., min_length=8),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account deactivated")


    session_id = create_db_session(db, user.id)
    access_token = create_access_token(data={"sub": str(user.id)})

    response.set_cookie(
        key="session_id",
        value=session_id,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=7 * 24 * 3600
    )

    logger.info(f"User logged in: {user.email}")
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/logout", summary="Выход", tags=["аутентификация"], description="Выход из аккаунта. Удаляет сессию.")
def logout(
    response: Response,
    session_id: Optional[str] = Cookie(None),
    db: Session = Depends(get_db)
):
    if session_id:
        delete_session(db, session_id)
        logger.info(f"Session deleted: {session_id}")
    response.delete_cookie("session_id")
    return {"detail": "Successfully logged out"}

@app.get("/profile" , tags=["пользователь"], description="Изменение пользователя", summary="Профиль", response_model=UserPublic)
def profile(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    jwt_user: Optional[User] = Depends(get_current_user_from_jwt)
):
    # 1. Пробуем через JWT
    if jwt_user:
        return jwt_user

    # 2. Пробуем через сессию
    session_id = request.cookies.get("session_id")
    session = get_active_session(db, session_id)
    if not session:
        raise HTTPException(status_code=401, detail="Not authenticated")

    user = db.query(User).filter(User.id == session.user_id, User.is_active == True).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid session")

    return user

class UserUpdate(BaseModel):
    first_name: Optional[str] = Field(None, min_length=2, max_length=50)
    last_name: Optional[str] = Field(None, min_length=2, max_length=50)
    patronymic: Optional[str] = None

@app.patch("/profile", response_model=UserPublic, tags=["пользователь"])
def update_profile(
    update_data: UserUpdate,
    db: Session = Depends(get_db),
    jwt_user: Optional[User] = Depends(get_current_user_from_jwt)
):
    current_user = None

    if jwt_user:
        current_user = jwt_user
    else:
        raise HTTPException(401, "Authentication required")

    for field, value in update_data.model_dump(exclude_unset=True).items():
        if value is not None:
            setattr(current_user, field, value)

    db.commit()
    db.refresh(current_user)
    return current_user

@app.delete("/account",
             summary="Мягкое удаление аккаунта", 
             tags=["пользователь"],
             description="Пользователь инициирует удаление аккаунта. Происходит logout и установка is_active=False.")
def delete_account(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    jwt_user: Optional[User] = Depends(get_current_user_from_jwt)
):
    current_user = None

    if jwt_user:
        current_user = jwt_user
    else:
        session_id = request.cookies.get("session_id")
        session = get_active_session(db, session_id)
        if session:
            user = db.query(User).filter(User.id == session.user_id).first()
            if user and user.is_active:
                current_user = user

    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    # Отозвать все сессии пользователя
    delete_all_sessions_for_user(db, current_user.id)

    soft_delete_user(db, current_user.id)

    response.delete_cookie("session_id")

    logger.info(f"User account soft-deleted: {current_user.email}")
    return {"detail": "Account deactivated. You have been logged out."}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", reload=True)