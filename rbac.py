from typing import Optional
from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session

from database import SessionLocal
from models import User, Role
from security import get_current_user_from_jwt, hash_password


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def is_admin(
    current_user: Optional[User] = Depends(get_current_user_from_jwt),
    db: Session = Depends(get_db)
):
    if not current_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    admin_role = db.query(Role).filter(Role.name == "admin").first()
    if not admin_role or current_user.role_id != admin_role.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    return current_user

def require_role(*role_names: str):
    def dependency(
        current_user: Optional[User] = Depends(get_current_user_from_jwt),
        db: Session = Depends(get_db)
    ):
        if not current_user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
        role = db.query(Role).filter(Role.id == current_user.role_id).first()
        if not role or role.name not in role_names:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
        return True
    return dependency


def seed_rbac_minimal(db: Session):
    for name in ("admin", "user"):
        role = db.query(Role).filter(Role.name == name).first()
        if not role:
            db.add(Role(name=name))
            db.commit()

def seed_users_minimal(db: Session):
    """Создаёт двух пользователей admin и user, если их нет (для быстрой проверки без БД Postgres)."""
    admin_role = db.query(Role).filter(Role.name == "admin").first()
    user_role = db.query(Role).filter(Role.name == "user").first()
    if admin_role:
        admin = db.query(User).filter(User.email == "admin@example.com").first()
        if not admin:
            db.add(User(
                email="admin@example.com",
                hashed_password=hash_password("AdminPass123"),
                is_active=True,
                role_id=admin_role.id,
                first_name="Админ",
                last_name="Пользователь"
            ))
            db.commit()
    if user_role:
        user = db.query(User).filter(User.email == "user@example.com").first()
        if not user:
            db.add(User(
                email="user@example.com",
                hashed_password=hash_password("UserPass123"),
                is_active=True,
                role_id=user_role.id,
                first_name="Обычный",
                last_name="Пользователь"
            ))
            db.commit()

