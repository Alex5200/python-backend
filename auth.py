from sqlalchemy.orm import Session
from schemas import UserCreate
from models import User, UserSession
from datetime import datetime, timedelta, timezone
from security import hash_password
import uuid
from security import verify_password

def create_user(db: Session, user: UserCreate) -> User:

    existing_active = db.query(User).filter(
        User.email == user.email,
        User.is_active.is_(True)
    ).first()
    if user.password != user.retrypassword:
        raise ValueError("Passwords do not match")
    if existing_active:
        raise ValueError("Email already registered")

    hashed_password = hash_password(user.password)

    db_user = User(
        id=uuid.uuid4(),
        email=user.email,
        hashed_password=hashed_password,
        first_name=user.first_name,
        last_name=user.last_name,
        patronymic=user.patronymic,
        is_active=True
    )
    
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def authenticate_user(db: Session, email: str, password: str) -> User | None:
    user = db.query(User).filter(User.email == email).first()
    if not user:
        return None
    if not user.is_active:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user

def create_db_session(db: Session, user_id: uuid.UUID, days=7) -> str:
    expires = datetime.now(timezone.utc) + timedelta(days=days)
    db_session = UserSession(
        user_id=user_id,
        expires_at=expires
    )
    db.add(db_session)
    db.commit()
    db.refresh(db_session)
    return str(db_session.id)

def get_active_session(db: Session, session_id: str):
    if not session_id:
        return None
    try:
        sid = uuid.UUID(session_id)
    except ValueError:
        return None

    session = db.query(UserSession).filter(
        UserSession.id == sid,
        UserSession.expires_at > datetime.now(timezone.utc)
    ).first()
    return session

def delete_session(db: Session, session_id: str):
    if not session_id:
        return
    try:
        sid = uuid.UUID(session_id)
    except ValueError:
        return
    db.query(UserSession).filter(UserSession.id == sid).delete()
    db.commit()

def soft_delete_user(db: Session, user_id: uuid.UUID):
    """Мягкое удаление: is_active = False"""
    user = db.query(User).filter(User.id == user_id).first()
    if user:
        user.is_active = False
        db.commit()
        db.refresh(user)
    return user