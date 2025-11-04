from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import SessionLocal
from models import Role, User
from rbac import is_admin

router = APIRouter(prefix="/admin", tags=["admin"])


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class RoleCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=50)


@router.post("/roles", status_code=201, dependencies=[Depends(is_admin)])
def create_role(payload: RoleCreate, db: Session = Depends(get_db)):
    exists = db.query(Role).filter(Role.name == payload.name).first()
    if exists:
        raise HTTPException(400, detail="Role already exists")
    role = Role(name=payload.name)
    db.add(role)
    db.commit()
    db.refresh(role)
    return {"id": str(role.id), "name": role.name}


@router.get("/roles", dependencies=[Depends(is_admin)])
def list_roles(db: Session = Depends(get_db)):
    roles = db.query(Role).all()
    return [{"id": str(r.id), "name": r.name} for r in roles]


class PermissionCreate(BaseModel):
    resource: str = Field(..., min_length=2, max_length=50)
    action: str = Field(..., min_length=2, max_length=50)


class SetUserRole(BaseModel):
    user_id: str
    role_id: str


@router.post("/set-user-role", status_code=200, dependencies=[Depends(is_admin)])
def set_user_role(payload: SetUserRole, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == payload.user_id).first()
    role = db.query(Role).filter(Role.id == payload.role_id).first()
    if not user or not user.is_active:
        raise HTTPException(404, detail="User not found")
    if not role:
        raise HTTPException(404, detail="Role not found")
    user.role_id = role.id
    db.commit()
    return {"detail": "Role set"}

