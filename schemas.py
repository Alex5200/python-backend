from pydantic import BaseModel, EmailStr, Field, ConfigDict, field_validator
from typing import Optional
from uuid import UUID

class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=72)
    retrypassword: str = Field(..., min_length=8, max_length=72)
    first_name: str = Field(..., min_length=2, max_length=50)
    last_name: str = Field(..., min_length=2, max_length=50)
    patronymic: Optional[str] = None
    @field_validator('password')
    def password_not_too_long(cls, v):
        if len(v.encode('utf-8')) > 72:
            raise ValueError('Password too long (max 72 bytes)')
        return v

class UserLogin(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)

class UserPublic(BaseModel):
    id: UUID
    email: EmailStr
    first_name: Optional[str]
    last_name: Optional[str]
    patronymic: Optional[str]
    is_active: bool

    model_config = ConfigDict(from_attributes=True)

class Token(BaseModel):
    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field(default="bearer", description="Token type (always 'bearer')")
    refresh_token: Optional[str] = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xxxxx",
                "token_type": "bearer",
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.yyyyy"
            }
        }
    )