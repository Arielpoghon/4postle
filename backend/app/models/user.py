from sqlalchemy import Column, String, Boolean, Enum, DateTime, func
from sqlalchemy.orm import relationship
from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import Optional
import enum

from app.models.base import BaseModel

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class UserRole(str, enum.Enum):
    ADMIN = "admin"
    USER = "user"
    READ_ONLY = "read_only"

class User(BaseModel):
    """User model for authentication and authorization."""
    __tablename__ = "users"

    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(50), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(100), nullable=True)
    is_active = Column(Boolean(), default=True)
    role = Column(Enum(UserRole), default=UserRole.USER)
    last_login = Column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    scans = relationship("Scan", back_populates="owner")
    targets = relationship("Target", back_populates="owner")

    def verify_password(self, password: str) -> bool:
        return pwd_context.verify(password, self.hashed_password)

    @classmethod
    def get_password_hash(cls, password: str) -> str:
        return pwd_context.hash(password)

    def get_token_payload(self, expires_delta: Optional[timedelta] = None):
        """Generate JWT token payload for the user."""
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=15)
            
        return {
            "sub": str(self.id),
            "email": self.email,
            "role": self.role.value,
            "exp": expire
        }
