from sqlalchemy import Column, String, Text, ForeignKey, Enum, DateTime, func
from sqlalchemy.orm import relationship
from datetime import datetime
import enum

from app.models.base import BaseModel

class TargetStatus(str, enum.Enum):
    PENDING = "pending"
    ACTIVE = "active"
    ARCHIVED = "archived"

class TargetType(str, enum.Enum):
    DOMAIN = "domain"
    IP_ADDRESS = "ip_address"
    URL = "url"
    NETWORK_RANGE = "network_range"

class Target(BaseModel):
    """Target model for systems to be scanned."""
    __tablename__ = "targets"

    name = Column(String(255), nullable=False, index=True)
    target = Column(String(512), nullable=False, index=True)
    target_type = Column(Enum(TargetType), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(Enum(TargetStatus), default=TargetStatus.PENDING)
    last_scan = Column(DateTime(timezone=True), nullable=True)
    
    # Foreign keys
    owner_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    
    # Relationships
    owner = relationship("User", back_populates="targets")
    scans = relationship("Scan", back_populates="target")
    vulnerabilities = relationship("Vulnerability", back_populates="target")

    def __repr__(self):
        return f"<Target {self.target_type}:{self.target}>"

    @property
    def scan_count(self):
        return len(self.scans)

    @property
    def vulnerability_count(self):
        return len(self.vulnerabilities)

    @property
    def critical_vulnerability_count(self):
        return sum(1 for vuln in self.vulnerabilities if vuln.severity == "critical")
