from sqlalchemy import Column, String, Text, ForeignKey, Enum, DateTime, JSON, Integer, func
from sqlalchemy.orm import relationship
from datetime import datetime
import enum

from app.models.base import BaseModel

class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELED = "canceled"

class ScanType(str, enum.Enum):
    FULL = "full"
    QUICK = "quick"
    CUSTOM = "custom"
    SCHEDULED = "scheduled"

class Scan(BaseModel):
    """Scan model to track vulnerability scans."""
    __tablename__ = "scans"

    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING)
    scan_type = Column(Enum(ScanType), default=ScanType.FULL)
    parameters = Column(JSON, nullable=True)  # Custom scan parameters
    results_summary = Column(JSON, nullable=True)  # Summary of scan results
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    
    # Foreign keys
    target_id = Column(Integer, ForeignKey("targets.id", ondelete="CASCADE"), nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    
    # Relationships
    target = relationship("Target", back_populates="scans")
    owner = relationship("User", back_populates="scans")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Scan {self.name} ({self.status})>"

    @property
    def duration(self):
        """Calculate the duration of the scan."""
        if not self.started_at:
            return None
        
        end_time = self.completed_at or datetime.utcnow()
        return end_time - self.started_at

    @property
    def vulnerability_counts(self):
        """Return a summary of vulnerabilities found in this scan."""
        if not self.vulnerabilities:
            return {}
            
        counts = {"total": len(self.vulnerabilities)}
        for vuln in self.vulnerabilities:
            counts[vuln.severity] = counts.get(vuln.severity, 0) + 1
            
        return counts
