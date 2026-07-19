import enum
from datetime import datetime, timezone

from sqlalchemy import (
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    Boolean,
)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


def utcnow():
    return datetime.now(timezone.utc)


class ProjectCategory(str, enum.Enum):
    wildcard_domain = "wildcard_domain"
    single_host = "single_host"
    single_ip = "single_ip"
    cidr_range = "cidr_range"
    ip_list = "ip_list"


class Project(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False, unique=True)
    description = Column(Text, default="")
    category = Column(Enum(ProjectCategory), nullable=False, default=ProjectCategory.wildcard_domain)
    target_value = Column(String(512), default="")  # primary target (domain, IP, CIDR)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    targets = relationship("Target", back_populates="project", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="project", cascade="all, delete-orphan")
    api_keys = relationship("ApiKey", back_populates="project", cascade="all, delete-orphan")


class TargetType(str, enum.Enum):
    ip = "ip"
    ip_range = "ip_range"
    url = "url"
    wildcard_domain = "wildcard_domain"


class ScopeDirection(str, enum.Enum):
    in_scope = "in_scope"
    out_of_scope = "out_of_scope"


class Target(Base):
    __tablename__ = "targets"

    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    value = Column(String(512), nullable=False)
    target_type = Column(Enum(TargetType), nullable=False)
    direction = Column(Enum(ScopeDirection), nullable=False, default=ScopeDirection.in_scope)

    project = relationship("Project", back_populates="targets")


class ScanStatus(str, enum.Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"
    cancelled = "cancelled"


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    scan_type = Column(String(100), nullable=False)
    status = Column(Enum(ScanStatus), default=ScanStatus.pending)
    tool_name = Column(String(100), nullable=False)
    command = Column(Text, default="")
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    error_message = Column(Text)

    project = relationship("Project", back_populates="scans")
    results = relationship("ScanResult", back_populates="scan", cascade="all, delete-orphan")


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    result_type = Column(String(100), nullable=False)
    value = Column(Text, nullable=False)
    metadata_json = Column(Text, default="{}")

    scan = relationship("Scan", back_populates="results")


class Setting(Base):
    __tablename__ = "settings"

    id = Column(Integer, primary_key=True)
    key = Column(String(255), unique=True, nullable=False)
    value = Column(Text, default="")
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class ApiKey(Base):
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    provider = Column(String(100), nullable=False)
    encrypted_key = Column(Text, nullable=False)
    is_valid = Column(Boolean, default=False)
    last_tested_at = Column(DateTime(timezone=True))

    project = relationship("Project", back_populates="api_keys")
